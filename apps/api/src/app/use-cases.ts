import { canCreateUser, decideContentAccess } from '../policy/access-policy.ts';
import { evaluateFilePolicy } from '../policy/file-policy.ts';
import { signDownloadToken } from '../policy/tokens.ts';
import type { Actor } from '../policy/types.ts';
import { newBlobKey } from '../storage/paths.ts';
import { decideScanOutcome, isUploadExpired, nextUploadState } from '../upload/state-machine.ts';
import type { ScanResult } from '../upload/state-machine.ts';
import { validateCreate, validatePatch } from '../upload/tus-guard.ts';
import { validateNewUser } from '../users/user-input.ts';
import type { FieldError } from '../users/user-input.ts';
import type { Deps, UploadSessionRecord, UserRecord } from './ports.ts';

export type Result<T> = { ok: true; value: T } | { ok: false; code: string; errors?: FieldError[] };

function fail(code: string, errors?: FieldError[]): { ok: false; code: string; errors?: FieldError[] } {
  return errors === undefined ? { ok: false, code } : { ok: false, code, errors };
}

function activeActor(deps: Deps, id: string): UserRecord | undefined {
  const u = deps.repo.getUser(id);
  return u !== undefined && u.status === 'active' ? u : undefined;
}

// ---------------------------------------------------------------- users

export function createUser(deps: Deps, actorId: string, raw: Record<string, string | undefined>, parentId?: string): Result<{ userId: string }> {
  const { repo, now } = deps;
  const actor = activeActor(deps, actorId);
  if (actor === undefined) return fail('unauthorized');
  const v = validateNewUser(raw, deps.quotaProfiles);
  if (!v.ok) return fail('validation', v.errors);
  let parent: UserRecord | null = null;
  if (parentId !== undefined) {
    parent = repo.getUser(parentId) ?? null;
    if (parent === null) return fail('parent_not_found');
  } else if (actor.role === 'super_admin' && v.value.role !== 'super_admin') {
    parent = actor;
  }
  const decision = canCreateUser(actor, v.value.role, parent);
  if (!decision.ok) {
    repo.audit({ at: now(), actorId, action: 'user.create', outcome: 'denied', metadata: { reason: decision.reason } });
    return fail(decision.reason);
  }
  if (repo.findUserByEmail(v.value.email) !== undefined) return fail('email_taken', [{ field: 'email', code: 'conflict' }]);
  const id = deps.newId();
  repo.insertUser({
    id,
    role: v.value.role,
    managedBy: decision.managedBy,
    status: 'active',
    email: v.value.email,
    firstName: v.value.firstName,
    lastName: v.value.lastName,
    orgUnit: v.value.orgUnit,
    quotaBytes: v.value.quotaBytes,
    maxFiles: v.value.maxFiles,
    passwordHash: null,
    mustChangePassword: true,
    failedLoginCount: 0,
    lockedUntil: null,
    accountExpiresAt: null,
  });
  repo.audit({ at: now(), actorId, action: 'user.create', resourceType: 'user', resourceId: id, outcome: 'success', metadata: { role: v.value.role } });
  return { ok: true, value: { userId: id } };
}

// ---------------------------------------------------------------- uploads

export interface StartUploadInput {
  folderId: string;
  fileName: string;
  uploadLength: string | undefined;
  deferLength?: string | undefined;
  existingFileId?: string;
}

export function startUpload(deps: Deps, actorId: string, input: StartUploadInput): Result<{ sessionId: string }> {
  const { repo, config } = deps;
  const actor = activeActor(deps, actorId);
  if (actor === undefined) return fail('unauthorized');
  const folder = repo.getFolder(input.folderId);
  const owner = folder === undefined ? undefined : repo.getUser(folder.ownerId);
  if (folder === undefined || owner === undefined) return fail('not_found');
  const access = decideContentAccess({ actor, owner, permission: 'UPLOAD', aclPermissions: repo.folderPermissions(actorId, folder.id) });
  if (!access.allowed) return fail('not_found'); // do not reveal that the folder exists
  let existing = undefined;
  if (input.existingFileId !== undefined) {
    existing = repo.getFile(input.existingFileId);
    if (existing === undefined || existing.folderId !== folder.id) return fail('not_found');
  }

  const guard = validateCreate({
    uploadLength: input.uploadLength,
    deferLength: input.deferLength,
    maxFileBytes: config.maxFileBytes,
    activeUploads: repo.countOpenUploads(actorId),
    maxConcurrent: config.maxConcurrentUploads,
  });
  if (!guard.ok) return fail(guard.code);
  // Name, size and extension are checked now; magic bytes are checked when the whole file is there.
  const early = evaluateFilePolicy(
    { name: input.fileName, sizeBytes: guard.value.sizeBytes, header: new Uint8Array(0) },
    { blockedExtensions: config.blockedExtensions, maxFileBytes: config.maxFileBytes },
  );
  if (!early.allowed) return fail(early.reason);

  const files: 0 | 1 = existing === undefined ? 1 : 0;
  const reserved = repo.reserveQuota(actorId, guard.value.sizeBytes, files);
  if (!reserved.ok) return fail(reserved.reason);

  const id = deps.newId();
  repo.insertUpload({
    id,
    userId: actorId,
    folderId: folder.id,
    fileId: existing?.id ?? null,
    originalName: early.name,
    expectedSize: guard.value.sizeBytes,
    offset: 0n,
    state: 'created',
    blobKey: newBlobKey(),
    finalizeKey: null,
    versionId: null,
    reservedFile: files === 1,
    expiresAt: deps.now() + config.uploadTtlMs,
  });
  repo.audit({ at: deps.now(), actorId, action: 'upload.start', resourceType: 'upload', resourceId: id, outcome: 'success' });
  return { ok: true, value: { sessionId: id } };
}

function ownedSession(deps: Deps, actorId: string, sessionId: string): UploadSessionRecord | undefined {
  const s = deps.repo.getUpload(sessionId);
  return s !== undefined && s.userId === actorId ? s : undefined; // someone else's session looks like a missing one
}

function closeSession(deps: Deps, s: UploadSessionRecord, state: UploadSessionRecord['state']): void {
  deps.repo.releaseReservation(s.userId, s.expectedSize, s.reservedFile ? 1 : 0);
  deps.storage.remove('incoming', s.blobKey);
  deps.repo.updateUpload({ ...s, state });
}

export function receiveChunk(
  deps: Deps,
  actorId: string,
  sessionId: string,
  headers: { contentType: string | undefined; uploadOffset: string | undefined; contentLength: string | undefined },
): Result<{ offset: bigint }> {
  const actor = activeActor(deps, actorId);
  if (actor === undefined) return fail('unauthorized');
  const s = ownedSession(deps, actorId, sessionId);
  if (s === undefined) return fail('not_found');
  if (isUploadExpired(s.expiresAt, deps.now(), s.state)) {
    closeSession(deps, s, 'expired');
    return fail('expired');
  }
  const next = nextUploadState(s.state, 'chunk');
  if (next === null) return fail('invalid_state');
  const guard = validatePatch({ ...headers, sessionOffset: s.offset, expectedSize: s.expectedSize, maxChunkBytes: deps.config.maxChunkBytes });
  if (!guard.ok) return fail(guard.code);
  deps.repo.updateUpload({ ...s, state: next, offset: guard.value.newOffset });
  return { ok: true, value: { offset: guard.value.newOffset } };
}

export function cancelUpload(deps: Deps, actorId: string, sessionId: string): Result<null> {
  const s = ownedSession(deps, actorId, sessionId);
  if (s === undefined) return fail('not_found');
  if (nextUploadState(s.state, 'cancel') === null) return fail('invalid_state');
  closeSession(deps, s, 'cancelled');
  deps.repo.audit({ at: deps.now(), actorId, action: 'upload.cancel', resourceType: 'upload', resourceId: s.id, outcome: 'success' });
  return { ok: true, value: null };
}

export function finalizeUpload(
  deps: Deps,
  actorId: string,
  sessionId: string,
  input: { finalizeKey: string; sha256: string; header: Uint8Array },
): Result<{ versionId: string }> {
  const { repo, storage, config } = deps;
  const actor = activeActor(deps, actorId);
  if (actor === undefined) return fail('unauthorized');
  const s = ownedSession(deps, actorId, sessionId);
  if (s === undefined) return fail('not_found');

  // The same finalize request can arrive twice (retry, double click): answer with the same version.
  if (s.state === 'finalized') {
    return s.finalizeKey === input.finalizeKey && s.versionId !== null ? { ok: true, value: { versionId: s.versionId } } : fail('already_finalized');
  }
  if (nextUploadState(s.state, 'finalize_requested') === null) return fail('invalid_state');
  if (s.offset !== s.expectedSize) return fail('incomplete');
  repo.updateUpload({ ...s, state: 'finalizing', finalizeKey: input.finalizeKey });

  const verdict = evaluateFilePolicy(
    { name: s.originalName, sizeBytes: s.expectedSize, header: input.header },
    { blockedExtensions: config.blockedExtensions, maxFileBytes: config.maxFileBytes },
  );
  if (!verdict.allowed) {
    closeSession(deps, { ...s, state: 'finalizing' }, 'failed');
    repo.audit({ at: deps.now(), actorId, action: 'upload.finalize', resourceType: 'upload', resourceId: s.id, outcome: 'denied', metadata: { reason: verdict.reason } });
    return fail(verdict.reason);
  }

  storage.promote('incoming', 'quarantine', s.blobKey);
  const versionId = deps.newId();
  repo.transaction(() => {
    let fileId = s.fileId;
    if (fileId === null) {
      fileId = deps.newId();
      repo.insertFile({ id: fileId, folderId: s.folderId, ownerId: actorId, name: verdict.name, status: 'pending', currentVersionId: null });
    }
    repo.insertVersion({
      id: versionId,
      fileId,
      versionNo: repo.nextVersionNo(fileId),
      blobKey: s.blobKey,
      sizeBytes: s.expectedSize,
      sha256: input.sha256,
      scanState: 'quarantined',
      rejectReason: null,
    });
    repo.updateUpload({ ...s, state: 'finalized', finalizeKey: input.finalizeKey, versionId });
    repo.enqueueScan({ versionId, attempt: 1, delayMs: 0 });
  });
  repo.audit({ at: deps.now(), actorId, action: 'upload.finalize', resourceType: 'version', resourceId: versionId, outcome: 'success' });
  return { ok: true, value: { versionId } };
}

// ---------------------------------------------------------------- scan results

export type ScanCompletion = 'clean' | 'rejected' | 'failed' | 'retry' | 'ignored';

export function completeScan(deps: Deps, versionId: string, result: ScanResult, attempt: number): Result<{ outcome: ScanCompletion }> {
  const { repo, storage } = deps;
  const version = repo.getVersion(versionId);
  const session = repo.findUploadByVersion(versionId);
  const file = version === undefined ? undefined : repo.getFile(version.fileId);
  if (version === undefined || session === undefined || file === undefined) return fail('not_found');
  // A job that runs twice must not commit quota twice or flip a decided version.
  if (version.scanState === 'clean' || version.scanState === 'rejected' || version.scanState === 'failed') return { ok: true, value: { outcome: 'ignored' } };

  const decision = decideScanOutcome(result, attempt);
  const files: 0 | 1 = session.reservedFile ? 1 : 0;
  if (decision.retry) {
    repo.enqueueScan({ versionId, attempt: attempt + 1, delayMs: decision.retryDelayMs });
    return { ok: true, value: { outcome: 'retry' } };
  }
  if (decision.scanState === 'clean') {
    storage.promote('quarantine', 'blobs', version.blobKey);
    repo.transaction(() => {
      repo.updateVersion({ ...version, scanState: 'clean' });
      repo.updateFile({ ...file, status: 'active', currentVersionId: version.id }); // only now does the new version become current
      repo.commitReservation(session.userId, version.sizeBytes, files);
    });
    repo.audit({ at: deps.now(), actorId: null, action: 'scan.clean', resourceType: 'version', resourceId: versionId, outcome: 'success' });
    return { ok: true, value: { outcome: 'clean' } };
  }
  // rejected or failed: the file stays in quarantine, is never downloadable, and gives its quota back
  const scanState = decision.scanState === 'rejected' ? 'rejected' : 'failed';
  repo.transaction(() => {
    repo.updateVersion({ ...version, scanState, rejectReason: decision.rejectReason ?? 'scan_failed' });
    repo.releaseReservation(session.userId, version.sizeBytes, files);
  });
  if (decision.alert) {
    const kind = result.kind === 'infected' ? 'scan_infected' : result.kind === 'limit' ? 'scan_limit' : 'scan_failed';
    repo.alert({ kind, versionId, ownerId: file.ownerId });
  }
  repo.audit({ at: deps.now(), actorId: null, action: `scan.${scanState}`, resourceType: 'version', resourceId: versionId, outcome: 'denied' });
  return { ok: true, value: { outcome: scanState } };
}

// ---------------------------------------------------------------- download

export function issueDownload(deps: Deps, actorId: string, versionId: string): Result<{ token: string }> {
  const { repo, config } = deps;
  const actor = activeActor(deps, actorId);
  if (actor === undefined) return fail('unauthorized');
  const version = repo.getVersion(versionId);
  const file = version === undefined ? undefined : repo.getFile(version.fileId);
  const owner = file === undefined ? undefined : repo.getUser(file.ownerId);
  if (version === undefined || file === undefined || owner === undefined) return fail('not_found');

  const decision = decideContentAccess({
    actor: actor as Actor,
    owner,
    permission: 'DOWNLOAD',
    aclPermissions: repo.folderPermissions(actorId, file.folderId),
    sharePermissions: repo.sharePermissions(actorId, file.id),
  });
  if (!decision.allowed) {
    repo.audit({ at: deps.now(), actorId, action: 'download.denied', resourceType: 'version', resourceId: versionId, outcome: 'denied' });
    return fail('not_found');
  }
  // Access is checked first so an unauthorised caller learns nothing about scan state.
  if (version.scanState !== 'clean' || file.status !== 'active') return fail('not_available');
  if (decision.audit) {
    repo.audit({ at: deps.now(), actorId, action: 'admin_content_access', resourceType: 'version', resourceId: versionId, outcome: 'success', metadata: { owner: owner.id } });
  }
  repo.audit({ at: deps.now(), actorId, action: 'download.authorized', resourceType: 'version', resourceId: versionId, outcome: 'success', metadata: { via: decision.via } });
  const iat = Math.floor(deps.now() / 1000);
  return { ok: true, value: { token: signDownloadToken({ versionId, userId: actorId, iat, exp: iat + 60 }, config.downloadSecret) } };
}
