import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { verifyDownloadToken } from '../policy/tokens.ts';
import { PE_HEADER_FOR_TESTS, setup } from './test-world.ts';
import { cancelUpload, completeScan, createUser, finalizeUpload, issueDownload, receiveChunk, startUpload } from './use-cases.ts';

const CT = 'application/offset+octet-stream';
const text = new TextEncoder().encode('plain text');
const MIB = 1024 * 1024;

function upload(w: ReturnType<typeof setup>, userId: string, size: number, name = 'report.pdf', folderId = `f-${userId}`) {
  const started = startUpload(w.deps, userId, { folderId, fileName: name, uploadLength: String(size) });
  assert.ok(started.ok, started.ok ? '' : started.code);
  const sent = receiveChunk(w.deps, userId, started.value.sessionId, { contentType: CT, uploadOffset: '0', contentLength: String(size) });
  assert.ok(sent.ok, sent.ok ? '' : sent.code);
  return started.value.sessionId;
}

function finish(w: ReturnType<typeof setup>, userId: string, sessionId: string, header: Uint8Array = text) {
  return finalizeUpload(w.deps, userId, sessionId, { finalizeKey: randomUUID(), sha256: 'a'.repeat(64), header });
}

test('creating users: region isolation and mandatory limits', () => {
  const w = setup();
  const base = { first_name: 'نو', last_name: 'کاربر', org_unit: 'IT', quota_mb: '1', max_files: '2' };
  assert.equal(createUser(w.deps, w.regionA, { ...base, email: 'new@example.com', role: 'region_manager' }).ok, false); // managers cannot create managers
  const noLimits = createUser(w.deps, w.regionA, { ...base, email: 'new@example.com', quota_mb: '', max_files: '' });
  assert.ok(!noLimits.ok && noLimits.code === 'validation');
  const ok = createUser(w.deps, w.regionA, { ...base, email: 'new@example.com' });
  assert.ok(ok.ok);
  assert.equal(w.repo.getUser(ok.value.userId)?.managedBy, w.regionA); // always under the creating manager
  const dup = createUser(w.deps, w.regionA, { ...base, email: 'NEW@example.com' });
  assert.ok(!dup.ok && dup.code === 'email_taken');
  assert.equal(createUser(w.deps, w.regionA, { ...base, email: 'x@example.com' }, w.regionB).ok, false); // cannot create under another manager
});

test('full lifecycle: upload, scan, owner and own manager download; other region and strangers cannot', () => {
  const w = setup();
  const session = upload(w, w.userA1, 400_000);
  const fin = finish(w, w.userA1, session);
  assert.ok(fin.ok);
  const versionId = fin.value.versionId;
  assert.deepEqual(w.storage.calls, [['promote', 'incoming', 'quarantine', w.repo.getUpload(session)?.blobKey]]);

  // Before the scan finishes nobody can download, not even the owner.
  const early = issueDownload(w.deps, w.userA1, versionId);
  assert.ok(!early.ok && early.code === 'not_available');
  assert.equal(w.repo.getFile(w.repo.getVersion(versionId)!.fileId)?.currentVersionId, null);

  assert.deepEqual(completeScan(w.deps, versionId, { kind: 'clean' }, 1), { ok: true, value: { outcome: 'clean' } });
  assert.equal(w.repo.getUsage(w.userA1).usedBytes, 400_000n);
  assert.equal(w.repo.getUsage(w.userA1).reservedBytes, 0n);
  assert.equal(w.repo.getUsage(w.userA1).fileCount, 1);

  const own = issueDownload(w.deps, w.userA1, versionId);
  assert.ok(own.ok);
  const verified = verifyDownloadToken(own.value.token, w.deps.config.downloadSecret, Math.floor(w.clock.now / 1000), { versionId, userId: w.userA1 });
  assert.ok(verified.ok);

  const manager = issueDownload(w.deps, w.regionA, versionId);
  assert.ok(manager.ok);
  assert.ok(w.repo.auditLog.some((e) => e.action === 'admin_content_access' && e.actorId === w.regionA)); // manager access is audited
  assert.ok(issueDownload(w.deps, w.admin, versionId).ok);

  for (const stranger of [w.regionB, w.userB1, w.userA2]) {
    const r = issueDownload(w.deps, stranger, versionId);
    assert.ok(!r.ok && r.code === 'not_found', stranger);
  }
  assert.ok(w.repo.auditLog.some((e) => e.action === 'download.denied' && e.actorId === w.userB1));

  // A share grants access to exactly that file and nothing else.
  w.repo.shares.set(`${w.userB1}|${w.repo.getVersion(versionId)!.fileId}`, new Set(['DOWNLOAD']));
  assert.ok(issueDownload(w.deps, w.userB1, versionId).ok);
});

test('quota: bytes and file count are enforced, reservations count, rejections give quota back', () => {
  const w = setup(); // userA1: 1 MiB and 2 files
  const s1 = upload(w, w.userA1, 600_000);
  const tooBig = startUpload(w.deps, w.userA1, { folderId: `f-${w.userA1}`, fileName: 'b.pdf', uploadLength: '600000' });
  assert.ok(!tooBig.ok && tooBig.code === 'quota_bytes_exceeded'); // the first upload's reservation already counts
  const fin = finish(w, w.userA1, s1);
  assert.ok(fin.ok);
  completeScan(w.deps, fin.value.versionId, { kind: 'clean' }, 1);

  const s2 = upload(w, w.userA1, 1000, 'c.txt');
  const fin2 = finish(w, w.userA1, s2);
  assert.ok(fin2.ok);
  completeScan(w.deps, fin2.value.versionId, { kind: 'clean' }, 1);
  const third = startUpload(w.deps, w.userA1, { folderId: `f-${w.userA1}`, fileName: 'd.txt', uploadLength: '10' });
  assert.ok(!third.ok && third.code === 'quota_files_exceeded');

  // A new version of an existing file needs no file slot.
  const fileId = w.repo.getVersion(fin2.value.versionId)!.fileId;
  const v2 = startUpload(w.deps, w.userA1, { folderId: `f-${w.userA1}`, fileName: 'c.txt', uploadLength: '10', existingFileId: fileId });
  assert.ok(v2.ok);
  const use = w.repo.getUsage(w.userA1);
  assert.equal(use.reservedFiles, 0);
  assert.equal(use.reservedBytes, 10n);
});

test('infected file: never downloadable, quota released, managers alerted, repeated job ignored', () => {
  const w = setup();
  const fin = finish(w, w.userA1, upload(w, w.userA1, 5000, 'invoice.pdf'));
  assert.ok(fin.ok);
  const r = completeScan(w.deps, fin.value.versionId, { kind: 'infected', signature: 'Eicar-Test-Signature' }, 1);
  assert.deepEqual(r, { ok: true, value: { outcome: 'rejected' } });
  assert.deepEqual(w.repo.alerts, [{ kind: 'scan_infected', versionId: fin.value.versionId, ownerId: w.userA1 }]);
  assert.equal(w.repo.getUsage(w.userA1).reservedBytes, 0n);
  assert.equal(w.repo.getUsage(w.userA1).usedBytes, 0n);
  for (const who of [w.userA1, w.regionA, w.admin]) {
    const d = issueDownload(w.deps, who, fin.value.versionId);
    assert.ok(!d.ok && d.code === 'not_available', who);
  }
  assert.deepEqual(completeScan(w.deps, fin.value.versionId, { kind: 'clean' }, 2), { ok: true, value: { outcome: 'ignored' } });
  assert.equal(w.repo.getVersion(fin.value.versionId)?.scanState, 'rejected');
});

test('scanner failures retry, then fail closed with an alert', () => {
  const w = setup();
  const fin = finish(w, w.userA1, upload(w, w.userA1, 5000));
  assert.ok(fin.ok);
  assert.deepEqual(completeScan(w.deps, fin.value.versionId, { kind: 'timeout' }, 1), { ok: true, value: { outcome: 'retry' } });
  assert.deepEqual(w.repo.scanQueue.at(-1), { versionId: fin.value.versionId, attempt: 2, delayMs: 30_000 });
  completeScan(w.deps, fin.value.versionId, { kind: 'error' }, 2);
  assert.deepEqual(completeScan(w.deps, fin.value.versionId, { kind: 'error' }, 3), { ok: true, value: { outcome: 'failed' } });
  assert.equal(w.repo.alerts.at(-1)?.kind, 'scan_failed');
  assert.ok(!issueDownload(w.deps, w.userA1, fin.value.versionId).ok);
});

test('disguised executable is rejected at finalize and its reservation is released', () => {
  const w = setup();
  const s = upload(w, w.userA1, 300, 'holiday.pdf');
  const r = finish(w, w.userA1, s, PE_HEADER_FOR_TESTS);
  assert.ok(!r.ok && r.code === 'detected_executable');
  assert.equal(w.repo.getUsage(w.userA1).reservedBytes, 0n);
  assert.equal(w.repo.getUpload(s)?.state, 'failed');
  assert.deepEqual(w.storage.calls.at(-1), ['remove', 'incoming', w.repo.getUpload(s)?.blobKey]);
  assert.equal(w.repo.versions.size, 0);
});

test('early rejections: blocked extension, too large, deferred length, too many concurrent uploads, someone else folder', () => {
  const w = setup();
  const f = `f-${w.userA1}`;
  w.repo.updateUser({ ...w.repo.getUser(w.userA1)!, maxFiles: 10 }); // so the concurrency limit is what stops us, not the file count
  const start = (over: object) => startUpload(w.deps, w.userA1, { folderId: f, fileName: 'a.txt', uploadLength: '10', ...over });
  assert.ok(!start({ fileName: 'setup.exe' }).ok);
  assert.deepEqual(start({ uploadLength: String(6 * MIB * 1024) }), { ok: false, code: 'file_too_large' });
  assert.deepEqual(start({ deferLength: '1' }), { ok: false, code: 'defer_length_not_supported' });
  for (let i = 0; i < 3; i++) assert.ok(start({}).ok);
  assert.deepEqual(start({}), { ok: false, code: 'too_many_concurrent_uploads' });
  const foreign = startUpload(w.deps, w.userB1, { folderId: f, fileName: 'a.txt', uploadLength: '10' });
  assert.deepEqual(foreign, { ok: false, code: 'not_found' });
  const manager = startUpload(w.deps, w.regionA, { folderId: f, fileName: 'a.txt', uploadLength: '10' });
  assert.deepEqual(manager, { ok: false, code: 'not_found' }); // managers cannot upload on behalf of users
});

test('chunks: wrong offset gets resync, other users sessions are invisible, expiry releases quota, cancel works', () => {
  const w = setup();
  const started = startUpload(w.deps, w.userA1, { folderId: `f-${w.userA1}`, fileName: 'a.bin', uploadLength: '1000' });
  assert.ok(started.ok);
  const id = started.value.sessionId;
  const hdr = (o: string, l: string) => ({ contentType: CT, uploadOffset: o, contentLength: l });
  assert.deepEqual(receiveChunk(w.deps, w.userA1, id, hdr('0', '400')), { ok: true, value: { offset: 400n } });
  assert.deepEqual(receiveChunk(w.deps, w.userA1, id, hdr('0', '400')), { ok: false, code: 'offset_mismatch' }); // duplicate chunk
  assert.deepEqual(receiveChunk(w.deps, w.userB1, id, hdr('400', '100')), { ok: false, code: 'not_found' });
  assert.deepEqual(finalizeUpload(w.deps, w.userA1, id, { finalizeKey: 'k', sha256: 'a'.repeat(64), header: text }), { ok: false, code: 'incomplete' });

  w.clock.now += w.deps.config.uploadTtlMs + 1;
  assert.deepEqual(receiveChunk(w.deps, w.userA1, id, hdr('400', '100')), { ok: false, code: 'expired' });
  assert.equal(w.repo.getUsage(w.userA1).reservedBytes, 0n);

  const again = startUpload(w.deps, w.userA1, { folderId: `f-${w.userA1}`, fileName: 'b.bin', uploadLength: '1000' });
  assert.ok(again.ok);
  assert.ok(cancelUpload(w.deps, w.userA1, again.value.sessionId).ok);
  assert.equal(w.repo.getUsage(w.userA1).reservedBytes, 0n);
  assert.deepEqual(cancelUpload(w.deps, w.userA1, again.value.sessionId), { ok: false, code: 'invalid_state' });
});

test('finalize is idempotent: the same key returns the same version and creates only one', () => {
  const w = setup();
  const s = upload(w, w.userA1, 2000);
  const key = randomUUID();
  const input = { finalizeKey: key, sha256: 'b'.repeat(64), header: text };
  const first = finalizeUpload(w.deps, w.userA1, s, input);
  const second = finalizeUpload(w.deps, w.userA1, s, input);
  assert.ok(first.ok && second.ok);
  assert.equal(first.value.versionId, second.value.versionId);
  assert.equal(w.repo.versions.size, 1);
  assert.equal(w.repo.scanQueue.length, 1);
  assert.deepEqual(finalizeUpload(w.deps, w.userA1, s, { ...input, finalizeKey: randomUUID() }), { ok: false, code: 'already_finalized' });
});

test('a new version stays hidden until it is clean; the old clean version remains current', () => {
  const w = setup();
  const first = finish(w, w.userA1, upload(w, w.userA1, 1000, 'plan.txt'));
  assert.ok(first.ok);
  completeScan(w.deps, first.value.versionId, { kind: 'clean' }, 1);
  const fileId = w.repo.getVersion(first.value.versionId)!.fileId;

  const started = startUpload(w.deps, w.userA1, { folderId: `f-${w.userA1}`, fileName: 'plan.txt', uploadLength: '2000', existingFileId: fileId });
  assert.ok(started.ok);
  receiveChunk(w.deps, w.userA1, started.value.sessionId, { contentType: CT, uploadOffset: '0', contentLength: '2000' });
  const second = finish(w, w.userA1, started.value.sessionId);
  assert.ok(second.ok);
  assert.equal(w.repo.getVersion(second.value.versionId)?.versionNo, 2);
  assert.equal(w.repo.getFile(fileId)?.currentVersionId, first.value.versionId);
  completeScan(w.deps, second.value.versionId, { kind: 'infected', signature: 'x' }, 1);
  assert.equal(w.repo.getFile(fileId)?.currentVersionId, first.value.versionId);
  assert.ok(issueDownload(w.deps, w.userA1, first.value.versionId).ok);
});

test('disabled users can do nothing', () => {
  const w = setup();
  w.repo.updateUser({ ...w.repo.getUser(w.userA1)!, status: 'disabled' });
  assert.deepEqual(startUpload(w.deps, w.userA1, { folderId: `f-${w.userA1}`, fileName: 'a.txt', uploadLength: '10' }), { ok: false, code: 'unauthorized' });
  assert.deepEqual(issueDownload(w.deps, w.userA1, 'x'), { ok: false, code: 'unauthorized' });
});
