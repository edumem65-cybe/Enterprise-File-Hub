import type { ContentPermission, UserRef } from '../policy/types.ts';
import type { Usage } from '../policy/quota.ts';
import type { QuotaProfile } from '../users/user-input.ts';
import type { Stage } from '../storage/paths.ts';
import type { UploadState } from '../upload/state-machine.ts';

export interface UserRecord extends UserRef {
  email: string;
  firstName: string;
  lastName: string;
  orgUnit: string;
  quotaBytes: bigint | null;
  maxFiles: number | null;
  passwordHash: string | null;
  mustChangePassword: boolean;
  failedLoginCount: number;
  lockedUntil: number | null;
  accountExpiresAt: number | null;
}

export interface FolderRecord {
  id: string;
  ownerId: string;
}

export interface UploadSessionRecord {
  id: string;
  userId: string;
  folderId: string;
  fileId: string | null; // set when uploading a new version of an existing file
  originalName: string;
  expectedSize: bigint;
  offset: bigint;
  state: UploadState;
  blobKey: string;
  finalizeKey: string | null;
  versionId: string | null;
  reservedFile: boolean;
  expiresAt: number;
}

export interface FileRecord {
  id: string;
  folderId: string;
  ownerId: string;
  name: string;
  status: 'pending' | 'active' | 'trashed';
  currentVersionId: string | null;
}

export type ScanState = 'quarantined' | 'scanning' | 'clean' | 'rejected' | 'failed';

export interface VersionRecord {
  id: string;
  fileId: string;
  versionNo: number;
  blobKey: string;
  sizeBytes: bigint;
  sha256: string;
  scanState: ScanState;
  rejectReason: string | null;
}

export interface AuditEvent {
  at: number;
  actorId: string | null;
  action: string;
  resourceType?: string;
  resourceId?: string;
  outcome: 'success' | 'denied' | 'error';
  metadata?: Record<string, string | number | boolean | null>;
}

export interface AlertEvent {
  kind: 'scan_infected' | 'scan_failed' | 'scan_limit';
  versionId: string;
  ownerId: string;
}

export interface ScanJob {
  versionId: string;
  attempt: number;
  delayMs: number;
}

// Persistence port. The PostgreSQL adapter implements it; tests use the in-memory one.
export interface Repo {
  getUser(id: string): UserRecord | undefined;
  findUserByEmail(email: string): UserRecord | undefined;
  insertUser(u: UserRecord): void;
  updateUser(u: UserRecord): void;

  getUsage(userId: string): Usage;
  reserveQuota(userId: string, bytes: bigint, files: 0 | 1): { ok: true } | { ok: false; reason: 'quota_bytes_exceeded' | 'quota_files_exceeded' };
  releaseReservation(userId: string, bytes: bigint, files: 0 | 1): void;
  commitReservation(userId: string, bytes: bigint, files: 0 | 1): void;

  countOpenUploads(userId: string): number;
  insertUpload(s: UploadSessionRecord): void;
  getUpload(id: string): UploadSessionRecord | undefined;
  updateUpload(s: UploadSessionRecord): void;
  findUploadByVersion(versionId: string): UploadSessionRecord | undefined;

  getFolder(id: string): FolderRecord | undefined;
  folderPermissions(userId: string, folderId: string): ReadonlySet<ContentPermission>;
  sharePermissions(userId: string, fileId: string): ReadonlySet<ContentPermission>;

  insertFile(f: FileRecord): void;
  getFile(id: string): FileRecord | undefined;
  updateFile(f: FileRecord): void;
  insertVersion(v: VersionRecord): void;
  getVersion(id: string): VersionRecord | undefined;
  updateVersion(v: VersionRecord): void;
  nextVersionNo(fileId: string): number;

  audit(e: AuditEvent): void;
  alert(a: AlertEvent): void;
  enqueueScan(job: ScanJob): void;
  transaction<T>(fn: () => T): T;
}

export interface StoragePort {
  promote(from: Stage, to: Stage, key: string): void;
  remove(stage: Stage, key: string): void;
}

export interface Config {
  maxFileBytes: bigint;
  maxChunkBytes: bigint;
  maxConcurrentUploads: number;
  uploadTtlMs: number;
  blockedExtensions: ReadonlySet<string>;
  downloadSecret: string;
}

export interface Deps {
  repo: Repo;
  storage: StoragePort;
  config: Config;
  quotaProfiles: ReadonlyMap<string, QuotaProfile>;
  now: () => number;
  newId: () => string;
}
