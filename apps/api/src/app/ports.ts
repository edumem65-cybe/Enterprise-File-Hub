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
  createdBy: string;
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
  getUser(id: string): Promise<UserRecord | undefined>;
  findUserByEmail(email: string): Promise<UserRecord | undefined>;
  insertUser(u: UserRecord): Promise<void>;
  updateUser(u: UserRecord): Promise<void>;

  getUsage(userId: string): Promise<Usage>;
  reserveQuota(userId: string, bytes: bigint, files: 0 | 1): Promise<{ ok: true } | { ok: false; reason: 'quota_bytes_exceeded' | 'quota_files_exceeded' }>;
  releaseReservation(userId: string, bytes: bigint, files: 0 | 1): Promise<void>;
  commitReservation(userId: string, bytes: bigint, files: 0 | 1): Promise<void>;

  countOpenUploads(userId: string): Promise<number>;
  insertUpload(s: UploadSessionRecord): Promise<void>;
  getUpload(id: string): Promise<UploadSessionRecord | undefined>;
  updateUpload(s: UploadSessionRecord): Promise<void>;
  findUploadByVersion(versionId: string): Promise<UploadSessionRecord | undefined>;

  getFolder(id: string): Promise<FolderRecord | undefined>;
  folderPermissions(userId: string, folderId: string): Promise<ReadonlySet<ContentPermission>>;
  sharePermissions(userId: string, fileId: string): Promise<ReadonlySet<ContentPermission>>;

  insertFile(f: FileRecord): Promise<void>;
  getFile(id: string): Promise<FileRecord | undefined>;
  updateFile(f: FileRecord): Promise<void>;
  insertVersion(v: VersionRecord): Promise<void>;
  getVersion(id: string): Promise<VersionRecord | undefined>;
  updateVersion(v: VersionRecord): Promise<void>;
  nextVersionNo(fileId: string): Promise<number>;

  audit(e: AuditEvent): Promise<void>;
  alert(a: AlertEvent): Promise<void>;
  enqueueScan(job: ScanJob): Promise<void>;
  transaction<T>(fn: () => Promise<T>): Promise<T>;
}

export interface StoragePort {
  promote(from: Stage, to: Stage, key: string): Promise<void>;
  remove(stage: Stage, key: string): Promise<void>;
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
