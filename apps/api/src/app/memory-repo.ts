import { evaluateReservation } from '../policy/quota.ts';
import type { Usage } from '../policy/quota.ts';
import type { ContentPermission } from '../policy/types.ts';
import type { AlertEvent, AuditEvent, FileRecord, FolderRecord, Repo, ScanJob, UploadSessionRecord, UserRecord, VersionRecord } from './ports.ts';

// In-memory Repo for tests and local experiments. Mirrors the semantics the PostgreSQL adapter must provide.
export class MemoryRepo implements Repo {
  users = new Map<string, UserRecord>();
  usage = new Map<string, Usage>();
  uploads = new Map<string, UploadSessionRecord>();
  folders = new Map<string, FolderRecord>();
  files = new Map<string, FileRecord>();
  versions = new Map<string, VersionRecord>();
  folderAcl = new Map<string, Set<ContentPermission>>(); // key: userId|folderId
  shares = new Map<string, Set<ContentPermission>>(); // key: userId|fileId
  auditLog: AuditEvent[] = [];
  alerts: AlertEvent[] = [];
  scanQueue: ScanJob[] = [];

  async getUser(id: string): Promise<UserRecord | undefined> {
    return this.users.get(id);
  }
  async findUserByEmail(email: string): Promise<UserRecord | undefined> {
    for (const u of this.users.values()) if (u.email === email) return u;
    return undefined;
  }
  async insertUser(u: UserRecord): Promise<void> {
    this.users.set(u.id, u);
    this.usage.set(u.id, { usedBytes: 0n, reservedBytes: 0n, fileCount: 0, reservedFiles: 0 });
  }
  async updateUser(u: UserRecord): Promise<void> {
    this.users.set(u.id, u);
  }

  async getUsage(userId: string): Promise<Usage> {
    return this.usage.get(userId) as Usage;
  }
  async reserveQuota(userId: string, bytes: bigint, files: 0 | 1) {
    const u = this.users.get(userId) as UserRecord;
    const usage = this.peekUsage(userId);
    const r = evaluateReservation(usage, { quotaBytes: u.quotaBytes, maxFiles: u.maxFiles }, bytes, files);
    if (r.ok) this.usage.set(userId, { ...usage, reservedBytes: usage.reservedBytes + bytes, reservedFiles: usage.reservedFiles + files });
    return r;
  }
  async releaseReservation(userId: string, bytes: bigint, files: 0 | 1): Promise<void> {
    const usage = this.peekUsage(userId);
    this.usage.set(userId, { ...usage, reservedBytes: usage.reservedBytes - bytes, reservedFiles: usage.reservedFiles - files });
  }
  async commitReservation(userId: string, bytes: bigint, files: 0 | 1): Promise<void> {
    const usage = this.peekUsage(userId);
    this.usage.set(userId, {
      usedBytes: usage.usedBytes + bytes,
      reservedBytes: usage.reservedBytes - bytes,
      fileCount: usage.fileCount + files,
      reservedFiles: usage.reservedFiles - files,
    });
  }

  async countOpenUploads(userId: string): Promise<number> {
    let n = 0;
    for (const s of this.uploads.values()) if (s.userId === userId && (s.state === 'created' || s.state === 'uploading' || s.state === 'finalizing')) n++;
    return n;
  }
  async insertUpload(s: UploadSessionRecord): Promise<void> {
    this.uploads.set(s.id, s);
  }
  async getUpload(id: string): Promise<UploadSessionRecord | undefined> {
    return this.uploads.get(id);
  }
  async updateUpload(s: UploadSessionRecord): Promise<void> {
    this.uploads.set(s.id, s);
  }
  async findUploadByVersion(versionId: string): Promise<UploadSessionRecord | undefined> {
    for (const s of this.uploads.values()) if (s.versionId === versionId) return s;
    return undefined;
  }

  async getFolder(id: string): Promise<FolderRecord | undefined> {
    return this.folders.get(id);
  }
  async folderPermissions(userId: string, folderId: string): Promise<ReadonlySet<ContentPermission>> {
    return this.folderAcl.get(`${userId}|${folderId}`) ?? new Set();
  }
  async sharePermissions(userId: string, fileId: string): Promise<ReadonlySet<ContentPermission>> {
    return this.shares.get(`${userId}|${fileId}`) ?? new Set();
  }

  async insertFile(f: FileRecord): Promise<void> {
    this.files.set(f.id, f);
  }
  async getFile(id: string): Promise<FileRecord | undefined> {
    return this.files.get(id);
  }
  async updateFile(f: FileRecord): Promise<void> {
    this.files.set(f.id, f);
  }
  async insertVersion(v: VersionRecord): Promise<void> {
    this.versions.set(v.id, v);
  }
  async getVersion(id: string): Promise<VersionRecord | undefined> {
    return this.versions.get(id);
  }
  async updateVersion(v: VersionRecord): Promise<void> {
    this.versions.set(v.id, v);
  }
  async nextVersionNo(fileId: string): Promise<number> {
    let max = 0;
    for (const v of this.versions.values()) if (v.fileId === fileId && v.versionNo > max) max = v.versionNo;
    return max + 1;
  }

  async audit(e: AuditEvent): Promise<void> {
    this.auditLog.push(e);
  }
  async alert(a: AlertEvent): Promise<void> {
    this.alerts.push(a);
  }
  async enqueueScan(job: ScanJob): Promise<void> {
    this.scanQueue.push(job);
  }
  async transaction<T>(fn: () => Promise<T>): Promise<T> {
    return fn();
  }

  // Synchronous inspection helpers for tests (not part of the Repo port).
  peekUser(id: string): UserRecord | undefined {
    return this.users.get(id);
  }
  peekUsage(id: string): Usage {
    return this.usage.get(id) as Usage;
  }
  peekUpload(id: string): UploadSessionRecord | undefined {
    return this.uploads.get(id);
  }
  peekFile(id: string): FileRecord | undefined {
    return this.files.get(id);
  }
  peekVersion(id: string): VersionRecord | undefined {
    return this.versions.get(id);
  }
}
