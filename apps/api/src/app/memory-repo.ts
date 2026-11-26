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

  getUser(id: string): UserRecord | undefined {
    return this.users.get(id);
  }
  findUserByEmail(email: string): UserRecord | undefined {
    for (const u of this.users.values()) if (u.email === email) return u;
    return undefined;
  }
  insertUser(u: UserRecord): void {
    this.users.set(u.id, u);
    this.usage.set(u.id, { usedBytes: 0n, reservedBytes: 0n, fileCount: 0, reservedFiles: 0 });
  }
  updateUser(u: UserRecord): void {
    this.users.set(u.id, u);
  }

  getUsage(userId: string): Usage {
    return this.usage.get(userId) as Usage;
  }
  reserveQuota(userId: string, bytes: bigint, files: 0 | 1) {
    const u = this.users.get(userId) as UserRecord;
    const usage = this.getUsage(userId);
    const r = evaluateReservation(usage, { quotaBytes: u.quotaBytes, maxFiles: u.maxFiles }, bytes, files);
    if (r.ok) this.usage.set(userId, { ...usage, reservedBytes: usage.reservedBytes + bytes, reservedFiles: usage.reservedFiles + files });
    return r;
  }
  releaseReservation(userId: string, bytes: bigint, files: 0 | 1): void {
    const usage = this.getUsage(userId);
    this.usage.set(userId, { ...usage, reservedBytes: usage.reservedBytes - bytes, reservedFiles: usage.reservedFiles - files });
  }
  commitReservation(userId: string, bytes: bigint, files: 0 | 1): void {
    const usage = this.getUsage(userId);
    this.usage.set(userId, {
      usedBytes: usage.usedBytes + bytes,
      reservedBytes: usage.reservedBytes - bytes,
      fileCount: usage.fileCount + files,
      reservedFiles: usage.reservedFiles - files,
    });
  }

  countOpenUploads(userId: string): number {
    let n = 0;
    for (const s of this.uploads.values()) if (s.userId === userId && (s.state === 'created' || s.state === 'uploading' || s.state === 'finalizing')) n++;
    return n;
  }
  insertUpload(s: UploadSessionRecord): void {
    this.uploads.set(s.id, s);
  }
  getUpload(id: string): UploadSessionRecord | undefined {
    return this.uploads.get(id);
  }
  updateUpload(s: UploadSessionRecord): void {
    this.uploads.set(s.id, s);
  }
  findUploadByVersion(versionId: string): UploadSessionRecord | undefined {
    for (const s of this.uploads.values()) if (s.versionId === versionId) return s;
    return undefined;
  }

  getFolder(id: string): FolderRecord | undefined {
    return this.folders.get(id);
  }
  folderPermissions(userId: string, folderId: string): ReadonlySet<ContentPermission> {
    return this.folderAcl.get(`${userId}|${folderId}`) ?? new Set();
  }
  sharePermissions(userId: string, fileId: string): ReadonlySet<ContentPermission> {
    return this.shares.get(`${userId}|${fileId}`) ?? new Set();
  }

  insertFile(f: FileRecord): void {
    this.files.set(f.id, f);
  }
  getFile(id: string): FileRecord | undefined {
    return this.files.get(id);
  }
  updateFile(f: FileRecord): void {
    this.files.set(f.id, f);
  }
  insertVersion(v: VersionRecord): void {
    this.versions.set(v.id, v);
  }
  getVersion(id: string): VersionRecord | undefined {
    return this.versions.get(id);
  }
  updateVersion(v: VersionRecord): void {
    this.versions.set(v.id, v);
  }
  nextVersionNo(fileId: string): number {
    let max = 0;
    for (const v of this.versions.values()) if (v.fileId === fileId && v.versionNo > max) max = v.versionNo;
    return max + 1;
  }

  audit(e: AuditEvent): void {
    this.auditLog.push(e);
  }
  alert(a: AlertEvent): void {
    this.alerts.push(a);
  }
  enqueueScan(job: ScanJob): void {
    this.scanQueue.push(job);
  }
  transaction<T>(fn: () => T): T {
    return fn();
  }
}
