import { AsyncLocalStorage } from 'node:async_hooks';
import { evaluateReservation } from '../policy/quota.ts';
import type { Usage } from '../policy/quota.ts';
import type { ContentPermission } from '../policy/types.ts';
import type {
  AlertEvent,
  AuditEvent,
  FileRecord,
  FolderRecord,
  Repo,
  ScanJob,
  UploadSessionRecord,
  UserRecord,
  VersionRecord,
} from '../app/ports.ts';
import type { UploadState } from '../upload/state-machine.ts';

// Minimal structural types: node-postgres (`pg`) Pool/PoolClient satisfy them, so this module needs no driver import.
export interface SqlResult {
  rows: Record<string, unknown>[];
  rowCount: number | null;
}
export interface SqlRunner {
  query(text: string, params?: unknown[]): Promise<SqlResult>;
}
export interface SqlPool extends SqlRunner {
  connect(): Promise<SqlRunner & { release(): void }>;
}

const big = (v: unknown): bigint => BigInt(v as string | number | bigint);
const ms = (v: unknown): number | null => (v === null || v === undefined ? null : (v as Date).getTime());
const str = (v: unknown): string => v as string;

const USER_SELECT = `
  SELECT u.id, u.role, u.managed_by, u.status, u.email, u.first_name, u.last_name, ou.name AS org_unit,
         u.quota_bytes, u.max_files, u.password_hash, u.must_change_password, u.failed_login_count,
         u.locked_until, u.account_expires_at
    FROM users u JOIN org_units ou ON ou.id = u.org_unit_id`;

function toUser(r: Record<string, unknown>): UserRecord {
  return {
    id: str(r.id),
    role: r.role as UserRecord['role'],
    managedBy: (r.managed_by as string | null) ?? null,
    status: r.status as UserRecord['status'],
    email: str(r.email),
    firstName: str(r.first_name),
    lastName: str(r.last_name),
    orgUnit: str(r.org_unit),
    quotaBytes: r.quota_bytes === null ? null : big(r.quota_bytes),
    maxFiles: r.max_files === null ? null : Number(r.max_files),
    passwordHash: (r.password_hash as string | null) ?? null,
    mustChangePassword: Boolean(r.must_change_password),
    failedLoginCount: Number(r.failed_login_count),
    lockedUntil: ms(r.locked_until),
    accountExpiresAt: ms(r.account_expires_at),
  };
}

const UPLOAD_SELECT = `
  SELECT id, user_id, folder_id, file_id, original_name, expected_size, offset_bytes, state, blob_key,
         finalize_key, version_id, reserved_file, expires_at
    FROM upload_sessions`;

function toUpload(r: Record<string, unknown>): UploadSessionRecord {
  return {
    id: str(r.id),
    userId: str(r.user_id),
    folderId: str(r.folder_id),
    fileId: (r.file_id as string | null) ?? null,
    originalName: str(r.original_name),
    expectedSize: big(r.expected_size),
    offset: big(r.offset_bytes),
    state: r.state as UploadState,
    blobKey: str(r.blob_key),
    finalizeKey: (r.finalize_key as string | null) ?? null,
    versionId: (r.version_id as string | null) ?? null,
    reservedFile: Boolean(r.reserved_file),
    expiresAt: ms(r.expires_at) as number,
  };
}

function toFile(r: Record<string, unknown>): FileRecord {
  return {
    id: str(r.id),
    folderId: str(r.folder_id),
    ownerId: str(r.owner_id),
    name: str(r.display_name),
    status: r.status as FileRecord['status'],
    currentVersionId: (r.current_version_id as string | null) ?? null,
  };
}

function toVersion(r: Record<string, unknown>): VersionRecord {
  return {
    id: str(r.id),
    fileId: str(r.file_id),
    versionNo: Number(r.version_no),
    blobKey: str(r.blob_key),
    sizeBytes: big(r.size_bytes),
    sha256: str(r.sha256),
    scanState: r.scan_state as VersionRecord['scanState'],
    rejectReason: (r.reject_reason as string | null) ?? null,
    createdBy: str(r.created_by),
  };
}

// PostgreSQL adapter for the Repo port (migrations 0001-0004). Transactions use AsyncLocalStorage so every
// call made inside `transaction(fn)` runs on the same connection without passing a client around.
export class PostgresRepo implements Repo {
  private readonly tx = new AsyncLocalStorage<SqlRunner>();
  private readonly pool: SqlPool;

  constructor(pool: SqlPool) {
    this.pool = pool;
  }

  private db(): SqlRunner {
    return this.tx.getStore() ?? this.pool;
  }

  async transaction<T>(fn: () => Promise<T>): Promise<T> {
    if (this.tx.getStore() !== undefined) return fn(); // already inside a transaction
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await this.tx.run(client, fn);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  // ---- users
  async getUser(id: string): Promise<UserRecord | undefined> {
    const r = await this.db().query(`${USER_SELECT} WHERE u.id = $1`, [id]);
    return r.rows[0] === undefined ? undefined : toUser(r.rows[0]);
  }

  async findUserByEmail(email: string): Promise<UserRecord | undefined> {
    const r = await this.db().query(`${USER_SELECT} WHERE lower(u.email) = lower($1)`, [email]);
    return r.rows[0] === undefined ? undefined : toUser(r.rows[0]);
  }

  async insertUser(u: UserRecord): Promise<void> {
    const ou = await this.db().query('SELECT id FROM org_units WHERE name = $1 OR id::text = $1 LIMIT 1', [u.orgUnit]);
    if (ou.rows[0] === undefined) throw new Error(`org unit not found: ${u.orgUnit}`);
    // username mirrors the email until an IdP provides its own identifier (ADR-0008)
    await this.db().query(
      `INSERT INTO users (id, username, email, first_name, last_name, org_unit_id, role, managed_by, status, quota_bytes, max_files,
                          password_hash, must_change_password, failed_login_count, locked_until, account_expires_at)
       VALUES ($1,$2,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
               CASE WHEN $14::bigint IS NULL THEN NULL ELSE to_timestamp($14::bigint / 1000.0) END,
               CASE WHEN $15::bigint IS NULL THEN NULL ELSE to_timestamp($15::bigint / 1000.0) END)`,
      [u.id, u.email, u.firstName, u.lastName, ou.rows[0].id, u.role, u.managedBy, u.status, u.quotaBytes?.toString() ?? null, u.maxFiles,
        u.passwordHash, u.mustChangePassword, u.failedLoginCount, u.lockedUntil, u.accountExpiresAt],
    );
  }

  async updateUser(u: UserRecord): Promise<void> {
    await this.db().query(
      `UPDATE users SET first_name = $2, last_name = $3, email = $4, status = $5, quota_bytes = $6, max_files = $7,
              password_hash = $8, must_change_password = $9, failed_login_count = $10,
              locked_until = CASE WHEN $11::bigint IS NULL THEN NULL ELSE to_timestamp($11::bigint / 1000.0) END,
              account_expires_at = CASE WHEN $12::bigint IS NULL THEN NULL ELSE to_timestamp($12::bigint / 1000.0) END
        WHERE id = $1`,
      [u.id, u.firstName, u.lastName, u.email, u.status, u.quotaBytes?.toString() ?? null, u.maxFiles, u.passwordHash,
        u.mustChangePassword, u.failedLoginCount, u.lockedUntil, u.accountExpiresAt],
    );
  }

  // ---- quota (user_usage counters; the conditional UPDATE is the atomic check)
  async getUsage(userId: string): Promise<Usage> {
    const r = await this.db().query('SELECT used_bytes, reserved_bytes, file_count, reserved_files FROM user_usage WHERE user_id = $1', [userId]);
    const row = r.rows[0];
    if (row === undefined) throw new Error('usage row missing');
    return { usedBytes: big(row.used_bytes), reservedBytes: big(row.reserved_bytes), fileCount: Number(row.file_count), reservedFiles: Number(row.reserved_files) };
  }

  async reserveQuota(userId: string, bytes: bigint, files: 0 | 1): Promise<{ ok: true } | { ok: false; reason: 'quota_bytes_exceeded' | 'quota_files_exceeded' }> {
    const r = await this.db().query(
      `UPDATE user_usage uu
          SET reserved_bytes = uu.reserved_bytes + $2::bigint, reserved_files = uu.reserved_files + $3::int, updated_at = now()
         FROM users u
        WHERE uu.user_id = u.id AND u.id = $1
          AND (u.quota_bytes IS NULL OR uu.used_bytes + uu.reserved_bytes + $2::bigint <= u.quota_bytes)
          AND (u.max_files IS NULL OR uu.file_count + uu.reserved_files + $3::int <= u.max_files)`,
      [userId, bytes.toString(), files],
    );
    if (r.rowCount === 1) return { ok: true };
    // Rejected: read the numbers only to say which limit was hit.
    const u = await this.getUser(userId);
    if (u === undefined) throw new Error('user not found');
    const verdict = evaluateReservation(await this.getUsage(userId), { quotaBytes: u.quotaBytes, maxFiles: u.maxFiles }, bytes, files);
    return verdict.ok ? { ok: false, reason: 'quota_bytes_exceeded' } : verdict; // verdict.ok here means we lost a race: still a rejection
  }

  async releaseReservation(userId: string, bytes: bigint, files: 0 | 1): Promise<void> {
    await this.db().query(
      'UPDATE user_usage SET reserved_bytes = reserved_bytes - $2::bigint, reserved_files = reserved_files - $3::int, updated_at = now() WHERE user_id = $1',
      [userId, bytes.toString(), files],
    );
  }

  async commitReservation(userId: string, bytes: bigint, files: 0 | 1): Promise<void> {
    await this.db().query(
      `UPDATE user_usage SET reserved_bytes = reserved_bytes - $2::bigint, used_bytes = used_bytes + $2::bigint,
              reserved_files = reserved_files - $3::int, file_count = file_count + $3::int, updated_at = now()
        WHERE user_id = $1`,
      [userId, bytes.toString(), files],
    );
  }

  // ---- uploads
  async countOpenUploads(userId: string): Promise<number> {
    const r = await this.db().query("SELECT count(*)::int AS n FROM upload_sessions WHERE user_id = $1 AND state IN ('created','uploading','finalizing')", [userId]);
    return Number(r.rows[0]?.n ?? 0);
  }

  async insertUpload(s: UploadSessionRecord): Promise<void> {
    await this.db().query(
      `INSERT INTO upload_sessions (id, tus_upload_id, user_id, folder_id, file_id, original_name, expected_size, offset_bytes, state,
                                    blob_key, finalize_key, version_id, reserved_file, expires_at)
       VALUES ($1, $1::text, $2, $3, $4, $5, $6::bigint, $7::bigint, $8, $9, $10, $11, $12, to_timestamp($13::bigint / 1000.0))`,
      [s.id, s.userId, s.folderId, s.fileId, s.originalName, s.expectedSize.toString(), s.offset.toString(), s.state, s.blobKey, s.finalizeKey,
        s.versionId, s.reservedFile, s.expiresAt],
    );
  }

  async getUpload(id: string): Promise<UploadSessionRecord | undefined> {
    const r = await this.db().query(`${UPLOAD_SELECT} WHERE id = $1`, [id]);
    return r.rows[0] === undefined ? undefined : toUpload(r.rows[0]);
  }

  async updateUpload(s: UploadSessionRecord): Promise<void> {
    await this.db().query(
      `UPDATE upload_sessions SET offset_bytes = $2::bigint, state = $3, finalize_key = $4, version_id = $5, updated_at = now() WHERE id = $1`,
      [s.id, s.offset.toString(), s.state, s.finalizeKey, s.versionId],
    );
  }

  async findUploadByVersion(versionId: string): Promise<UploadSessionRecord | undefined> {
    const r = await this.db().query(`${UPLOAD_SELECT} WHERE version_id = $1`, [versionId]);
    return r.rows[0] === undefined ? undefined : toUpload(r.rows[0]);
  }

  // ---- folders, permissions, shares
  async getFolder(id: string): Promise<FolderRecord | undefined> {
    const r = await this.db().query('SELECT id, owner_id FROM folders WHERE id = $1 AND deleted_at IS NULL', [id]);
    const row = r.rows[0];
    return row === undefined ? undefined : { id: str(row.id), ownerId: str(row.owner_id) };
  }

  // ADR-0003: ACL entries of the folder itself, plus inheritable entries of ancestors, stopping at the nearest
  // folder with inherit_acl = false (that folder's own entries still apply, anything above it does not).
  async folderPermissions(userId: string, folderId: string): Promise<ReadonlySet<ContentPermission>> {
    const r = await this.db().query(
      `WITH target AS (SELECT id, path_ids FROM folders WHERE id = $2 AND deleted_at IS NULL),
            chain AS (
              SELECT fo.id, fo.inherit_acl, strpos(t.path_ids, '/' || fo.id::text || '/') AS pos, (fo.id = t.id) AS is_target
                FROM folders fo JOIN target t ON strpos(t.path_ids, '/' || fo.id::text || '/') > 0
            ),
            boundary AS (SELECT COALESCE(MAX(pos) FILTER (WHERE NOT inherit_acl), 0) AS b FROM chain)
       SELECT DISTINCT a.permission
         FROM folder_acl a JOIN chain c ON c.id = a.folder_id CROSS JOIN boundary
        WHERE c.pos >= boundary.b AND (c.is_target OR a.inherit)
          AND ((a.principal_type = 'user' AND a.principal_id = $1)
            OR (a.principal_type = 'group' AND a.principal_id IN (SELECT group_id FROM group_members WHERE user_id = $1)))`,
      [userId, folderId],
    );
    return new Set(r.rows.map((x) => x.permission as ContentPermission));
  }

  // Active (not revoked, not expired) shares on the file or directly on its folder, to the user or one of their groups.
  async sharePermissions(userId: string, fileId: string): Promise<ReadonlySet<ContentPermission>> {
    const r = await this.db().query(
      `SELECT DISTINCT unnest(s.permissions) AS permission
         FROM shares s
        WHERE s.revoked_at IS NULL AND (s.expires_at IS NULL OR s.expires_at > now())
          AND ((s.resource_type = 'file' AND s.resource_id = $2)
            OR (s.resource_type = 'folder' AND s.resource_id = (SELECT folder_id FROM files WHERE id = $2)))
          AND ((s.principal_type = 'user' AND s.principal_id = $1)
            OR (s.principal_type = 'group' AND s.principal_id IN (SELECT group_id FROM group_members WHERE user_id = $1)))`,
      [userId, fileId],
    );
    return new Set(r.rows.map((x) => x.permission as ContentPermission));
  }

  // ---- files and versions
  async insertFile(f: FileRecord): Promise<void> {
    await this.db().query('INSERT INTO files (id, folder_id, owner_id, display_name, status, current_version_id) VALUES ($1,$2,$3,$4,$5,$6)', [
      f.id, f.folderId, f.ownerId, f.name, f.status, f.currentVersionId,
    ]);
  }

  async getFile(id: string): Promise<FileRecord | undefined> {
    const r = await this.db().query('SELECT id, folder_id, owner_id, display_name, status, current_version_id FROM files WHERE id = $1', [id]);
    return r.rows[0] === undefined ? undefined : toFile(r.rows[0]);
  }

  async updateFile(f: FileRecord): Promise<void> {
    await this.db().query('UPDATE files SET display_name = $2, status = $3, current_version_id = $4, updated_at = now() WHERE id = $1', [
      f.id, f.name, f.status, f.currentVersionId,
    ]);
  }

  async insertVersion(v: VersionRecord): Promise<void> {
    await this.db().query(
      `INSERT INTO file_versions (id, file_id, version_no, blob_key, size_bytes, sha256, scan_state, reject_reason, created_by)
       VALUES ($1,$2,$3,$4,$5::bigint,$6,$7,$8,$9)`,
      [v.id, v.fileId, v.versionNo, v.blobKey, v.sizeBytes.toString(), v.sha256, v.scanState, v.rejectReason, v.createdBy],
    );
  }

  async getVersion(id: string): Promise<VersionRecord | undefined> {
    const r = await this.db().query(
      'SELECT id, file_id, version_no, blob_key, size_bytes, sha256, scan_state, reject_reason, created_by FROM file_versions WHERE id = $1',
      [id],
    );
    return r.rows[0] === undefined ? undefined : toVersion(r.rows[0]);
  }

  async updateVersion(v: VersionRecord): Promise<void> {
    await this.db().query('UPDATE file_versions SET scan_state = $2, reject_reason = $3 WHERE id = $1', [v.id, v.scanState, v.rejectReason]);
  }

  async nextVersionNo(fileId: string): Promise<number> {
    const r = await this.db().query('SELECT COALESCE(MAX(version_no), 0) + 1 AS n FROM file_versions WHERE file_id = $1', [fileId]);
    return Number(r.rows[0]?.n ?? 1);
  }

  // ---- audit, alerts, queue
  async audit(e: AuditEvent): Promise<void> {
    await this.db().query(
      `INSERT INTO audit_events (occurred_at, actor_id, action, resource_type, resource_id, outcome, metadata)
       VALUES (to_timestamp($1::bigint / 1000.0), $2, $3, $4, $5, $6, $7::jsonb)`,
      [e.at, e.actorId, e.action, e.resourceType ?? null, e.resourceId ?? null, e.outcome, JSON.stringify(e.metadata ?? {})],
    );
  }

  async alert(a: AlertEvent): Promise<void> {
    await this.db().query('INSERT INTO alerts (kind, file_version_id, owner_id) VALUES ($1,$2,$3)', [a.kind, a.versionId, a.ownerId]);
  }

  async enqueueScan(job: ScanJob): Promise<void> {
    await this.db().query(
      "INSERT INTO outbox (topic, payload, available_at) VALUES ('scan', $1::jsonb, now() + make_interval(secs => $2::double precision / 1000))",
      [JSON.stringify({ versionId: job.versionId, attempt: job.attempt }), job.delayMs],
    );
  }
}
