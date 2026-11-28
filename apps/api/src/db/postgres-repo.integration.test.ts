import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { FakeStorage } from '../app/test-world.ts';
import type { Deps, UserRecord } from '../app/ports.ts';
import { cancelUpload, completeScan, finalizeUpload, issueDownload, receiveChunk, startUpload } from '../app/use-cases.ts';
import { MAX_FAILURES, loginLocal } from '../auth/login.ts';
import { hashPassword } from '../auth/password.ts';
import { PostgresRepo } from './postgres-repo.ts';
import type { SqlPool } from './postgres-repo.ts';

// Runs only when DATABASE_URL points at a PostgreSQL 16 server (and the `pg` package is installed).
// It creates a throw-away schema, applies migrations 0001-0004 and removes the schema afterwards.
const url = process.env.DATABASE_URL;
const skip = url === undefined ? 'set DATABASE_URL to run the PostgreSQL integration tests' : false;

const CT = 'application/offset+octet-stream';
const MIGRATIONS = ['0001_init.sql', '0002_user_hierarchy_quota.sql', '0003_scan_retention_auth.sql', '0004_app_columns_alerts.sql'];

test('PostgresRepo against a real PostgreSQL', { skip }, async (t) => {
  const pgModule = 'pg';
  const pg = (await import(pgModule)) as { Pool: new (cfg: object) => SqlPool & { end(): Promise<void> } };
  const schema = `file_upload_it_${randomUUID().replaceAll('-', '').slice(0, 12)}`;
  const admin = new pg.Pool({ connectionString: url, max: 1 });
  await admin.query(`CREATE SCHEMA ${schema}`);
  const pool = new pg.Pool({ connectionString: url, max: 10, options: `-c search_path=${schema},public` });

  try {
    const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../db/migrations');
    for (const file of MIGRATIONS) await pool.query(readFileSync(path.join(dir, file), 'utf8'));

    const repo = new PostgresRepo(pool);
    const deps: Deps = {
      repo,
      storage: new FakeStorage(),
      quotaProfiles: new Map(),
      now: () => Date.now(),
      newId: () => randomUUID(),
      config: {
        maxFileBytes: 5n * 1024n ** 3n,
        maxChunkBytes: 16n * 1024n * 1024n,
        maxConcurrentUploads: 3,
        uploadTtlMs: 24 * 3_600_000,
        blockedExtensions: new Set(['exe']),
        downloadSecret: 'integration-test-secret-with-32-plus-bytes',
      },
    };

    const orgId = randomUUID();
    await pool.query('INSERT INTO org_units (id, name, path_ids) VALUES ($1, $2, $3)', [orgId, 'IT', `/${orgId}/`]);
    const mk = (role: UserRecord['role'], managedBy: string | null, quota: bigint | null, files: number | null): UserRecord => {
      const id = randomUUID();
      return {
        id, role, managedBy, status: 'active', email: `${id}@example.com`, firstName: 'T', lastName: id.slice(0, 6), orgUnit: 'IT',
        quotaBytes: quota, maxFiles: files, passwordHash: null, mustChangePassword: false, failedLoginCount: 0, lockedUntil: null, accountExpiresAt: null,
      };
    };
    const MIB = 1024n * 1024n;
    const admin1 = mk('super_admin', null, null, null);
    const regionA = mk('region_manager', admin1.id, MIB, 100);
    const regionB = mk('region_manager', admin1.id, MIB, 100);
    const userA1 = mk('user', regionA.id, MIB, 2);
    const userA2 = mk('user', regionA.id, MIB, 2);
    const userB1 = mk('user', regionB.id, MIB, 2);
    const burst = mk('user', regionA.id, MIB, 100);
    for (const u of [admin1, regionA, regionB, userA1, userA2, userB1, burst]) await repo.insertUser(u);

    const folder = async (owner: UserRecord, parent: string | null = null, parentPath = '/'): Promise<{ id: string; path: string }> => {
      const id = randomUUID();
      const p = `${parentPath}${id}/`;
      await pool.query('INSERT INTO folders (id, parent_id, org_unit_id, owner_id, name, path_ids) VALUES ($1,$2,$3,$4,$5,$6)', [id, parent, orgId, owner.id, `f-${id}`, p]);
      return { id, path: p };
    };
    const fA1 = await folder(userA1);

    await t.test('quota reservation is atomic under concurrency', async () => {
      const results = await Promise.all(Array.from({ length: 10 }, () => repo.reserveQuota(burst.id, 400_000n, 1)));
      assert.equal(results.filter((r) => r.ok).length, 2); // 800 000 fits in 1 MiB, a third reservation does not
      assert.equal((await repo.getUsage(burst.id)).reservedBytes, 800_000n);
      await repo.releaseReservation(burst.id, 800_000n, 1);
      await repo.releaseReservation(burst.id, 0n, 1);
      assert.equal((await repo.getUsage(burst.id)).reservedBytes, 0n);
    });

    await t.test('upload, scan and download across regions', async () => {
      const started = await startUpload(deps, userA1.id, { folderId: fA1.id, fileName: 'report.pdf', uploadLength: '400000' });
      assert.ok(started.ok, started.ok ? '' : started.code);
      const sent = await receiveChunk(deps, userA1.id, started.value.sessionId, { contentType: CT, uploadOffset: '0', contentLength: '400000' });
      assert.ok(sent.ok);
      const fin = await finalizeUpload(deps, userA1.id, started.value.sessionId, { finalizeKey: randomUUID(), sha256: 'a'.repeat(64), header: new Uint8Array([1, 2, 3]) });
      assert.ok(fin.ok, fin.ok ? '' : fin.code);
      assert.equal((await issueDownload(deps, userA1.id, fin.value.versionId)).ok, false); // not clean yet
      const scanned = await completeScan(deps, fin.value.versionId, { kind: 'clean' }, 1);
      assert.ok(scanned.ok && scanned.value.outcome === 'clean');
      const use = await repo.getUsage(userA1.id);
      assert.deepEqual([use.usedBytes, use.reservedBytes, use.fileCount], [400_000n, 0n, 1]);

      assert.ok((await issueDownload(deps, userA1.id, fin.value.versionId)).ok);
      assert.ok((await issueDownload(deps, regionA.id, fin.value.versionId)).ok);
      for (const stranger of [regionB.id, userB1.id, userA2.id]) {
        const r = await issueDownload(deps, stranger, fin.value.versionId);
        assert.ok(!r.ok && r.code === 'not_found', stranger);
      }
      const audited = await pool.query("SELECT count(*)::int AS n FROM audit_events WHERE action = 'admin_content_access' AND actor_id = $1", [regionA.id]);
      assert.equal(audited.rows[0]?.n, 1);
    });

    await t.test('infected file is never downloadable and gives its quota back', async () => {
      const started = await startUpload(deps, userA1.id, { folderId: fA1.id, fileName: 'invoice.pdf', uploadLength: '5000' });
      assert.ok(started.ok);
      await receiveChunk(deps, userA1.id, started.value.sessionId, { contentType: CT, uploadOffset: '0', contentLength: '5000' });
      const fin = await finalizeUpload(deps, userA1.id, started.value.sessionId, { finalizeKey: randomUUID(), sha256: 'b'.repeat(64), header: new Uint8Array([1]) });
      assert.ok(fin.ok);
      const r = await completeScan(deps, fin.value.versionId, { kind: 'infected', signature: 'Eicar-Test-Signature' }, 1);
      assert.ok(r.ok && r.value.outcome === 'rejected');
      assert.ok(!(await issueDownload(deps, userA1.id, fin.value.versionId)).ok);
      assert.equal((await repo.getUsage(userA1.id)).reservedBytes, 0n);
      const alerts = await pool.query('SELECT kind FROM alerts WHERE file_version_id = $1', [fin.value.versionId]);
      assert.deepEqual(alerts.rows.map((x) => x.kind), ['scan_infected']);
    });

    await t.test('cancel releases the reservation; sessions are counted while open', async () => {
      const started = await startUpload(deps, userA1.id, { folderId: fA1.id, fileName: 'x.bin', uploadLength: '1000' });
      assert.ok(started.ok);
      assert.equal(await repo.countOpenUploads(userA1.id), 1);
      assert.ok((await cancelUpload(deps, userA1.id, started.value.sessionId)).ok);
      assert.equal(await repo.countOpenUploads(userA1.id), 0);
    });

    await t.test('folder ACL inheritance stops at a folder that breaks inheritance', async () => {
      const root = await folder(userA2);
      const a = await folder(userA2, root.id, root.path);
      const b = await folder(userA2, a.id, a.path);
      const grant = (folderId: string, perm: string, inherit = true) =>
        pool.query("INSERT INTO folder_acl (folder_id, principal_type, principal_id, permission, inherit) VALUES ($1,'user',$2,$3,$4)", [folderId, userB1.id, perm, inherit]);
      await grant(root.id, 'VIEW');
      assert.deepEqual([...(await repo.folderPermissions(userB1.id, b.id))], ['VIEW']);
      await pool.query('UPDATE folders SET inherit_acl = false WHERE id = $1', [a.id]);
      assert.deepEqual([...(await repo.folderPermissions(userB1.id, b.id))], []); // root's grant no longer reaches b
      await grant(a.id, 'DOWNLOAD');
      assert.deepEqual([...(await repo.folderPermissions(userB1.id, b.id))], ['DOWNLOAD']);
      await grant(b.id, 'UPLOAD', false); // non-inheritable entries still apply to the folder itself
      assert.deepEqual([...(await repo.folderPermissions(userB1.id, b.id))].sort(), ['DOWNLOAD', 'UPLOAD']);
      assert.deepEqual([...(await repo.folderPermissions(userA1.id, b.id))], []); // other users get nothing
    });

    await t.test('shares: active ones count, expired and revoked ones do not', async () => {
      const fileId = randomUUID();
      await repo.insertFile({ id: fileId, folderId: fA1.id, ownerId: userA1.id, name: `shared-${fileId}`, status: 'active', currentVersionId: null });
      const share = (extra: string) =>
        pool.query(`INSERT INTO shares (resource_type, resource_id, principal_type, principal_id, permissions, created_by ${extra ? ', ' + extra.split('=')[0] : ''})
                    VALUES ('file', $1, 'user', $2, ARRAY['DOWNLOAD'], $3 ${extra ? ', ' + extra.split('=')[1] : ''})`, [fileId, userB1.id, userA1.id]);
      await share("revoked_at=now()");
      await share("expires_at=now() - interval '1 hour'");
      assert.deepEqual([...(await repo.sharePermissions(userB1.id, fileId))], []);
      await share('');
      assert.deepEqual([...(await repo.sharePermissions(userB1.id, fileId))], ['DOWNLOAD']);
    });

    await t.test('a failed transaction rolls everything back', async () => {
      const fileId = randomUUID();
      await assert.rejects(
        repo.transaction(async () => {
          await repo.insertFile({ id: fileId, folderId: fA1.id, ownerId: userA1.id, name: `tx-${fileId}`, status: 'pending', currentVersionId: null });
          throw new Error('boom');
        }),
        /boom/,
      );
      assert.equal(await repo.getFile(fileId), undefined);
    });

    await t.test('local login: timestamps and lockout round-trip through timestamptz', async () => {
      const user = mk('user', regionA.id, MIB, 5);
      user.passwordHash = await hashPassword('the-right-password', { N: 2 ** 10, r: 8, p: 1 });
      await repo.insertUser(user);
      const now = Date.now();
      for (let i = 0; i < MAX_FAILURES; i++) await loginLocal(repo, user.email, 'wrong', now);
      const locked = await repo.getUser(user.id);
      assert.equal(locked?.failedLoginCount, MAX_FAILURES);
      assert.ok(typeof locked?.lockedUntil === 'number' && Math.abs(locked.lockedUntil - (now + 15 * 60_000)) < 2000);
      assert.equal((await loginLocal(repo, user.email, 'the-right-password', now + 1000)).ok, false);
      assert.equal((await loginLocal(repo, user.email, 'the-right-password', now + 16 * 60_000)).ok, true);
    });
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  }
});
