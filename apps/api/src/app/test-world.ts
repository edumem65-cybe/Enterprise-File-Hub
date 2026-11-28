import { randomUUID } from 'node:crypto';
import type { Stage } from '../storage/paths.ts';
import { MemoryRepo } from './memory-repo.ts';
import type { Deps, StoragePort, UserRecord } from './ports.ts';

// Shared fixture: one super admin, two region managers, users under each, personal folders, tiny quotas.
export class FakeStorage implements StoragePort {
  calls: unknown[][] = [];
  async promote(from: Stage, to: Stage, key: string): Promise<void> {
    this.calls.push(['promote', from, to, key]);
  }
  async remove(stage: Stage, key: string): Promise<void> {
    this.calls.push(['remove', stage, key]);
  }
}

export const PE_HEADER_FOR_TESTS: Uint8Array = (() => {
  const h = new Uint8Array(256);
  h[0] = 0x4d;
  h[1] = 0x5a;
  h[0x3c] = 0x80;
  h[0x80] = 0x50;
  h[0x81] = 0x45;
  return h;
})();

function user(id: string, role: UserRecord['role'], managedBy: string | null, quotaBytes: bigint | null, maxFiles: number | null): UserRecord {
  return {
    id, role, managedBy, status: 'active', email: `${id}@example.com`, firstName: id, lastName: 'T', orgUnit: 'IT', quotaBytes, maxFiles,
    passwordHash: null, mustChangePassword: false, failedLoginCount: 0, lockedUntil: null, accountExpiresAt: null,
  };
}

export async function setup() {
  const repo = new MemoryRepo();
  const storage = new FakeStorage();
  const clock = { now: 1_700_000_000_000 };
  const deps: Deps = {
    repo,
    storage,
    quotaProfiles: new Map(),
    now: () => clock.now,
    newId: () => randomUUID(),
    config: {
      maxFileBytes: 5n * 1024n ** 3n,
      maxChunkBytes: 16n * 1024n * 1024n,
      maxConcurrentUploads: 3,
      uploadTtlMs: 24 * 3_600_000,
      blockedExtensions: new Set(['exe', 'bat', 'ps1', 'dll']),
      downloadSecret: 'unit-test-download-secret-with-32-plus-bytes',
    },
  };
  const ids = { admin: 'admin', regionA: 'rA', regionB: 'rB', userA1: 'uA1', userA2: 'uA2', userB1: 'uB1' };
  const limit = 1024n * 1024n; // 1 MiB, 2 files
  await repo.insertUser(user(ids.admin, 'super_admin', null, null, null));
  await repo.insertUser(user(ids.regionA, 'region_manager', ids.admin, limit, 100));
  await repo.insertUser(user(ids.regionB, 'region_manager', ids.admin, limit, 100));
  await repo.insertUser(user(ids.userA1, 'user', ids.regionA, limit, 2));
  await repo.insertUser(user(ids.userA2, 'user', ids.regionA, limit, 2));
  await repo.insertUser(user(ids.userB1, 'user', ids.regionB, limit, 2));
  for (const id of [ids.userA1, ids.userA2, ids.userB1]) repo.folders.set(`f-${id}`, { id: `f-${id}`, ownerId: id });
  return { deps, repo, storage, clock, ...ids };
}
