import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MemoryRepo } from '../app/memory-repo.ts';
import type { UserRecord } from '../app/ports.ts';
import { MAX_FAILURES, hashToken, isSessionActive, lockUntil, loginLocal, newSession } from './login.ts';
import { checkPasswordPolicy, hashPassword, needsRehash, verifyPassword } from './password.ts';

const FAST = { N: 2 ** 10, r: 8, p: 1 }; // keeps the tests quick; production uses DEFAULT_PARAMS

test('hash and verify, salted, unicode-normalised', async () => {
  const a = await hashPassword('درخت-سبز-و-بلند-۱۲۳', FAST);
  const b = await hashPassword('درخت-سبز-و-بلند-۱۲۳', FAST);
  assert.notEqual(a, b);
  assert.equal(await verifyPassword('درخت-سبز-و-بلند-۱۲۳', a), true);
  assert.equal(await verifyPassword('درخت-سبز-و-بلند-۱۲۴', a), false);
  assert.equal(await verifyPassword('x', 'not-a-hash'), false);
  assert.equal(await verifyPassword('x', 'scrypt$99999999$8$1$AAAA$AAAA'), false); // hostile parameters refused
});

test('stored parameters allow upgrading hashes later', async () => {
  const h = await hashPassword('a-long-enough-password', FAST);
  assert.equal(needsRehash(h, FAST), false);
  assert.equal(needsRehash(h, { N: 2 ** 15, r: 8, p: 1 }), true);
  assert.equal(needsRehash('garbage'), true);
});

test('password policy', () => {
  assert.deepEqual(checkPasswordPolicy('correct horse battery', 'ali@example.com'), []);
  assert.deepEqual(checkPasswordPolicy('short', 'ali@example.com'), ['too_short']);
  assert.ok(checkPasswordPolicy('password1234', 'x@example.com').includes('common'));
  assert.ok(checkPasswordPolicy('aaaaaaaaaaaaaa', 'x@example.com').includes('repeated'));
  assert.ok(checkPasswordPolicy('my-rezaei-secret-99', 'ali.rezaei@example.com').length === 0); // local part is 'ali.rezaei'
  assert.ok(checkPasswordPolicy('ali.rezaei-is-me-99', 'ali.rezaei@example.com').includes('contains_email_name'));
  assert.ok(checkPasswordPolicy('x'.repeat(129) + 'yz', 'a@b.co').includes('too_long'));
});

test('lockout grows after the threshold and is capped', () => {
  assert.equal(lockUntil(MAX_FAILURES - 1, 0), null);
  assert.equal(lockUntil(5, 0), 15 * 60_000);
  assert.equal(lockUntil(6, 0), 30 * 60_000);
  assert.equal(lockUntil(50, 0), 24 * 3_600_000);
});

async function seed(): Promise<{ repo: MemoryRepo; user: UserRecord }> {
  const repo = new MemoryRepo();
  const user: UserRecord = {
    id: 'u1', role: 'user', managedBy: null, status: 'active', email: 'ali@example.com', firstName: 'Ali', lastName: 'R', orgUnit: 'IT',
    quotaBytes: 1000n, maxFiles: 5, passwordHash: await hashPassword('the-right-password', FAST), mustChangePassword: false,
    failedLoginCount: 0, lockedUntil: null, accountExpiresAt: null,
  };
  repo.insertUser(user);
  return { repo, user };
}

test('login: success resets the counters; every failure looks the same', async () => {
  const { repo } = await seed();
  const t = 1_000_000;
  assert.deepEqual(await loginLocal(repo, 'ALI@example.com ', 'the-right-password', t), { ok: true, userId: 'u1', mustChangePassword: false });
  assert.deepEqual(await loginLocal(repo, 'ali@example.com', 'wrong', t), { ok: false, code: 'invalid_credentials' });
  assert.deepEqual(await loginLocal(repo, 'nobody@example.com', 'wrong', t), { ok: false, code: 'invalid_credentials' });
  assert.equal(repo.getUser('u1')?.failedLoginCount, 1);
  await loginLocal(repo, 'ali@example.com', 'the-right-password', t);
  assert.equal(repo.getUser('u1')?.failedLoginCount, 0);
});

test('login: five failures lock the account even for the right password, then it recovers', async () => {
  const { repo } = await seed();
  const t = 5_000_000;
  for (let i = 0; i < MAX_FAILURES; i++) await loginLocal(repo, 'ali@example.com', 'wrong', t);
  assert.equal(repo.getUser('u1')?.lockedUntil, t + 15 * 60_000);
  assert.equal((await loginLocal(repo, 'ali@example.com', 'the-right-password', t + 1000)).ok, false);
  assert.equal((await loginLocal(repo, 'ali@example.com', 'the-right-password', t + 15 * 60_000 + 1)).ok, true);
});

test('login: disabled and expired accounts are refused', async () => {
  const { repo, user } = await seed();
  repo.updateUser({ ...user, status: 'disabled' });
  assert.equal((await loginLocal(repo, 'ali@example.com', 'the-right-password', 1)).ok, false);
  repo.updateUser({ ...user, accountExpiresAt: 100 });
  assert.equal((await loginLocal(repo, 'ali@example.com', 'the-right-password', 101)).ok, false);
  assert.equal((await loginLocal(repo, 'ali@example.com', 'the-right-password', 99)).ok, true);
});

test('login attempts are audited without secrets', async () => {
  const { repo } = await seed();
  await loginLocal(repo, 'ali@example.com', 'wrong', 1);
  const last = repo.auditLog.at(-1);
  assert.equal(last?.action, 'login');
  assert.equal(last?.outcome, 'denied');
  assert.equal(JSON.stringify(last).includes('wrong'), false);
});

test('sessions: only the hash is stored; idle, absolute expiry and revocation', () => {
  const s = newSession(1000, 3_600_000);
  assert.equal(hashToken(s.token), s.tokenHash);
  assert.notEqual(s.token, s.tokenHash);
  assert.equal(s.expiresAt, 3_601_000);
  const live = { expiresAt: 10_000, lastSeenAt: 5000, revokedAt: null };
  assert.equal(isSessionActive(live, 6000, 2000), true);
  assert.equal(isSessionActive(live, 8000, 2000), false); // idle too long
  assert.equal(isSessionActive(live, 10_000, 99_999), false); // absolute expiry
  assert.equal(isSessionActive({ ...live, revokedAt: 5500 }, 6000, 2000), false);
});
