import { createHash, randomBytes } from 'node:crypto';
import type { Repo } from '../app/ports.ts';
import { hashPassword, verifyPassword } from './password.ts';

export const MAX_FAILURES = 5;
export const BASE_LOCK_MS = 15 * 60_000;
export const MAX_LOCK_MS = 24 * 3_600_000;

// Progressive lockout: from the 5th failure on, 15 min, 30 min, 1 h ... capped at 24 h.
export function lockUntil(failedCount: number, now: number): number | null {
  if (failedCount < MAX_FAILURES) return null;
  return now + Math.min(BASE_LOCK_MS * 2 ** (failedCount - MAX_FAILURES), MAX_LOCK_MS);
}

let dummyHash: Promise<string> | null = null;

export type LoginResult = { ok: true; userId: string; mustChangePassword: boolean } | { ok: false; code: 'invalid_credentials' };

// One generic error for every failure (unknown user, wrong password, locked, disabled, expired) so the response
// does not reveal which accounts exist. Unknown users still pay for a hash to keep timing similar.
export async function loginLocal(repo: Repo, email: string, password: string, now: number): Promise<LoginResult> {
  const user = repo.findUserByEmail(email.trim().toLowerCase());
  if (user === undefined || user.passwordHash === null) {
    dummyHash ??= hashPassword('timing-equalisation-only');
    await verifyPassword(password, await dummyHash);
    repo.audit({ at: now, actorId: null, action: 'login', outcome: 'denied', metadata: { reason: 'unknown_user' } });
    return { ok: false, code: 'invalid_credentials' };
  }
  const blocked =
    user.status !== 'active' || (user.accountExpiresAt !== null && now >= user.accountExpiresAt) || (user.lockedUntil !== null && now < user.lockedUntil);
  const valid = await verifyPassword(password, user.passwordHash);
  if (blocked || !valid) {
    if (!valid && !blocked) {
      const failed = user.failedLoginCount + 1;
      repo.updateUser({ ...user, failedLoginCount: failed, lockedUntil: lockUntil(failed, now) });
    }
    repo.audit({ at: now, actorId: user.id, action: 'login', outcome: 'denied', metadata: { reason: blocked ? 'blocked' : 'bad_password' } });
    return { ok: false, code: 'invalid_credentials' };
  }
  repo.updateUser({ ...user, failedLoginCount: 0, lockedUntil: null });
  repo.audit({ at: now, actorId: user.id, action: 'login', outcome: 'success' });
  return { ok: true, userId: user.id, mustChangePassword: user.mustChangePassword };
}

export interface NewSession {
  token: string; // sent once in the cookie, never stored
  tokenHash: string; // what the database keeps
  csrfSecret: string;
  expiresAt: number;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function newSession(now: number, ttlMs: number): NewSession {
  const token = randomBytes(32).toString('base64url');
  return { token, tokenHash: hashToken(token), csrfSecret: randomBytes(24).toString('base64url'), expiresAt: now + ttlMs };
}

export function isSessionActive(s: { expiresAt: number; lastSeenAt: number; revokedAt: number | null }, now: number, idleMs: number): boolean {
  return s.revokedAt === null && now < s.expiresAt && now - s.lastSeenAt < idleMs;
}
