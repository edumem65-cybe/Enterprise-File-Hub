import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_DOWNLOAD_TOKEN_TTL_SECONDS, signDownloadToken, verifyDownloadToken } from './tokens.ts';

const secret = 'a-test-secret-that-is-at-least-32-bytes-long';
const claims = { versionId: 'v1', userId: 'u1', iat: 1000, exp: 1030 };

test('round trip', () => {
  const t = signDownloadToken(claims, secret);
  assert.deepEqual(verifyDownloadToken(t, secret, 1010, { versionId: 'v1', userId: 'u1' }), { ok: true, claims });
});

test('expired token', () => {
  assert.deepEqual(verifyDownloadToken(signDownloadToken(claims, secret), secret, 1030), { ok: false, reason: 'expired' });
});

test('wrong secret and tampered payload are rejected', () => {
  const t = signDownloadToken(claims, secret);
  assert.deepEqual(verifyDownloadToken(t, 'another-secret-that-is-at-least-32-bytes-xx', 1010), { ok: false, reason: 'bad_signature' });
  const [p, s] = t.split('.') as [string, string];
  const forged = Buffer.from(JSON.stringify({ ...claims, userId: 'attacker' })).toString('base64url');
  assert.notEqual(forged, p);
  assert.deepEqual(verifyDownloadToken(`${forged}.${s}`, secret, 1010), { ok: false, reason: 'bad_signature' });
});

test('token bound to version and user', () => {
  const t = signDownloadToken(claims, secret);
  assert.deepEqual(verifyDownloadToken(t, secret, 1010, { versionId: 'v2' }), { ok: false, reason: 'mismatch' });
  assert.deepEqual(verifyDownloadToken(t, secret, 1010, { userId: 'u2' }), { ok: false, reason: 'mismatch' });
});

test('malformed input', () => {
  for (const t of ['', 'abc', 'a.b.c', '.']) {
    const r = verifyDownloadToken(t, secret, 1);
    assert.equal(r.ok, false, t);
  }
});

test('lifetime is capped', () => {
  assert.throws(() => signDownloadToken({ ...claims, exp: claims.iat + MAX_DOWNLOAD_TOKEN_TTL_SECONDS + 1 }, secret), RangeError);
  assert.throws(() => signDownloadToken(claims, 'short'), RangeError);
});
