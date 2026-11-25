import { createHmac, timingSafeEqual } from 'node:crypto';

// ADR-0007: short-lived download token issued by api and verified by file-service.
export const MAX_DOWNLOAD_TOKEN_TTL_SECONDS = 60;

export interface DownloadClaims {
  versionId: string;
  userId: string;
  iat: number; // unix seconds
  exp: number; // unix seconds
}

export type VerifyResult =
  | { ok: true; claims: DownloadClaims }
  | { ok: false; reason: 'malformed' | 'bad_signature' | 'expired' | 'ttl_too_long' | 'mismatch' };

function mac(payload: string, secret: Buffer): Buffer {
  return createHmac('sha256', secret).update(payload).digest();
}

function toKey(secret: string | Buffer): Buffer {
  const key = typeof secret === 'string' ? Buffer.from(secret, 'utf8') : secret;
  if (key.length < 32) throw new RangeError('secret must be at least 32 bytes');
  return key;
}

export function signDownloadToken(claims: DownloadClaims, secret: string | Buffer): string {
  if (claims.exp <= claims.iat || claims.exp - claims.iat > MAX_DOWNLOAD_TOKEN_TTL_SECONDS) {
    throw new RangeError('invalid token lifetime');
  }
  const payload = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  return `${payload}.${mac(payload, toKey(secret)).toString('base64url')}`;
}

function isClaims(v: unknown): v is DownloadClaims {
  if (typeof v !== 'object' || v === null) return false;
  const c = v as Record<string, unknown>;
  return typeof c.versionId === 'string' && typeof c.userId === 'string' && Number.isInteger(c.iat) && Number.isInteger(c.exp);
}

export function verifyDownloadToken(
  token: string,
  secret: string | Buffer,
  nowSeconds: number,
  expected?: { versionId?: string; userId?: string },
): VerifyResult {
  const parts = token.split('.');
  if (parts.length !== 2) return { ok: false, reason: 'malformed' };
  const [payload, sig] = parts as [string, string];
  const given = Buffer.from(sig, 'base64url');
  const wanted = mac(payload, toKey(secret));
  if (given.length !== wanted.length || !timingSafeEqual(given, wanted)) return { ok: false, reason: 'bad_signature' };
  let claims: unknown;
  try {
    claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (!isClaims(claims)) return { ok: false, reason: 'malformed' };
  if (claims.exp - claims.iat > MAX_DOWNLOAD_TOKEN_TTL_SECONDS) return { ok: false, reason: 'ttl_too_long' };
  if (nowSeconds >= claims.exp) return { ok: false, reason: 'expired' };
  if (expected?.versionId !== undefined && expected.versionId !== claims.versionId) return { ok: false, reason: 'mismatch' };
  if (expected?.userId !== undefined && expected.userId !== claims.userId) return { ok: false, reason: 'mismatch' };
  return { ok: true, claims };
}
