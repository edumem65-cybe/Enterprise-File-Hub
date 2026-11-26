import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

// ADR-0008: Node 22 has no built-in argon2id, so v1 uses scrypt (an OWASP-accepted option) behind this module.
// The stored format carries its parameters, so hashes can be upgraded on login (needsRehash) or replaced by argon2id later.
export interface ScryptParams {
  N: number;
  r: number;
  p: number;
}

export const DEFAULT_PARAMS: ScryptParams = { N: 2 ** 15, r: 8, p: 1 }; // ~32 MiB per hash
const KEY_LEN = 32;

function derive(password: string, salt: Buffer, params: ScryptParams): Promise<Buffer> {
  const maxmem = 256 * params.N * params.r; // headroom above the 128*N*r minimum
  return new Promise((resolve, reject) => {
    scrypt(password.normalize('NFKC'), salt, KEY_LEN, { N: params.N, r: params.r, p: params.p, maxmem }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

export async function hashPassword(password: string, params: ScryptParams = DEFAULT_PARAMS): Promise<string> {
  const salt = randomBytes(16);
  const key = await derive(password, salt, params);
  return `scrypt$${params.N}$${params.r}$${params.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

function parse(stored: string): { params: ScryptParams; salt: Buffer; key: Buffer } | null {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return null;
  const [, n, r, p, salt, key] = parts as [string, string, string, string, string, string];
  const params = { N: Number(n), r: Number(r), p: Number(p) };
  if (![params.N, params.r, params.p].every((x) => Number.isInteger(x) && x > 0)) return null;
  if (params.N > 2 ** 20 || params.r > 32 || params.p > 16) return null; // refuse hostile parameters
  return { params, salt: Buffer.from(salt, 'base64'), key: Buffer.from(key, 'base64') };
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parsed = parse(stored);
  if (parsed === null || parsed.key.length !== KEY_LEN) return false;
  const key = await derive(password, parsed.salt, parsed.params);
  return timingSafeEqual(key, parsed.key);
}

export function needsRehash(stored: string, target: ScryptParams = DEFAULT_PARAMS): boolean {
  const parsed = parse(stored);
  return parsed === null || parsed.params.N < target.N || parsed.params.r < target.r || parsed.params.p < target.p;
}

const COMMON = new Set(['password1234', 'passw0rd1234', '123456789012', 'qwertyuiop12', 'iloveyou1234', 'administrator', 'welcome12345']);

export type PasswordIssue = 'too_short' | 'too_long' | 'common' | 'repeated' | 'contains_email_name';

export function checkPasswordPolicy(password: string, email: string): PasswordIssue[] {
  const issues: PasswordIssue[] = [];
  const pw = password.normalize('NFKC');
  if (pw.length < 12) issues.push('too_short');
  if (pw.length > 128) issues.push('too_long');
  const lower = pw.toLowerCase();
  if (COMMON.has(lower)) issues.push('common');
  if (new Set(pw).size <= 3) issues.push('repeated');
  const local = (email.split('@')[0] ?? '').toLowerCase();
  if (local.length >= 4 && lower.includes(local)) issues.push('contains_email_name');
  return issues;
}
