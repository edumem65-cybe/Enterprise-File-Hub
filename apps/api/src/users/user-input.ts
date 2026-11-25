import type { Role } from '../policy/types.ts';

export interface QuotaProfile {
  quotaBytes: bigint;
  maxFiles: number;
}

export interface NewUserValue {
  firstName: string;
  lastName: string;
  orgUnit: string; // org unit name or id, resolved by the caller
  email: string;
  role: Role;
  quotaBytes: bigint | null; // null only for super_admin
  maxFiles: number | null;
  phone: string | null;
  employeeCode: string | null;
  jobTitle: string | null;
}

export interface FieldError {
  field: string;
  code: 'required' | 'invalid' | 'too_long' | 'unknown_profile' | 'conflict';
}

export type ValidationResult = { ok: true; value: NewUserValue } | { ok: false; errors: FieldError[] };

const ROLES: ReadonlySet<string> = new Set(['super_admin', 'region_manager', 'user']);
export const MAX_FILES_LIMIT = 10_000_000;
const GIB = 1024n ** 3n;
const MIB = 1024n ** 2n;

// Persian (U+06F0..) and Arabic-Indic (U+0660..) digits are common in typed input.
export function normalizeDigits(s: string): string {
  let out = '';
  for (const ch of s) {
    const c = ch.codePointAt(0) as number;
    if (c >= 0x06f0 && c <= 0x06f9) out += String(c - 0x06f0);
    else if (c >= 0x0660 && c <= 0x0669) out += String(c - 0x0660);
    else if (c === 0x066b || c === 0x060c) out += c === 0x066b ? '.' : ',';
    else out += ch;
  }
  return out;
}

function hasControlChars(s: string): boolean {
  for (const ch of s) {
    const c = ch.codePointAt(0) as number;
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

function cleanText(raw: string | undefined, max: number): { value: string; error: 'too_long' | 'invalid' | null } {
  const value = (raw ?? '').normalize('NFC').trim();
  if (value.length > max) return { value, error: 'too_long' };
  if (hasControlChars(value)) return { value, error: 'invalid' };
  return { value, error: null };
}

export function isValidEmail(email: string): boolean {
  if (email.length > 254 || email.includes(' ')) return false;
  const parts = email.split('@');
  if (parts.length !== 2) return false;
  const [local, domain] = parts as [string, string];
  if (local === '' || local.length > 64 || domain.length < 3) return false;
  if (!domain.includes('.') || domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) return false;
  return true;
}

// '2' -> 2 GiB, '2.5' -> 2.5 GiB (up to 3 decimals). Returns null when invalid or not positive.
export function parseSizeToBytes(raw: string, unit: 'gb' | 'mb'): bigint | null {
  const s = normalizeDigits(raw.trim());
  const m = s.split('.');
  if (m.length > 2) return null;
  const [whole, frac = ''] = m as [string, string?];
  if (whole === '' || !isDigits(whole) || (frac !== '' && !isDigits(frac)) || frac.length > 3) return null;
  const unitBytes = unit === 'gb' ? GIB : MIB;
  const fracPadded = frac.padEnd(3, '0');
  const bytes = BigInt(whole) * unitBytes + (BigInt(fracPadded) * unitBytes) / 1000n;
  return bytes > 0n ? bytes : null;
}

function isDigits(s: string): boolean {
  if (s === '') return false;
  for (const ch of s) {
    if (ch < '0' || ch > '9') return false;
  }
  return true;
}

// Accepted keys: first_name, last_name, org_unit, email, role, quota_profile, quota_gb, quota_mb, max_files,
// phone, employee_code, job_title.
export function validateNewUser(raw: Record<string, string | undefined>, profiles: ReadonlyMap<string, QuotaProfile>): ValidationResult {
  const errors: FieldError[] = [];
  const text = (key: string, max: number, required: boolean): string => {
    const r = cleanText(raw[key], max);
    if (r.error !== null) errors.push({ field: key, code: r.error });
    else if (required && r.value === '') errors.push({ field: key, code: 'required' });
    return r.value;
  };

  const firstName = text('first_name', 100, true);
  const lastName = text('last_name', 100, true);
  const orgUnit = text('org_unit', 200, true);
  const jobTitle = text('job_title', 150, false);
  const employeeCode = text('employee_code', 50, false);

  const email = (raw.email ?? '').trim().toLowerCase();
  if (email === '') errors.push({ field: 'email', code: 'required' });
  else if (!isValidEmail(email)) errors.push({ field: 'email', code: 'invalid' });

  const roleRaw = (raw.role ?? '').trim().toLowerCase() || 'user';
  if (!ROLES.has(roleRaw)) errors.push({ field: 'role', code: 'invalid' });
  const role = (ROLES.has(roleRaw) ? roleRaw : 'user') as Role;

  const phoneRaw = normalizeDigits((raw.phone ?? '').trim());
  let phone: string | null = null;
  if (phoneRaw !== '') {
    let okPhone = phoneRaw.length <= 20;
    for (const ch of phoneRaw) if (!(isDigits(ch) || ch === '+' || ch === '-' || ch === ' ')) okPhone = false;
    if (okPhone) phone = phoneRaw;
    else errors.push({ field: 'phone', code: 'invalid' });
  }

  let quotaBytes: bigint | null = null;
  let maxFiles: number | null = null;
  if (role !== 'super_admin') {
    const profileName = (raw.quota_profile ?? '').trim();
    const hasExplicit = (raw.quota_gb ?? '').trim() !== '' || (raw.quota_mb ?? '').trim() !== '' || (raw.max_files ?? '').trim() !== '';
    if (profileName !== '' && hasExplicit) {
      errors.push({ field: 'quota_profile', code: 'conflict' });
    } else if (profileName !== '') {
      const p = profiles.get(profileName);
      if (p === undefined) errors.push({ field: 'quota_profile', code: 'unknown_profile' });
      else {
        quotaBytes = p.quotaBytes;
        maxFiles = p.maxFiles;
      }
    } else {
      const gb = (raw.quota_gb ?? '').trim();
      const mb = (raw.quota_mb ?? '').trim();
      if (gb !== '' && mb !== '') errors.push({ field: 'quota_mb', code: 'conflict' });
      else if (gb === '' && mb === '') errors.push({ field: 'quota_gb', code: 'required' });
      else {
        quotaBytes = gb !== '' ? parseSizeToBytes(gb, 'gb') : parseSizeToBytes(mb, 'mb');
        if (quotaBytes === null) errors.push({ field: gb !== '' ? 'quota_gb' : 'quota_mb', code: 'invalid' });
      }
      const mf = normalizeDigits((raw.max_files ?? '').trim());
      if (mf === '') errors.push({ field: 'max_files', code: 'required' });
      else if (!isDigits(mf) || Number(mf) < 1 || Number(mf) > MAX_FILES_LIMIT) errors.push({ field: 'max_files', code: 'invalid' });
      else maxFiles = Number(mf);
    }
  }

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    value: { firstName, lastName, orgUnit, email, role, quotaBytes, maxFiles, phone, employeeCode: employeeCode || null, jobTitle: jobTitle || null },
  };
}
