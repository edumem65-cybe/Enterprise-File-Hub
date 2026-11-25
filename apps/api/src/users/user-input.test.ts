import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isValidEmail, normalizeDigits, parseSizeToBytes, validateNewUser } from './user-input.ts';

const profiles = new Map([['small', { quotaBytes: 5n * 1024n ** 3n, maxFiles: 500 }]]);
const base = { first_name: 'علی', last_name: 'رضایی', org_unit: 'IT', email: ' Ali.Rezaei@Example.COM ', quota_gb: '10', max_files: '1000' };

test('valid user with explicit limits', () => {
  const r = validateNewUser(base, profiles);
  assert.ok(r.ok);
  assert.equal(r.value.email, 'ali.rezaei@example.com');
  assert.equal(r.value.role, 'user');
  assert.equal(r.value.quotaBytes, 10n * 1024n ** 3n);
  assert.equal(r.value.maxFiles, 1000);
});

test('valid user from a quota profile', () => {
  const r = validateNewUser({ ...base, quota_gb: '', max_files: '', quota_profile: 'small' }, profiles);
  assert.ok(r.ok);
  assert.equal(r.value.quotaBytes, 5n * 1024n ** 3n);
  assert.equal(r.value.maxFiles, 500);
});

test('limits are mandatory for non super admins', () => {
  const r = validateNewUser({ ...base, quota_gb: '', max_files: '' }, profiles);
  assert.ok(!r.ok);
  assert.deepEqual(r.errors.map((e) => e.field).sort(), ['max_files', 'quota_gb']);
});

test('super admin needs no limits and gets none', () => {
  const r = validateNewUser({ ...base, role: 'super_admin', quota_gb: '', max_files: '' }, profiles);
  assert.ok(r.ok);
  assert.equal(r.value.quotaBytes, null);
  assert.equal(r.value.maxFiles, null);
});

test('profile and explicit limits cannot be mixed; unknown profile is reported', () => {
  assert.ok(!validateNewUser({ ...base, quota_profile: 'small' }, profiles).ok);
  const r = validateNewUser({ ...base, quota_gb: '', max_files: '', quota_profile: 'huge' }, profiles);
  assert.ok(!r.ok);
  assert.deepEqual(r.errors, [{ field: 'quota_profile', code: 'unknown_profile' }]);
});

test('Persian digits are accepted in numeric fields', () => {
  const r = validateNewUser({ ...base, quota_gb: '۲٫۵', max_files: '۱۲۰۰', phone: '۰۹۱۲-۱۲۳-۴۵۶۷' }, profiles);
  assert.ok(r.ok);
  assert.equal(r.value.quotaBytes, (5n * 1024n ** 3n) / 2n);
  assert.equal(r.value.maxFiles, 1200);
  assert.equal(r.value.phone, '0912-123-4567');
});

test('required, invalid and too long fields are all reported at once', () => {
  const r = validateNewUser({ first_name: '', last_name: 'x'.repeat(101), email: 'not-an-email', role: 'boss', org_unit: 'IT', quota_gb: '0', max_files: '-1' }, profiles);
  assert.ok(!r.ok);
  const got = r.errors.map((e) => `${e.field}:${e.code}`).sort();
  assert.deepEqual(got, ['email:invalid', 'first_name:required', 'last_name:too_long', 'max_files:invalid', 'quota_gb:invalid', 'role:invalid']);
});

test('email validation', () => {
  for (const ok of ['a@b.co', 'first.last@sub.example.org']) assert.equal(isValidEmail(ok), true, ok);
  for (const bad of ['a@b', '@b.co', 'a@@b.co', 'a b@c.co', 'a@b..co', 'a@.co', 'a@b.']) assert.equal(isValidEmail(bad), false, bad);
});

test('size parsing', () => {
  assert.equal(parseSizeToBytes('1', 'gb'), 1024n ** 3n);
  assert.equal(parseSizeToBytes('0.5', 'gb'), 1024n ** 3n / 2n);
  assert.equal(parseSizeToBytes('512', 'mb'), 512n * 1024n ** 2n);
  for (const bad of ['', '0', '-1', '1.2345', '1e3', 'abc', '1.2.3', '.5']) assert.equal(parseSizeToBytes(bad, 'gb'), null, bad);
  assert.equal(normalizeDigits('۰۱۲۳۴۵۶۷۸۹٠١٢'), '0123456789012');
});
