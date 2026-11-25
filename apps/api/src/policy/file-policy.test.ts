import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectExecutable, evaluateFilePolicy, extensionOf, sanitizeFileName } from './file-policy.ts';

const config = { blockedExtensions: new Set(['exe', 'bat', 'ps1', 'dll']), maxFileBytes: 5n * 1024n ** 3n };
const text = new TextEncoder().encode('hello world');

function peHeader(): Uint8Array {
  const h = new Uint8Array(256);
  h[0] = 0x4d;
  h[1] = 0x5a;
  h[0x3c] = 0x80; // e_lfanew = 0x80
  h[0x80] = 0x50;
  h[0x81] = 0x45;
  return h;
}

test('any ordinary file type is allowed (no allowlist)', () => {
  for (const name of ['report.pdf', 'photo.JPG', 'data.xyz', 'archive.tar.gz', 'README', 'گزارش ماهانه.docx']) {
    const r = evaluateFilePolicy({ name, sizeBytes: 10n, header: text }, config);
    assert.equal(r.allowed, true, name);
  }
});

test('blocked extensions are rejected, case-insensitively and with trailing dots', () => {
  for (const name of ['setup.exe', 'SETUP.EXE', 'run.bat', 'a.exe.', 'a.exe ', 'invoice.pdf.exe']) {
    const r = evaluateFilePolicy({ name, sizeBytes: 10n, header: text }, config);
    assert.deepEqual(r, { allowed: false, reason: 'blocked_extension' }, name);
  }
});

test('renaming an executable does not bypass the policy (magic bytes)', () => {
  const r = evaluateFilePolicy({ name: 'holiday.pdf', sizeBytes: 300n, header: peHeader() }, config);
  assert.deepEqual(r, { allowed: false, reason: 'detected_executable' });
  const elf = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
  assert.equal(detectExecutable(elf), 'elf');
});

test('plain text that starts with MZ is not flagged', () => {
  const memo = new TextEncoder().encode('MZ Corporation internal memo '.repeat(10));
  assert.equal(detectExecutable(memo), null);
});

test('Java class files are not treated as fat Mach-O', () => {
  assert.equal(detectExecutable(new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52])), null);
  assert.equal(detectExecutable(new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2])), 'macho');
});

test('size rules', () => {
  assert.deepEqual(evaluateFilePolicy({ name: 'a.txt', sizeBytes: 0n, header: text }, config), { allowed: false, reason: 'empty_file' });
  assert.deepEqual(evaluateFilePolicy({ name: 'a.iso', sizeBytes: config.maxFileBytes + 1n, header: text }, config), { allowed: false, reason: 'too_large' });
  assert.equal(evaluateFilePolicy({ name: 'a.iso', sizeBytes: config.maxFileBytes, header: text }, config).allowed, true);
});

test('unsafe names are rejected (path traversal, control chars, bidi override)', () => {
  const bad = ['../etc/passwd', 'a/b.txt', 'a' + String.fromCharCode(92) + 'b.txt', '..', '', 'x\u0000.txt', 'x\r\n.txt', 'photo\u202Egnp.exe', 'a'.repeat(300)];
  for (const name of bad) assert.equal(sanitizeFileName(name), null, JSON.stringify(name));
});

test('Persian names with ZWNJ are kept and normalised', () => {
  const name = 'می\u200Cخواهم.pdf';
  assert.equal(sanitizeFileName(name), name.normalize('NFC'));
  assert.equal(extensionOf('گزارش.PDF'), 'pdf');
  assert.equal(extensionOf('noext'), null);
  assert.equal(extensionOf('trailingdot.'), null);
});
