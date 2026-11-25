import { test } from 'node:test';
import assert from 'node:assert/strict';
import { attachmentHeader } from './content-disposition.ts';

test('ASCII name', () => {
  assert.equal(attachmentHeader('report.pdf'), `attachment; filename="report.pdf"; filename*=UTF-8''report.pdf`);
});

test('Persian name gets a safe fallback and a UTF-8 encoded name', () => {
  const h = attachmentHeader('گزارش.pdf');
  assert.ok(h.startsWith('attachment; filename="'));
  assert.ok(h.includes("filename*=UTF-8''%DA%AF"));
  assert.ok(h.endsWith('.pdf'));
});

test('header injection and quotes cannot escape the header', () => {
  const h = attachmentHeader('a"b\r\nSet-Cookie: x=1.txt');
  assert.equal(h.includes('\r'), false);
  assert.equal(h.includes('\n'), false);
  assert.equal(h.split('"').length, 3); // exactly one quoted fallback
  assert.ok(h.includes('%0D%0A'));
});

test('RFC 5987 reserved characters are percent-encoded', () => {
  assert.ok(attachmentHeader("it's (1)*.txt").includes('it%27s%20%281%29%2A.txt'));
});
