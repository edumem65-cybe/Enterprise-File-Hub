import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertInside, assertSameFilesystem, ensureStageDirs, isBlobKey, newBlobKey, promote, stagePath } from './paths.ts';

test('blob keys are random 32-char hex and validated', () => {
  const a = newBlobKey();
  assert.ok(isBlobKey(a));
  assert.notEqual(a, newBlobKey());
  for (const bad of ['', 'abc', '../../etc/passwd', 'G'.repeat(32), 'a'.repeat(31), 'A'.repeat(32)]) assert.equal(isBlobKey(bad), false, bad);
});

test('stage paths are sharded for blobs and always inside the root', () => {
  const root = path.join(tmpdir(), 'filehub-root');
  const key = 'ab' + 'cd' + '0'.repeat(28);
  assert.equal(stagePath(root, 'blobs', key), path.join(root, 'blobs', 'ab', 'cd', key));
  assert.equal(stagePath(root, 'incoming', key), path.join(root, 'incoming', key));
  assert.throws(() => stagePath(root, 'blobs', '../escape'), RangeError);
  assert.throws(() => assertInside(root, path.join(root, '..', 'other')), RangeError);
  assert.throws(() => assertInside(root, root + '-sibling'), RangeError);
});

test('promote moves a file through all stages atomically and never overwrites', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'filehub-'));
  try {
    ensureStageDirs(root);
    assertSameFilesystem(root);
    const key = newBlobKey();
    writeFileSync(stagePath(root, 'incoming', key), 'payload');
    promote(root, 'incoming', 'quarantine', key);
    assert.equal(existsSync(stagePath(root, 'incoming', key)), false);
    const final = promote(root, 'quarantine', 'blobs', key);
    assert.equal(readFileSync(final, 'utf8'), 'payload');
    // A second file with the same key in quarantine must not replace the clean blob.
    writeFileSync(stagePath(root, 'quarantine', key), 'other');
    assert.throws(() => promote(root, 'quarantine', 'blobs', key), /already exists/);
    assert.equal(readFileSync(final, 'utf8'), 'payload');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('missing stage directory is reported', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'filehub-'));
  try {
    assert.throws(() => assertSameFilesystem(root), /missing storage directory/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
