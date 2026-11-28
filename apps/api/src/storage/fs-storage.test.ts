import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { FsStorage } from './fs-storage.ts';
import { readHeader, sha256File } from './hash.ts';
import { ensureStageDirs, newBlobKey } from './paths.ts';

function withRoot<T>(fn: (root: string, storage: FsStorage) => Promise<T>): Promise<T> {
  const root = mkdtempSync(path.join(tmpdir(), 'file-upload-'));
  ensureStageDirs(root);
  return fn(root, new FsStorage(root)).finally(() => rmSync(root, { recursive: true, force: true }));
}

test('promote is idempotent after a crash between rename and the database update', () =>
  withRoot(async (_root, storage) => {
    const key = newBlobKey();
    writeFileSync(storage.pathFor('incoming', key), 'data');
    await storage.promote('incoming', 'quarantine', key);
    await storage.promote('incoming', 'quarantine', key); // second call finds the file already moved
    assert.equal(readFileSync(storage.pathFor('quarantine', key), 'utf8'), 'data');
    assert.equal(existsSync(storage.pathFor('incoming', key)), false);
  }));

test('promote still fails when the file is nowhere', () =>
  withRoot(async (_root, storage) => {
    await assert.rejects(storage.promote('incoming', 'quarantine', newBlobKey()));
  }));

test('remove ignores missing files and removes existing ones', () =>
  withRoot(async (_root, storage) => {
    const key = newBlobKey();
    await storage.remove('incoming', key);
    writeFileSync(storage.pathFor('incoming', key), 'x');
    await storage.remove('incoming', key);
    assert.equal(existsSync(storage.pathFor('incoming', key)), false);
  }));

test('sha256 and header of a file', () =>
  withRoot(async (root) => {
    const file = path.join(root, 'sample.bin');
    writeFileSync(file, 'hello world');
    const r = await sha256File(file);
    assert.equal(r.sha256, 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
    assert.equal(r.size, 11n);
    assert.equal(new TextDecoder().decode(await readHeader(file, 5)), 'hello');
    assert.equal((await readHeader(file)).length, 11); // shorter files give a shorter header
  }));
