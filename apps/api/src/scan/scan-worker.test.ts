import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setup } from '../app/test-world.ts';
import { finalizeUpload, receiveChunk, startUpload } from '../app/use-cases.ts';
import type { ScanResult } from '../upload/state-machine.ts';
import type { Scanner } from './clamd.ts';
import { processScanJob } from './scan-worker.ts';

const CT = 'application/offset+octet-stream';
const BODY = Buffer.from('some file content for the scan worker');
const SHA = createHash('sha256').update(BODY).digest('hex');

class StubScanner implements Scanner {
  calls: string[] = [];
  result: ScanResult = { kind: 'clean' };
  async scan(p: string): Promise<ScanResult> {
    this.calls.push(p);
    return this.result;
  }
}

// Builds a finalized upload whose bytes really exist on disk, so the worker can hash them.
async function world(sha = SHA, body: Buffer | null = BODY) {
  const w = await setup();
  const dir = mkdtempSync(path.join(tmpdir(), 'file-upload-'));
  const started = await startUpload(w.deps, w.userA1, { folderId: `f-${w.userA1}`, fileName: 'a.txt', uploadLength: String(BODY.length) });
  assert.ok(started.ok);
  await receiveChunk(w.deps, w.userA1, started.value.sessionId, { contentType: CT, uploadOffset: '0', contentLength: String(BODY.length) });
  const fin = await finalizeUpload(w.deps, w.userA1, started.value.sessionId, { finalizeKey: randomUUID(), sha256: sha, header: new Uint8Array([1]) });
  assert.ok(fin.ok);
  const key = w.repo.peekUpload(started.value.sessionId)!.blobKey;
  if (body !== null) writeFileSync(path.join(dir, key), body);
  const scanner = new StubScanner();
  const worker = { deps: w.deps, scanner, quarantinePath: (k: string) => path.join(dir, k) };
  return { w, scanner, worker, versionId: fin.value.versionId, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('intact clean file: scanned once, version released', async () => {
  const x = await world();
  try {
    const r = await processScanJob(x.worker, { versionId: x.versionId, attempt: 1, delayMs: 0 });
    assert.deepEqual(r, { ok: true, value: { outcome: 'clean' } });
    assert.equal(x.scanner.calls.length, 1);
    assert.equal(x.w.repo.peekVersion(x.versionId)?.scanState, 'clean');
  } finally {
    x.cleanup();
  }
});

test('antivirus verdict is applied', async () => {
  const x = await world();
  try {
    x.scanner.result = { kind: 'infected', signature: 'Eicar-Test-Signature' };
    const r = await processScanJob(x.worker, { versionId: x.versionId, attempt: 1, delayMs: 0 });
    assert.deepEqual(r, { ok: true, value: { outcome: 'rejected' } });
    assert.equal(x.w.repo.peekVersion(x.versionId)?.rejectReason, 'infected');
  } finally {
    x.cleanup();
  }
});

test('bytes that differ from the uploaded hash are rejected without asking the scanner', async () => {
  const x = await world('0'.repeat(64));
  try {
    const r = await processScanJob(x.worker, { versionId: x.versionId, attempt: 1, delayMs: 0 });
    assert.deepEqual(r, { ok: true, value: { outcome: 'rejected' } });
    assert.equal(x.scanner.calls.length, 0);
    assert.equal(x.w.repo.peekVersion(x.versionId)?.rejectReason, 'integrity_mismatch');
    assert.equal(x.w.repo.alerts.length, 1);
  } finally {
    x.cleanup();
  }
});

test('a missing file is retried and then fails closed', async () => {
  const x = await world(SHA, null);
  try {
    const first = await processScanJob(x.worker, { versionId: x.versionId, attempt: 1, delayMs: 0 });
    assert.deepEqual(first, { ok: true, value: { outcome: 'retry' } });
    const last = await processScanJob(x.worker, { versionId: x.versionId, attempt: 3, delayMs: 0 });
    assert.deepEqual(last, { ok: true, value: { outcome: 'failed' } });
    assert.equal(x.scanner.calls.length, 0);
  } finally {
    x.cleanup();
  }
});

test('duplicate delivery of a decided job does nothing; unknown versions are reported', async () => {
  const x = await world();
  try {
    await processScanJob(x.worker, { versionId: x.versionId, attempt: 1, delayMs: 0 });
    const again = await processScanJob(x.worker, { versionId: x.versionId, attempt: 2, delayMs: 0 });
    assert.deepEqual(again, { ok: true, value: { outcome: 'ignored' } });
    assert.equal(x.scanner.calls.length, 1);
    assert.deepEqual(await processScanJob(x.worker, { versionId: randomUUID(), attempt: 1, delayMs: 0 }), { ok: false, code: 'not_found' });
  } finally {
    x.cleanup();
  }
});
