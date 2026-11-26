import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decideScanOutcome, isTerminalUploadState, isUploadExpired, nextUploadState } from './state-machine.ts';

test('happy path', () => {
  assert.equal(nextUploadState('created', 'chunk'), 'uploading');
  assert.equal(nextUploadState('uploading', 'chunk'), 'uploading');
  assert.equal(nextUploadState('uploading', 'finalize_requested'), 'finalizing');
  assert.equal(nextUploadState('finalizing', 'finalize_done'), 'finalized');
});

test('repeated finalize requests are idempotent', () => {
  assert.equal(nextUploadState('finalizing', 'finalize_requested'), 'finalizing');
  assert.equal(nextUploadState('finalized', 'finalize_requested'), 'finalized');
});

test('illegal transitions are refused', () => {
  assert.equal(nextUploadState('created', 'finalize_requested'), null);
  assert.equal(nextUploadState('finalizing', 'cancel'), null);
  assert.equal(nextUploadState('finalizing', 'expire'), null);
  for (const s of ['finalized', 'failed', 'expired', 'cancelled'] as const) {
    assert.equal(nextUploadState(s, 'chunk'), null, s);
    assert.equal(isTerminalUploadState(s), true, s);
  }
  assert.equal(nextUploadState('expired', 'finalize_requested'), null);
});

test('only open sessions expire', () => {
  assert.equal(isUploadExpired(100, 100, 'uploading'), true);
  assert.equal(isUploadExpired(100, 99, 'uploading'), false);
  assert.equal(isUploadExpired(100, 500, 'finalizing'), false);
  assert.equal(isUploadExpired(100, 500, 'finalized'), false);
});

test('scan: only an explicit clean verdict releases the file', () => {
  assert.equal(decideScanOutcome({ kind: 'clean' }, 1).scanState, 'clean');
  const bad = decideScanOutcome({ kind: 'infected', signature: 'Eicar-Test-Signature' }, 1);
  assert.deepEqual([bad.scanState, bad.rejectReason, bad.alert, bad.retry], ['rejected', 'infected', true, false]);
  const lim = decideScanOutcome({ kind: 'limit' }, 1);
  assert.deepEqual([lim.scanState, lim.rejectReason, lim.alert], ['rejected', 'scan_limit', true]);
});

test('scan errors retry with backoff, then fail closed with an alert', () => {
  const first = decideScanOutcome({ kind: 'error' }, 1);
  assert.deepEqual([first.scanState, first.retry, first.retryDelayMs, first.alert], ['quarantined', true, 30_000, false]);
  assert.equal(decideScanOutcome({ kind: 'timeout' }, 2).retryDelayMs, 60_000);
  const last = decideScanOutcome({ kind: 'timeout' }, 3);
  assert.deepEqual([last.scanState, last.retry, last.alert], ['failed', false, true]);
  assert.equal(decideScanOutcome({ kind: 'error' }, 10, 20).retryDelayMs, 600_000); // capped
});
