import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateReservation } from './quota.ts';

const usage = { usedBytes: 800n, reservedBytes: 100n, fileCount: 8, reservedFiles: 1 };

test('fits exactly at the limit', () => {
  assert.deepEqual(evaluateReservation(usage, { quotaBytes: 1000n, maxFiles: 10 }, 100n, 1), { ok: true });
});

test('reserved bytes count against the quota (concurrent uploads cannot overshoot)', () => {
  assert.deepEqual(evaluateReservation(usage, { quotaBytes: 1000n, maxFiles: 10 }, 101n, 1), { ok: false, reason: 'quota_bytes_exceeded' });
});

test('file count limit is separate from the bytes limit', () => {
  assert.deepEqual(evaluateReservation(usage, { quotaBytes: 1_000_000n, maxFiles: 9 }, 10n, 1), { ok: false, reason: 'quota_files_exceeded' });
});

test('a new version of an existing file does not use a file slot', () => {
  assert.deepEqual(evaluateReservation(usage, { quotaBytes: 1_000_000n, maxFiles: 9 }, 10n, 0), { ok: true });
});

test('unlimited (super admin)', () => {
  assert.deepEqual(evaluateReservation(usage, { quotaBytes: null, maxFiles: null }, 10n ** 15n, 1), { ok: true });
});

test('rejects non-positive size', () => {
  assert.throws(() => evaluateReservation(usage, { quotaBytes: null, maxFiles: null }, 0n, 1), RangeError);
});
