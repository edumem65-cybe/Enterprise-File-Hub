import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TUS_PATCH_CONTENT_TYPE, validateCreate, validatePatch } from './tus-guard.ts';

const create = { uploadLength: '1000', deferLength: undefined, maxFileBytes: 5000n, activeUploads: 0, maxConcurrent: 3 };

test('create: valid request', () => {
  assert.deepEqual(validateCreate(create), { ok: true, value: { sizeBytes: 1000n } });
});

test('create: defer length, bad lengths, too large, too many uploads', () => {
  assert.deepEqual(validateCreate({ ...create, deferLength: '1' }), { ok: false, status: 400, code: 'defer_length_not_supported' });
  for (const bad of [undefined, '', '0', '-5', '1e3', '12.5', 'abc', '1'.repeat(30)]) {
    assert.deepEqual(validateCreate({ ...create, uploadLength: bad }), { ok: false, status: 400, code: 'invalid_upload_length' }, String(bad));
  }
  assert.deepEqual(validateCreate({ ...create, uploadLength: '5001' }), { ok: false, status: 413, code: 'file_too_large' });
  assert.deepEqual(validateCreate({ ...create, activeUploads: 3 }), { ok: false, status: 429, code: 'too_many_concurrent_uploads' });
  assert.equal(validateCreate({ ...create, activeUploads: 2 }).ok, true);
});

const patch = {
  contentType: TUS_PATCH_CONTENT_TYPE,
  uploadOffset: '100',
  contentLength: '50',
  sessionOffset: 100n,
  expectedSize: 1000n,
  maxChunkBytes: 16n * 1024n * 1024n,
};

test('patch: valid chunk advances the offset', () => {
  assert.deepEqual(validatePatch(patch), { ok: true, value: { newOffset: 150n } });
});

test('patch: duplicate or out-of-order chunk gets 409 so the client can resync', () => {
  assert.deepEqual(validatePatch({ ...patch, uploadOffset: '50' }), { ok: false, status: 409, code: 'offset_mismatch' });
  assert.deepEqual(validatePatch({ ...patch, uploadOffset: '150' }), { ok: false, status: 409, code: 'offset_mismatch' });
});

test('patch: content type, headers, chunk size and declared size are enforced', () => {
  assert.equal(validatePatch({ ...patch, contentType: 'text/plain' }).ok, false);
  assert.deepEqual(validatePatch({ ...patch, contentType: undefined }), { ok: false, status: 415, code: 'invalid_content_type' });
  assert.deepEqual(validatePatch({ ...patch, contentLength: undefined }), { ok: false, status: 400, code: 'invalid_headers' });
  assert.deepEqual(validatePatch({ ...patch, contentLength: '0' }), { ok: false, status: 400, code: 'invalid_headers' });
  assert.deepEqual(validatePatch({ ...patch, contentLength: String(16 * 1024 * 1024 + 1), expectedSize: 10n ** 9n }), { ok: false, status: 413, code: 'chunk_too_large' });
  assert.deepEqual(validatePatch({ ...patch, contentLength: '901' }), { ok: false, status: 413, code: 'exceeds_declared_size' });
  assert.deepEqual(validatePatch({ ...patch, contentLength: '900' }), { ok: true, value: { newOffset: 1000n } });
});
