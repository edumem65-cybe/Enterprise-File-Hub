// Request checks for the tus endpoints (ADR-0001). Pure functions: the HTTP layer maps `status` and `code`.
export type GuardResult<T> = { ok: true; value: T } | { ok: false; status: 400 | 409 | 413 | 415 | 429; code: string };

export const TUS_PATCH_CONTENT_TYPE = 'application/offset+octet-stream';

function parseUint(raw: string | undefined): bigint | null {
  if (raw === undefined || raw === '' || raw.length > 18) return null;
  for (const ch of raw) if (ch < '0' || ch > '9') return null;
  return BigInt(raw);
}

export function validateCreate(args: {
  uploadLength: string | undefined;
  deferLength: string | undefined;
  maxFileBytes: bigint;
  activeUploads: number;
  maxConcurrent: number;
}): GuardResult<{ sizeBytes: bigint }> {
  // Quota reservation needs the exact size up front, so Upload-Defer-Length is not supported.
  if (args.deferLength !== undefined) return { ok: false, status: 400, code: 'defer_length_not_supported' };
  const size = parseUint(args.uploadLength);
  if (size === null || size <= 0n) return { ok: false, status: 400, code: 'invalid_upload_length' };
  if (size > args.maxFileBytes) return { ok: false, status: 413, code: 'file_too_large' };
  if (args.activeUploads >= args.maxConcurrent) return { ok: false, status: 429, code: 'too_many_concurrent_uploads' };
  return { ok: true, value: { sizeBytes: size } };
}

export function validatePatch(args: {
  contentType: string | undefined;
  uploadOffset: string | undefined;
  contentLength: string | undefined;
  sessionOffset: bigint;
  expectedSize: bigint;
  maxChunkBytes: bigint;
}): GuardResult<{ newOffset: bigint }> {
  if (args.contentType !== TUS_PATCH_CONTENT_TYPE) return { ok: false, status: 415, code: 'invalid_content_type' };
  const offset = parseUint(args.uploadOffset);
  const length = parseUint(args.contentLength);
  if (offset === null || length === null || length === 0n) return { ok: false, status: 400, code: 'invalid_headers' };
  // A duplicate or out-of-order chunk gets 409; the client re-syncs with HEAD and resumes from the real offset.
  if (offset !== args.sessionOffset) return { ok: false, status: 409, code: 'offset_mismatch' };
  if (length > args.maxChunkBytes) return { ok: false, status: 413, code: 'chunk_too_large' };
  if (offset + length > args.expectedSize) return { ok: false, status: 413, code: 'exceeds_declared_size' };
  return { ok: true, value: { newOffset: offset + length } };
}
