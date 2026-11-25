export interface Usage {
  usedBytes: bigint;
  reservedBytes: bigint;
  fileCount: number;
  reservedFiles: number;
}

// null = unlimited (only super_admin, enforced by a DB CHECK).
export interface Limits {
  quotaBytes: bigint | null;
  maxFiles: number | null;
}

export type ReservationResult = { ok: true } | { ok: false; reason: 'quota_bytes_exceeded' | 'quota_files_exceeded' };

// Mirrors the atomic SQL in migration 0002. files = 1 for a new file, 0 for a new version of an existing file.
export function evaluateReservation(usage: Usage, limits: Limits, bytes: bigint, files: 0 | 1): ReservationResult {
  if (bytes <= 0n) throw new RangeError('bytes must be positive');
  if (limits.quotaBytes !== null && usage.usedBytes + usage.reservedBytes + bytes > limits.quotaBytes) {
    return { ok: false, reason: 'quota_bytes_exceeded' };
  }
  if (limits.maxFiles !== null && usage.fileCount + usage.reservedFiles + files > limits.maxFiles) {
    return { ok: false, reason: 'quota_files_exceeded' };
  }
  return { ok: true };
}
