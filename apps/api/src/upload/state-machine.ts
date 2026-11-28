// State machines from docs/architecture.md. Illegal transitions return null instead of silently continuing.
export type UploadState = 'created' | 'uploading' | 'finalizing' | 'finalized' | 'failed' | 'expired' | 'cancelled';
export type UploadEvent = 'chunk' | 'finalize_requested' | 'finalize_done' | 'finalize_failed' | 'cancel' | 'expire' | 'fail';

const TRANSITIONS: Record<UploadState, Partial<Record<UploadEvent, UploadState>>> = {
  created: { chunk: 'uploading', cancel: 'cancelled', expire: 'expired', fail: 'failed' },
  uploading: { chunk: 'uploading', finalize_requested: 'finalizing', cancel: 'cancelled', expire: 'expired', fail: 'failed' },
  // A repeated finalize request (same idempotency key) is harmless; a finalizing upload never expires silently.
  finalizing: { finalize_requested: 'finalizing', finalize_done: 'finalized', finalize_failed: 'failed' },
  finalized: { finalize_requested: 'finalized' },
  failed: {},
  expired: {},
  cancelled: {},
};

export function nextUploadState(state: UploadState, event: UploadEvent): UploadState | null {
  return TRANSITIONS[state][event] ?? null;
}

export function isTerminalUploadState(state: UploadState): boolean {
  return state === 'finalized' || state === 'failed' || state === 'expired' || state === 'cancelled';
}

export function isUploadExpired(expiresAt: number, now: number, state: UploadState): boolean {
  return (state === 'created' || state === 'uploading') && now >= expiresAt;
}

export type ScanResult =
  | { kind: 'clean' }
  | { kind: 'infected'; signature: string }
  | { kind: 'error' }
  | { kind: 'timeout' }
  | { kind: 'limit' }
  | { kind: 'integrity_mismatch' }; // the bytes on disk differ from the bytes that were uploaded

export interface ScanDecision {
  scanState: 'clean' | 'rejected' | 'failed' | 'quarantined';
  retry: boolean;
  retryDelayMs: number;
  rejectReason: 'infected' | 'scan_limit' | 'integrity_mismatch' | null;
  alert: boolean; // notify super admin and the owner's region manager
}

export const MAX_SCAN_ATTEMPTS = 3;

// Fail closed: only an explicit clean verdict makes a file downloadable.
export function decideScanOutcome(result: ScanResult, attempt: number, maxAttempts: number = MAX_SCAN_ATTEMPTS): ScanDecision {
  switch (result.kind) {
    case 'clean':
      return { scanState: 'clean', retry: false, retryDelayMs: 0, rejectReason: null, alert: false };
    case 'infected':
      return { scanState: 'rejected', retry: false, retryDelayMs: 0, rejectReason: 'infected', alert: true };
    case 'limit':
      return { scanState: 'rejected', retry: false, retryDelayMs: 0, rejectReason: 'scan_limit', alert: true };
    case 'integrity_mismatch':
      return { scanState: 'rejected', retry: false, retryDelayMs: 0, rejectReason: 'integrity_mismatch', alert: true };
    default:
      if (attempt < maxAttempts) {
        const delay = Math.min(30_000 * 2 ** (attempt - 1), 600_000);
        return { scanState: 'quarantined', retry: true, retryDelayMs: delay, rejectReason: null, alert: false };
      }
      return { scanState: 'failed', retry: false, retryDelayMs: 0, rejectReason: null, alert: true };
  }
}
