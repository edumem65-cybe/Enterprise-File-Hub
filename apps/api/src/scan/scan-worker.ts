import type { Deps, ScanJob } from '../app/ports.ts';
import { completeScan } from '../app/use-cases.ts';
import type { Result, ScanCompletion } from '../app/use-cases.ts';
import { sha256File } from '../storage/hash.ts';
import type { ScanResult } from '../upload/state-machine.ts';
import type { Scanner } from './clamd.ts';

export interface ScanWorkerDeps {
  deps: Deps;
  scanner: Scanner;
  quarantinePath: (blobKey: string) => string; // where the file waits for its verdict
}

// One scan job: integrity check first (the bytes on disk must be the bytes that were uploaded), then the antivirus.
// Any failure becomes a ScanResult, so the decision (retry, reject, fail closed) stays in one place.
export async function processScanJob(w: ScanWorkerDeps, job: ScanJob): Promise<Result<{ outcome: ScanCompletion }>> {
  const version = await w.deps.repo.getVersion(job.versionId);
  if (version === undefined) return { ok: false, code: 'not_found' };
  if (version.scanState === 'clean' || version.scanState === 'rejected' || version.scanState === 'failed') {
    return { ok: true, value: { outcome: 'ignored' } }; // duplicate delivery of an already decided job
  }
  const path = w.quarantinePath(version.blobKey);
  let verdict: ScanResult;
  try {
    const actual = await sha256File(path);
    if (actual.sha256 !== version.sha256 || actual.size !== version.sizeBytes) {
      verdict = { kind: 'integrity_mismatch' };
    } else {
      verdict = await w.scanner.scan(path);
    }
  } catch {
    verdict = { kind: 'error' }; // e.g. the file is missing or the storage is unreachable: retry, then fail closed
  }
  return completeScan(w.deps, job.versionId, verdict, job.attempt);
}
