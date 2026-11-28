import { existsSync, rmSync } from 'node:fs';
import type { StoragePort } from '../app/ports.ts';
import { promote, stagePath } from './paths.ts';
import type { Stage } from './paths.ts';

// StoragePort on a local filesystem (the SAN-backed volume of the file-store VM, ADR-0007).
export class FsStorage implements StoragePort {
  private readonly root: string;

  constructor(root: string) {
    this.root = root;
  }

  pathFor(stage: Stage, key: string): string {
    return stagePath(this.root, stage, key);
  }

  // Idempotent: a retry after a crash between rename and the database update finds the file already moved.
  async promote(from: Stage, to: Stage, key: string): Promise<void> {
    const src = this.pathFor(from, key);
    const dst = this.pathFor(to, key);
    if (!existsSync(src) && existsSync(dst)) return;
    promote(this.root, from, to, key);
  }

  async remove(stage: Stage, key: string): Promise<void> {
    rmSync(this.pathFor(stage, key), { force: true });
  }
}
