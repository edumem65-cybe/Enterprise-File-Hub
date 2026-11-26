import { randomBytes } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, renameSync, statSync } from 'node:fs';
import path from 'node:path';

// ADR-0004: incoming/ -> quarantine/ -> blobs/ab/cd/<key>, all on ONE filesystem so rename is atomic.
export type Stage = 'incoming' | 'quarantine' | 'blobs';
export const STAGES: readonly Stage[] = ['incoming', 'quarantine', 'blobs'];

const HEX = '0123456789abcdef';

export function newBlobKey(): string {
  return randomBytes(16).toString('hex'); // 32 hex chars; never derived from user input
}

export function isBlobKey(key: string): boolean {
  if (key.length !== 32) return false;
  for (const c of key) if (!HEX.includes(c)) return false;
  return true;
}

export function assertInside(root: string, candidate: string): string {
  const r = path.resolve(root);
  const c = path.resolve(candidate);
  if (c !== r && !c.startsWith(r + path.sep)) throw new RangeError('path escapes storage root');
  return c;
}

export function stagePath(root: string, stage: Stage, key: string): string {
  if (!isBlobKey(key)) throw new RangeError('invalid blob key');
  const p = stage === 'blobs' ? path.join(root, 'blobs', key.slice(0, 2), key.slice(2, 4), key) : path.join(root, stage, key);
  return assertInside(root, p);
}

// Atomic rename needs the stage directories on the same device. Fails loudly instead of silently copying.
export function assertSameFilesystem(root: string): void {
  let dev: number | null = null;
  for (const stage of STAGES) {
    const d = path.join(root, stage);
    if (!existsSync(d)) throw new Error(`missing storage directory: ${stage}`);
    const id = statSync(d).dev;
    if (dev !== null && id !== dev) throw new Error('storage stages are not on the same filesystem');
    dev = id;
  }
}

export function ensureStageDirs(root: string): void {
  for (const stage of STAGES) mkdirSync(path.join(root, stage), { recursive: true, mode: 0o750 });
}

// Move a file to the next stage: fsync the data, refuse to overwrite, rename, fsync the target directory.
export function promote(root: string, from: Stage, to: Stage, key: string): string {
  const src = stagePath(root, from, key);
  const dst = stagePath(root, to, key);
  if (existsSync(dst)) throw new Error('target already exists');
  mkdirSync(path.dirname(dst), { recursive: true, mode: 0o750 });
  const fd = openSync(src, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(src, dst);
  const dirFd = openSync(path.dirname(dst), 'r');
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
  return dst;
}
