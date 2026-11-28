import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { open } from 'node:fs/promises';

export async function sha256File(path: string): Promise<{ sha256: string; size: bigint }> {
  const hash = createHash('sha256');
  let size = 0n;
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk as Buffer);
    size += BigInt((chunk as Buffer).length);
  }
  return { sha256: hash.digest('hex'), size };
}

// First bytes of a file, for the magic-byte check (4 KiB is enough for the executable signatures).
export async function readHeader(path: string, bytes = 4096): Promise<Uint8Array> {
  const handle = await open(path, 'r');
  try {
    const buf = Buffer.alloc(bytes);
    const { bytesRead } = await handle.read(buf, 0, bytes, 0);
    return new Uint8Array(buf.subarray(0, bytesRead));
  } finally {
    await handle.close();
  }
}
