import net from 'node:net';
import type { ScanResult } from '../upload/state-machine.ts';

export interface Scanner {
  scan(path: string): Promise<ScanResult>;
}

export interface ClamdOptions {
  host?: string;
  port?: number;
  socketPath?: string; // alternative to host/port
  timeoutMs?: number;
  // clamd sees the shared volume under its own mount point: map the local path to the path clamd must scan.
  mapPath?: (localPath: string) => string;
}

// Parses one clamd reply line, e.g. '/storage/x: OK', '/storage/x: Eicar-Test-Signature FOUND', '... ERROR'.
export function parseClamdReply(reply: string): ScanResult {
  const line = reply.replace(/\0/g, '').trim();
  if (line.endsWith(' FOUND')) {
    const body = line.slice(0, -' FOUND'.length);
    const signature = body.slice(body.lastIndexOf(': ') + 2);
    return { kind: 'infected', signature };
  }
  if (line.endsWith(' OK')) return { kind: 'clean' };
  if (line.toLowerCase().includes('size limit')) return { kind: 'limit' };
  return { kind: 'error' };
}

// Scans by PATH on a read-only shared volume (ADR-0004), so clamd's stream size limit does not apply.
export class ClamdScanner implements Scanner {
  private readonly opts: ClamdOptions;

  constructor(opts: ClamdOptions) {
    this.opts = opts;
  }

  private request(command: string): Promise<string> {
    const { host = '127.0.0.1', port = 3310, socketPath, timeoutMs = 120_000 } = this.opts;
    return new Promise((resolve, reject) => {
      const socket = socketPath === undefined ? net.connect({ host, port }) : net.connect({ path: socketPath });
      const chunks: Buffer[] = [];
      let done = false;
      const finish = (err: Error | null, value?: string) => {
        if (done) return;
        done = true;
        socket.destroy();
        if (err) reject(err);
        else resolve(value as string);
      };
      socket.setTimeout(timeoutMs, () => finish(new Error('timeout')));
      socket.on('error', (e) => finish(e));
      socket.on('data', (d) => chunks.push(Buffer.from(d)));
      socket.on('end', () => finish(null, Buffer.concat(chunks).toString('utf8')));
      socket.on('connect', () => socket.write(`z${command}\0`));
    });
  }

  async ping(): Promise<boolean> {
    try {
      return (await this.request('PING')).replace(/\0/g, '').trim() === 'PONG';
    } catch {
      return false;
    }
  }

  async scan(path: string): Promise<ScanResult> {
    const target = this.opts.mapPath === undefined ? path : this.opts.mapPath(path);
    try {
      return parseClamdReply(await this.request(`SCAN ${target}`));
    } catch (err) {
      return (err as Error).message === 'timeout' ? { kind: 'timeout' } : { kind: 'error' };
    }
  }
}
