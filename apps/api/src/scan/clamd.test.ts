import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { ClamdScanner, parseClamdReply } from './clamd.ts';

// A tiny fake clamd: reads one NUL-terminated command and answers with whatever the handler returns.
async function fakeClamd(handler: (command: string) => string | null): Promise<{ port: number; close: () => Promise<void>; seen: string[] }> {
  const seen: string[] = [];
  const server = net.createServer((socket) => {
    let buf = '';
    socket.on('data', (d) => {
      buf += d.toString('utf8');
      const end = buf.indexOf('\0');
      if (end === -1) return;
      const command = buf.slice(0, end);
      seen.push(command);
      const reply = handler(command);
      if (reply !== null) socket.end(reply + '\0');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as AddressInfo).port,
    seen,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

test('reply parsing', () => {
  assert.deepEqual(parseClamdReply('/storage/a: OK'), { kind: 'clean' });
  assert.deepEqual(parseClamdReply('/storage/a: Eicar-Test-Signature FOUND\0'), { kind: 'infected', signature: 'Eicar-Test-Signature' });
  assert.deepEqual(parseClamdReply('/storage/a: Win.Test.EICAR_HDB-1 FOUND'), { kind: 'infected', signature: 'Win.Test.EICAR_HDB-1' });
  assert.deepEqual(parseClamdReply('/storage/a: lstat() failed: No such file or directory. ERROR'), { kind: 'error' });
  assert.deepEqual(parseClamdReply('INSTREAM size limit exceeded. ERROR'), { kind: 'limit' });
  assert.deepEqual(parseClamdReply(''), { kind: 'error' });
});

test('scans by path with z-prefixed commands and maps the path for clamd', async () => {
  const clamd = await fakeClamd((c) => `${c.slice('zSCAN '.length)}: OK`);
  try {
    const scanner = new ClamdScanner({ port: clamd.port, mapPath: (p) => p.replace('/data/files', '/storage') });
    assert.deepEqual(await scanner.scan('/data/files/quarantine/abc'), { kind: 'clean' });
    assert.deepEqual(clamd.seen, ['zSCAN /storage/quarantine/abc']);
  } finally {
    await clamd.close();
  }
});

test('infected, error replies, ping', async () => {
  const clamd = await fakeClamd((c) => (c === 'zPING' ? 'PONG' : c.includes('bad') ? '/x: Eicar-Test-Signature FOUND' : '/x: Access denied. ERROR'));
  try {
    const scanner = new ClamdScanner({ port: clamd.port });
    assert.equal(await scanner.ping(), true);
    assert.deepEqual(await scanner.scan('/q/bad-file'), { kind: 'infected', signature: 'Eicar-Test-Signature' });
    assert.deepEqual(await scanner.scan('/q/other'), { kind: 'error' });
  } finally {
    await clamd.close();
  }
});

test('timeouts and unreachable servers fail closed', async () => {
  const silent = await fakeClamd(() => null); // accepts the command and never answers
  try {
    const slow = new ClamdScanner({ port: silent.port, timeoutMs: 100 });
    assert.deepEqual(await slow.scan('/q/x'), { kind: 'timeout' });
  } finally {
    await silent.close();
  }
  const gone = new ClamdScanner({ port: 1, timeoutMs: 500 }); // nothing listens here
  assert.deepEqual(await gone.scan('/q/x'), { kind: 'error' });
  assert.equal(await gone.ping(), false);
});
