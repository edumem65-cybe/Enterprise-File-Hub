// ADR-0006: every file type is allowed unless it is problematic. There is no allowlist.

export interface FilePolicyConfig {
  blockedExtensions: ReadonlySet<string>; // lower case, without a dot
  maxFileBytes: bigint;
}

export interface FileCandidate {
  name: string;
  sizeBytes: bigint;
  header: Uint8Array; // first bytes of the file (4 KiB is enough)
}

export type FilePolicyResult =
  | { allowed: true; name: string; extension: string | null }
  | {
      allowed: false;
      reason: 'invalid_name' | 'empty_file' | 'too_large' | 'blocked_extension' | 'detected_executable';
    };

const MAX_NAME_BYTES = 255;
const BACKSLASH = String.fromCharCode(92);

export function sanitizeFileName(raw: string): string | null {
  const name = raw.normalize('NFC').trim();
  if (name === '' || name === '.' || name === '..') return null;
  if (name.includes('/') || name.includes(BACKSLASH)) return null;
  if (new TextEncoder().encode(name).length > MAX_NAME_BYTES) return null;
  for (const ch of name) {
    const c = ch.codePointAt(0) as number;
    if (c < 0x20 || c === 0x7f) return null; // control characters, NUL, CR, LF
    if ((c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069)) return null; // bidi override (extension spoofing)
    // ZWNJ (U+200C) and RLM/LRM are valid in Persian names and stay allowed.
  }
  return name;
}

export function extensionOf(name: string): string | null {
  const trimmed = name.replace(/[. ]+$/, ''); // 'a.exe.' and 'a.exe ' are treated as 'a.exe' on Windows
  const idx = trimmed.lastIndexOf('.');
  if (idx === -1 || idx === trimmed.length - 1) return null;
  return trimmed.slice(idx + 1).toLowerCase();
}

export type ExecutableKind = 'pe' | 'elf' | 'macho';

export function detectExecutable(h: Uint8Array): ExecutableKind | null {
  if (h.length >= 4 && h[0] === 0x7f && h[1] === 0x45 && h[2] === 0x4c && h[3] === 0x46) return 'elf';
  if (h.length >= 4) {
    const w = ((h[0] as number) << 24) | ((h[1] as number) << 16) | ((h[2] as number) << 8) | (h[3] as number);
    const u = w >>> 0;
    if (u === 0xfeedface || u === 0xfeedfacf || u === 0xcefaedfe || u === 0xcffaedfe) return 'macho';
    if (u === 0xcafebabe && h.length >= 8) {
      const nfat = (((h[4] as number) << 24) | ((h[5] as number) << 16) | ((h[6] as number) << 8) | (h[7] as number)) >>> 0;
      if (nfat >= 1 && nfat < 20) return 'macho'; // fat Mach-O; Java class files have a version >= 45 here
    }
  }
  if (h.length >= 0x40 && h[0] === 0x4d && h[1] === 0x5a) {
    // 'MZ' alone is too weak (plain text can start with it): require a valid PE header pointer.
    const off = ((h[0x3c] as number) | ((h[0x3d] as number) << 8) | ((h[0x3e] as number) << 16) | ((h[0x3f] as number) << 24)) >>> 0;
    if (off + 4 <= h.length && h[off] === 0x50 && h[off + 1] === 0x45 && h[off + 2] === 0 && h[off + 3] === 0) return 'pe';
  }
  return null;
}

export function evaluateFilePolicy(file: FileCandidate, config: FilePolicyConfig): FilePolicyResult {
  const name = sanitizeFileName(file.name);
  if (name === null) return { allowed: false, reason: 'invalid_name' };
  if (file.sizeBytes <= 0n) return { allowed: false, reason: 'empty_file' };
  if (file.sizeBytes > config.maxFileBytes) return { allowed: false, reason: 'too_large' };
  const extension = extensionOf(name);
  if (extension !== null && config.blockedExtensions.has(extension)) return { allowed: false, reason: 'blocked_extension' };
  // Renaming setup.exe to setup.pdf must not bypass the policy.
  if (detectExecutable(file.header) !== null) return { allowed: false, reason: 'detected_executable' };
  return { allowed: true, name, extension };
}
