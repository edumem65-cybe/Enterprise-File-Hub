// Downloads are always attachments (ADR-0004), with a safe ASCII fallback and an RFC 5987 UTF-8 name.
export function attachmentHeader(fileName: string): string {
  const fallback = fileName.replace(/[^A-Za-z0-9._ -]/g, '_').slice(0, 100) || 'download';
  const encoded = encodeURIComponent(fileName).replace(/['()*!]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  return `attachment; filename="${fallback}"; filename*=UTF-8''${encoded}`;
}

export const DOWNLOAD_SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': "default-src 'none'; sandbox",
  'Cache-Control': 'private, no-store',
};
