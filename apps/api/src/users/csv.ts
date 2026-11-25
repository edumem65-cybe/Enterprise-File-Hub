// Minimal RFC 4180 CSV parser for bulk user import (Excel exports in Persian locales often use ';').
export interface CsvRow {
  line: number; // 1-based line number of the record in the file (header = 1)
  values: Record<string, string>;
}

export type CsvResult = { ok: true; rows: CsvRow[] } | { ok: false; error: 'empty' | 'unterminated_quote' | 'duplicate_header' | 'too_many_rows' };

export const MAX_IMPORT_ROWS = 5000;

function detectDelimiter(headerLine: string): string {
  let best = ',';
  let bestCount = -1;
  for (const d of [',', ';', '\t']) {
    const count = headerLine.split(d).length;
    if (count > bestCount) {
      best = d;
      bestCount = count;
    }
  }
  return best;
}

export function parseCsv(input: string): CsvResult {
  const text = input.startsWith('\uFEFF') ? input.slice(1) : input;
  if (text.trim() === '') return { ok: false, error: 'empty' };
  const firstLine = text.split('\n', 1)[0] as string;
  const delimiter = detectDelimiter(firstLine);

  const records: { line: number; fields: string[] }[] = [];
  let field = '';
  let fields: string[] = [];
  let inQuotes = false;
  let line = 1;
  let recordLine = 1;
  let pending = false; // true when the current record has any content

  const endRecord = () => {
    fields.push(field);
    if (pending || fields.length > 1 || fields[0] !== '') records.push({ line: recordLine, fields });
    field = '';
    fields = [];
    pending = false;
  };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        if (ch === '\n') line++;
        field += ch;
      }
      continue;
    }
    if (ch === '"' && field === '') {
      inQuotes = true;
      pending = true;
    } else if (ch === delimiter) {
      fields.push(field);
      field = '';
      pending = true;
    } else if (ch === '\r') {
      // ignore; handled with the following \n
    } else if (ch === '\n') {
      endRecord();
      line++;
      recordLine = line;
    } else {
      field += ch;
      pending = true;
    }
  }
  if (inQuotes) return { ok: false, error: 'unterminated_quote' };
  if (field !== '' || fields.length > 0 || pending) endRecord();

  const [header, ...body] = records;
  if (header === undefined) return { ok: false, error: 'empty' };
  const names = header.fields.map((h) => h.trim().toLowerCase());
  if (new Set(names).size !== names.length) return { ok: false, error: 'duplicate_header' };
  if (body.length > MAX_IMPORT_ROWS) return { ok: false, error: 'too_many_rows' };

  const rows = body.map((r) => {
    const values: Record<string, string> = {};
    names.forEach((n, idx) => {
      values[n] = (r.fields[idx] ?? '').trim();
    });
    return { line: r.line, values };
  });
  return { ok: true, rows };
}
