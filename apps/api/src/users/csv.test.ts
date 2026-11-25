import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_IMPORT_ROWS, parseCsv } from './csv.ts';

test('basic comma file with BOM and CRLF', () => {
  const r = parseCsv('\uFEFFfirst_name,last_name,email\r\nAli,Rezaei,ali@example.com\r\nSara,Karimi,sara@example.com\r\n');
  assert.ok(r.ok);
  assert.equal(r.rows.length, 2);
  assert.deepEqual(r.rows[0], { line: 2, values: { first_name: 'Ali', last_name: 'Rezaei', email: 'ali@example.com' } });
  assert.equal(r.rows[1]?.line, 3);
});

test('semicolon delimiter (Excel in Persian locales) and Persian text', () => {
  const r = parseCsv('first_name;last_name\nعلی;رضایی\n');
  assert.ok(r.ok);
  assert.deepEqual(r.rows[0]?.values, { first_name: 'علی', last_name: 'رضایی' });
});

test('quoted fields with delimiter, escaped quotes and embedded newlines', () => {
  const r = parseCsv('name,note\n"Rezaei, Ali","He said ""hi"""\n"Karimi","line1\nline2"\nlast,ok\n');
  assert.ok(r.ok);
  assert.equal(r.rows[0]?.values.name, 'Rezaei, Ali');
  assert.equal(r.rows[0]?.values.note, 'He said "hi"');
  assert.equal(r.rows[1]?.values.note, 'line1\nline2');
  assert.equal(r.rows[2]?.line, 5); // line numbers account for the embedded newline
});

test('blank lines are skipped and short rows are padded', () => {
  const r = parseCsv('a,b,c\n\n1,2\n');
  assert.ok(r.ok);
  assert.equal(r.rows.length, 1);
  assert.deepEqual(r.rows[0]?.values, { a: '1', b: '2', c: '' });
});

test('errors', () => {
  assert.deepEqual(parseCsv('   \n'), { ok: false, error: 'empty' });
  assert.deepEqual(parseCsv('a,b\n"open,1\n'), { ok: false, error: 'unterminated_quote' });
  assert.deepEqual(parseCsv('a,A\n1,2\n'), { ok: false, error: 'duplicate_header' });
  const big = 'a\n' + 'x\n'.repeat(MAX_IMPORT_ROWS + 1);
  assert.deepEqual(parseCsv(big), { ok: false, error: 'too_many_rows' });
});
