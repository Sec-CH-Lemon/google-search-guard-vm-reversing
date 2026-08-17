'use strict';

/** Formatting of the report on what the challenge read from the browser and called. */

const LABELS = { read: 'read', in: 'in? ', keys: 'keys', call: 'call', new: 'new ', throw: 'throw' };

/** The ops that are invocations rather than property accesses. */
const CALL_OPS = new Set(['call', 'new', 'throw']);

/** Reads come before the calls they lead to, so a name and its uses stay together. */
const OP_ORDER = ['in', 'keys', 'read', 'call', 'new', 'throw'];

/** Objects whose properties get read, in the order they are printed. */
const GROUP_ORDER = ['window', 'document', 'navigator', 'screen', 'history', 'performance'];

const KEY_WIDTH = 42;

/**
 * @param {Array<{op,key,args,exists,value,count}>} rows
 * @param {{ invisible: boolean }} meta
 * @returns {string}
 */
function formatTable(rows, meta) {
  const accesses = rows.filter((r) => !CALL_OPS.has(r.op));
  const calls = rows.filter((r) => CALL_OPS.has(r.op));
  const absent = accesses.filter((r) => !r.exists && r.op !== 'keys').length;
  const times = (subset) => subset.reduce((sum, row) => sum + row.count, 0);

  const out = [
    '='.repeat(72),
    `  what the challenge reads and calls             invisible: ${meta.invisible ? 'YES' : 'NO'}`,
    `  ${times(accesses)} accesses, ${accesses.length} distinct, ${absent} of them to names that do not exist`,
    `  ${times(calls)} calls, ${calls.length} distinct argument lists`,
    '  read - property get | call - invocation | in? - `in` presence check | ABSENT - missing',
    '='.repeat(72),
  ];

  for (const [group, items] of groupBy(rows)) {
    out.push('', `  ${group} (${items.length})`);
    for (const row of items) {
      const label = (LABELS[row.op] || row.op).padEnd(5);
      const presence = row.exists ? '      ' : 'ABSENT';
      const name = CALL_OPS.has(row.op) ? `${row.key}(${row.args})` : row.key;
      const value = row.op === 'read' || CALL_OPS.has(row.op) ? ` = ${row.value}` : '';
      const repeats = row.count > 1 ? `  x${row.count}` : '';
      out.push(`    ${label}${presence}  ${name.padEnd(KEY_WIDTH)}${value}${repeats}`);
    }
  }

  return out.join('\n');
}

/** Buckets the rows by owning object, keeping a sensible order. */
function groupBy(rows) {
  const groups = new Map();
  for (const row of rows) {
    const group = row.key.split('.')[0] || '*';
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(row);
  }

  const rank = (name) => {
    const index = GROUP_ORDER.indexOf(name);
    return index < 0 ? GROUP_ORDER.length : index;
  };

  const byName = (x, y) =>
    x.key.localeCompare(y.key) ||
    OP_ORDER.indexOf(x.op) - OP_ORDER.indexOf(y.op) ||
    x.args.localeCompare(y.args);

  return [...groups.entries()]
    .sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b))
    .map(([group, items]) => [group, items.sort(byName)]);
}

module.exports = { formatTable };
