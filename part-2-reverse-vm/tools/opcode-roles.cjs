'use strict';
// ============================================================================
//  opcode-roles.cjs — find the opcodes a static walk needs SEMANTICS for.
//
//  opcode-table.cjs derives operand layouts, which is enough to step over an
//  instruction. It is not enough to traverse: a handful of opcodes carry
//  traversal meaning, and without them the walk has nowhere to go.
//
//    control     touches the program counter — conditional jump, call, return
//    alphabet    loads the byte table every string decodes against
//    string      materialises a string from that table
//    rekey       re-keys the stream; after it, nothing decrypts without it
//
//  Their numbers are build-scoped like everything else, so they are found by what
//  their handler DOES. Signatures, each read off the old build's known handlers:
//
//    control   a call taking the program-counter slot as a literal argument.
//              This finds a GROUP, and that is right: the old build's 451
//              (conditional jump), 346 (call sub) and 485 (return) all move the
//              counter and the walk needs all three. Their operand layouts
//              separate them — VV, V and B+n×V respectively.
//    alphabet  `array.push(readByte(state))` inside a loop
//    string    a modulo against a length, accumulating characters from a table
//    rekey     an assignment into a state property from a 32-bit read
//
//     node opcode-roles.cjs --handlers=handlers.json [--pc=473] [--check]
//
//  --check runs the signatures against the old build, where the answers are known
//  from 06-vm-mechanics §6: jump 451, alphabet 262, string 402, rekey 501.
// ============================================================================
const fs = require('fs');
const path = require('path');
const acorn = require('acorn');

const argv = process.argv.slice(2);
const optOf = (n, d) => { const h = argv.find((a) => a.startsWith('--' + n + '=')); return h ? h.slice(n.length + 3) : d; };

/** what the old build's handlers are known to be — the validation target */
const KNOWN_OLD = { control: [346, 451, 485], alphabet: [262], string: [402], rekey: [501] };
const OLD_PC = 202;

function parse(src) {
  for (const wrap of ['(' + src + ')', src]) {
    try { return acorn.parse(wrap, { ecmaVersion: 2020, ranges: true }); } catch (e) { /* try the other */ }
  }
  return null;
}
function walk(node, fn) {
  (function go(n) {
    if (!n || typeof n.type !== 'string') return;
    fn(n);
    for (const k of Object.keys(n)) {
      if (['start', 'end', 'range', 'type'].includes(k)) continue;
      const v = n[k];
      if (Array.isArray(v)) v.forEach(go); else if (v && typeof v.type === 'string') go(v);
    }
  })(node);
}
function firstParam(ast) {
  let name = null;
  walk(ast, (n) => {
    if (name) return;
    if ((n.type === 'FunctionExpression' || n.type === 'FunctionDeclaration')
      && n.params.length && n.params[0].type === 'Identifier') name = n.params[0].name;
  });
  return name;
}

/** jump: a call taking the program-counter slot as a literal argument */
function isJump(ast, pc) {
  let hit = false;
  walk(ast, (n) => {
    if (n.type !== 'CallExpression') return;
    if (n.arguments.some((a) => a.type === 'Literal' && a.value === pc)) hit = true;
  });
  return hit;
}

/** alphabet: pushes single bytes into an array, in a loop */
function isAlphabet(ast, state) {
  let hit = false;
  walk(ast, (n) => {
    if (n.type !== 'CallExpression') return;
    if (!n.callee || n.callee.type !== 'MemberExpression') return;
    if (!n.callee.property || n.callee.property.name !== 'push') return;
    // the pushed value is a one-argument call handed the state
    for (const a of n.arguments) {
      if (a.type === 'CallExpression' && a.arguments.length === 1
        && a.arguments[0].type === 'Identifier' && a.arguments[0].name === state) hit = true;
    }
  });
  return hit;
}

/** string: accumulates characters, indexing a table, modulo a length */
function isString(ast) {
  let mod = false, accum = false, doubleIndex = false;
  walk(ast, (n) => {
    if (n.type === 'BinaryExpression' && n.operator === '%') mod = true;
    if (n.type === 'AssignmentExpression' && n.operator === '+=') accum = true;
    // table[index[i]] — a lookup through two levels
    if (n.type === 'MemberExpression' && n.computed && n.property
      && n.property.type === 'MemberExpression' && n.property.computed) doubleIndex = true;
  });
  return mod && accum && doubleIndex;
}

/** rekey: assigns a state property from a call whose first argument is 32 */
function isRekey(ast, state) {
  let hit = false;
  walk(ast, (n) => {
    if (n.type !== 'AssignmentExpression' || n.operator !== '=') return;
    const l = n.left, r = n.right;
    if (!l || l.type !== 'MemberExpression' || !l.object || l.object.name !== state) return;
    if (!r || r.type !== 'CallExpression') return;
    if (r.arguments.some((a) => a.type === 'Literal' && a.value === 32)) hit = true;
  });
  return hit;
}

function roles(handlers, pc) {
  const found = { control: [], alphabet: [], string: [], rekey: [] };
  for (const [slot, src] of Object.entries(handlers)) {
    const ast = parse(src);
    if (!ast) continue;
    const state = firstParam(ast);
    if (!state) continue;
    if (isJump(ast, pc)) found.control.push(Number(slot));
    if (isAlphabet(ast, state)) found.alphabet.push(Number(slot));
    if (isString(ast)) found.string.push(Number(slot));
    if (isRekey(ast, state)) found.rekey.push(Number(slot));
  }
  return found;
}

module.exports = { roles, KNOWN_OLD, OLD_PC };

if (require.main !== module) return;

const file = optOf('handlers', null);
if (!file) { console.error('usage: node opcode-roles.cjs --handlers=handlers.json [--pc=N] [--check]'); process.exit(2); }
const handlers = JSON.parse(fs.readFileSync(path.resolve(file), 'utf8'));
const pc = Number(optOf('pc', argv.includes('--check') ? OLD_PC : 473));

console.log('handlers        : ' + Object.keys(handlers).length);
console.log('program counter : slot ' + pc);
console.log('');
const found = roles(handlers, pc);
for (const role of ['control', 'alphabet', 'string', 'rekey']) {
  const got = found[role].sort((a, b) => a - b);
  const line = role.padEnd(10) + ' : ' + (got.length ? got.join(', ') : '(none)');
  if (!argv.includes('--check')) { console.log(line); continue; }
  const want = KNOWN_OLD[role];
  const same = got.length === want.length && got.every((v, i) => v === want[i]);
  console.log(line.padEnd(30) + '  expected ' + want.join(', ').padEnd(16)
    + (same ? 'ok' : want.every((w) => got.includes(w)) ? 'superset' : 'MISS'));
}
