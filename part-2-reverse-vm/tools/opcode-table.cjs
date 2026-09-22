'use strict';
// ============================================================================
//  opcode-table.cjs — DERIVE a build's opcode operand layouts from its own
//  handlers, instead of hardcoding them.
//
//  static-disasm.cjs carries ~30 opcode numbers with their operand layouts,
//  written by hand for build 885c049eda50. On any other build it decodes one
//  instruction and stops: the numbers mean something else there, and they cannot
//  be translated — a new build is a REGENERATION, not a rename, so matching
//  handlers by shape across builds scores zero (docs/13-builds.md).
//
//  But the layout is not a secret: it is written in the handler itself. A handler
//  reads its operands by calling a small set of helpers, and which helper it
//  calls says what it consumes:
//
//    readOperand(state, _)         -> one variable-width operand   "V"
//    loadBytes(_, K, state, _, _)  -> one operand then K raw bytes  "V" + K×"B"
//    emit(K, state) / emit(state, K) -> two operands                "V V"
//
//  The helper NAMES are build-scoped, so they are identified by shape: the
//  operand reader is the callee most handlers invoke with their own first
//  parameter (the VM state). Everything else follows from that.
//
//     node opcode-table.cjs --handlers=handlers.json [--check]
//
//  --check validates the derivation against the table static-disasm.cjs
//  hardcodes for the old build. That is the point of the exercise: the method has
//  to reproduce a known-correct answer before it is trusted on a build nobody has
//  read.
// ============================================================================
const fs = require('fs');
const path = require('path');

const argv = process.argv.slice(2);
const optOf = (n, d) => { const h = argv.find((a) => a.startsWith('--' + n + '=')); return h ? h.slice(n.length + 3) : d; };

/** the layout static-disasm.cjs hardcodes for 885c049eda50 — the ground truth */
const KNOWN_OLD = {
  5: 'VVV', 8: 'VB', 49: 'VBB', 459: 'VBBBB', 88: 'VV', 184: 'VV', 141: 'VV',
  285: 'VVV', 430: 'VVV', 37: 'VVV', 10: 'VV', 11: 'VV', 153: 'VBV', 123: 'VVV',
  451: 'VV', 346: 'V', 101: 'V', 140: 'VV', 268: 'VV', 297: 'VV', 371: 'VV',
  375: 'VV', 408: 'VVVV',
};

const acorn = require('acorn');

/**
 * Parse a handler and return its calls.
 *
 * This has to be a real parse. The code is written inside-out —
 * `z(a, (v = z(a, 114), 42))` — so a regex that cannot see through nested
 * parentheses silently under-counts the operand reads, and the derived layout
 * comes out short. That was the first attempt, and it scored 13 of 23.
 */
function parseHandler(src) {
  let ast;
  for (const wrap of ['(' + src + ')', src]) {
    try { ast = acorn.parse(wrap, { ecmaVersion: 2020, ranges: true }); break; } catch (e) { /* try the other */ }
  }
  if (!ast) return null;
  let fn = null;
  const calls = [];
  let depth = 0;
  (function walk(n) {
    if (!n || typeof n.type !== 'string') return;
    const isFn = n.type === 'FunctionExpression' || n.type === 'FunctionDeclaration'
      || n.type === 'ArrowFunctionExpression';
    if (!fn && (n.type === 'FunctionExpression' || n.type === 'FunctionDeclaration')) fn = n;
    if (isFn) depth++;
    // The callee is not always a bare name. This code writes an operand read as
    //     (u = Q(11, t), Q)(94, O)
    // — a comma expression whose value is the reader, then called. Requiring an
    // Identifier callee silently drops that read, the layout comes out one operand
    // short, and every instruction boundary after it is fiction. That is what
    // stalled the static walk on d4a6b4f0a2a5 at 33 instructions: opcodes
    // 63/127/286 are three-operand GETPROPs derived as two.
    if (n.type === 'CallExpression' && n.callee) {
      let calleeName = null;
      if (n.callee.type === 'Identifier') calleeName = n.callee.name;
      else if (n.callee.type === 'SequenceExpression') {
        // Record the call, but do NOT rewrite the node: the sequence's earlier
        // elements hold reads of their own — `(u = Q(11, t), Q)(94, O)` contains
        // two — and replacing the callee would stop the walk descending into them.
        const last = n.callee.expressions[n.callee.expressions.length - 1];
        if (last && last.type === 'Identifier') calleeName = last.name;
      }
      if (calleeName) calls.push({ name: calleeName, args: n.arguments, at: n.start, nested: depth > 1 });
    }
    for (const k of Object.keys(n)) {
      if (['start', 'end', 'range', 'type'].includes(k)) continue;
      const v = n[k];
      if (Array.isArray(v)) v.forEach(walk); else if (v && typeof v.type === 'string') walk(v);
    }
  })(ast);
  // A handler need not take the state at all. Once a build keeps it in a closure,
  // some handlers stop declaring parameters entirely —
  // `function () { j3(0, 7, 1, V) }` is a complete constant-load opcode on
  // c348580f3670. Requiring a first parameter rejected those outright, and they
  // are exactly the ones DEF_OPCODE installs at run time.
  if (!fn) return null;
  const first = fn.params.length && fn.params[0].type === 'Identifier' ? fn.params[0].name : null;
  calls.sort((a, b) => a.at - b.at);
  const params = new Set(fn.params.filter((x) => x.type === 'Identifier').map((x) => x.name));
  return { state: first, params, calls };
}

// This code is written inside-out: the state often arrives wrapped in a sequence
// expression whose only purpose is to run an assignment first —
// `z(((Z = z(a, 114)), a), 78)`. Unwrap to the value the expression actually
// yields before asking whether it is the state, or a third of the operand reads
// are invisible.
function unwrap(a) {
  while (a && (a.type === 'SequenceExpression' || a.type === 'ParenthesizedExpression')) {
    a = a.type === 'SequenceExpression' ? a.expressions[a.expressions.length - 1] : a.expression;
  }
  return a;
}
const isIdent = (a, name) => { const u = unwrap(a); return u && u.type === 'Identifier' && u.name === name; };
const isNum = (a) => { const u = unwrap(a); return u && u.type === 'Literal' && typeof u.value === 'number'; };

/** the handler's first parameter is the VM state */
function stateParam(src) {
  const p = parseHandler(src);
  return p ? p.state : null;
}

/**
 * The operand reader: the callee that the most handlers invoke with their own
 * state as an argument, in a two-argument call. Identified by shape so it
 * survives a rename.
 */
// A handler's state is its first parameter — until a build also keeps the state
// in a closure variable and uses the two interchangeably:
//
//    function (t, f, x, q) {
//      if (false == ![]) q = h(J, 25);          // <- a read, via the closure
//      R(((x = ((f = h(t, 25)), h(t, 28))), J), x, A(t, q) || A(J, f));
//    }
//
// `J` holds the same state object — it sits in R's state position — so `h(J, 25)`
// consumes an operand exactly like `h(t, 25)`. Counting only the parameter drops
// those reads and the layout comes out short: on c348580f3670 every layout
// collapsed to V / VV / B, with none of the three- and four-operand forms the
// same VM has on the build before it.
//
// The alias is found without a name: an identifier that appears in the operand
// reader's state position while NOT being one of that handler's own parameters
// is a free reference to the state.
function findStateAliases(handlers, readers) {
  readers = Array.isArray(readers) ? readers : [readers];
  const alias = new Set();
  for (const src of Object.values(handlers)) {
    const p = parseHandler(src);
    if (!p) continue;
    for (const c of p.calls) {
      if (!readers.includes(c.name) || c.args.length !== 2) continue;
      for (const a of c.args) {
        const u = unwrap(a);
        if (u && u.type === 'Identifier' && !p.params.has(u.name)) alias.add(u.name);
      }
      /* a parameterless handler reads through the closure only */
    }
  }
  return alias;
}

/**
 * A build can have MORE THAN ONE operand reader, and taking only the commonest
 * loses operands silently. c348580f3670's property-write handler reads three:
 *
 *   f = h(O, 23);   K = l(10, t);   x = l(14, V);
 *
 * `h` is the reader the most handlers use, `l` is a second one, and counting only
 * `h` derives a layout of one operand where the truth is three. The disassembler
 * then reads one operand too few at every property write and desynchronises.
 *
 * A reader is told from a register accessor by its second argument: the reader
 * takes the state and a NUMERIC LITERAL, the accessor takes the state and a slot
 * held in a variable — `h(O, 23)` against `M(t, K)`.
 */
function findOperandReaders(handlers) {
  const users = new Map();
  for (const src of Object.values(handlers)) {
    const p = parseHandler(src);
    if (!p) continue;
    for (const c of p.calls) {
      if (c.args.length !== 2) continue;
      const hasState = c.args.some((a) => isIdent(a, p.state));
      const hasNum = c.args.some(isNum);
      if (!hasState || !hasNum) continue;
      if (!users.has(c.name)) users.set(c.name, new Set());
      users.get(c.name).add(src);
    }
  }
  // The separation is not subtle, so a share threshold is enough and a bare
  // count is not. Measured share of handlers using each name:
  //
  //   885c049eda50   z 72%   then B, lP, Ru at 6%
  //   c348580f3670   h 62%   l 35%   then Z, uz, Oz at 6%
  //
  // The 6% names are emit and register helpers that also take the state and a
  // literal. Counting them as readers put a phantom operand into the four emit
  // opcodes on the old build, whose layouts were right before.
  const total = Object.keys(handlers).length || 1;
  const floor = Math.max(3, Math.ceil(total * 0.15));
  const ranked = [...users.entries()].filter(([, v]) => v.size >= floor)
    .sort((a, b) => b[1].size - a[1].size);
  return ranked.map(([n]) => n);
}

/** kept for callers that want the primary reader's name */
function findOperandReader(handlers) {
  const r = findOperandReaders(handlers);
  return r.length ? r[0] : null;
}

/**
 * Derive one handler's layout, in SOURCE order — which for this code is the
 * order operands are consumed, because the reader advances the bit-PC as a side
 * effect and the inside-out nesting only reorders the assignments around it.
 */
function deriveLayout(src, reader, aliases) {
  const readers = Array.isArray(reader) ? reader : [reader];
  const p = parseHandler(src);
  if (!p) return null;
  const parts = [];
  let via = null;
  // every way this handler can name the state: its own first parameter, plus the
  // build's closure aliases for the same object
  const isState = (a) => {
    const u = unwrap(a);
    if (!u || u.type !== 'Identifier') return false;
    if (p.state && u.name === p.state) return true;
    return !!(aliases && aliases.has(u.name) && !p.params.has(u.name));
  };

  for (const c of p.calls) {
    const args = c.args;
    // one variable-width operand: reader(state, _) in either argument order
    if (readers.includes(c.name) && args.length === 2 && args.some(isState) && args.some(isNum)) {
      parts.push('V');
      via = via || ('reader ' + c.name);
      continue;
    }
    // one raw byte: a single-argument helper handed the state — Xa(state)
    if (args.length === 1 && isState(args[0])) {
      parts.push('B');
      via = via || ('byte ' + c.name + '(state)');
      continue;
    }
    // One operand then K raw bytes. The helper's arity and the state's position
    // in it are build-scoped — `pm(8, 4, a, 2, 33)` on one build, `j3(0, 39, 4, t)`
    // on the next — but the count always sits immediately BEFORE the state:
    //
    //   pm(8, 4, a, 2, 33)   state at 2, count at 1  ->  V + 4 bytes
    //   j3(0, 39, 4, t)      state at 3, count at 2  ->  V + 4 bytes
    //   j3(0,  7, 1, V)      via the closure alias   ->  V + 1 byte
    //
    // Anchoring on the arity instead missed all three of the new build's
    // constant loads, and a constant load is what gives the walk its register
    // values and its jumps.
    if (args.length >= 3) {
      const si = args.findIndex(isState);
      const cnt = si > 0 ? unwrap(args[si - 1]) : null;
      if (cnt && cnt.type === 'Literal' && Number.isInteger(cnt.value) && cnt.value >= 1 && cnt.value <= 8) {
        parts.push('V');
        for (let i = 0; i < cnt.value; i++) parts.push('B');
        via = via || ('bytes ' + c.name + '(…,' + cnt.value + ',state,…)');
        continue;
      }
    }
  }

  // A read inside a CLOSURE the handler builds is not this instruction's operand:
  // it happens later, as many times as the data says. Opcode 237 on 885c049eda50
  // is one of these — it installs `function (P, …) { … D1.push(z(P, 34)) … }` and
  // consumes a number of operands that depends on arrays built at run time. The
  // hand-written case reads 13, which was measured for one program and is not a
  // property of the build at all. Marking it means the walk can stop honestly
  // instead of decoding noise.
  const lazy = p.calls.some((c) => c.nested && readers.includes(c.name));
  if (lazy) return { layout: parts.join(''), via: via || 'closure', variable: true };

  if (!parts.length) {
    // emit helpers take the state and a small literal and consume two operands
    for (const c of p.calls) {
      if (c.args.length !== 2) continue;
      if (!c.args.some(isState)) continue;
      if (!c.args.some(isNum)) continue;
      return { layout: 'VV', via: 'emit ' + c.name };
    }
    return null;
  }
  return { layout: parts.join(''), via };
}

function derive(handlers) {
  const readers = findOperandReaders(handlers);
  const aliases = findStateAliases(handlers, readers);
  const out = {};
  for (const [slot, src] of Object.entries(handlers)) {
    const d = deriveLayout(src, readers, aliases);
    if (d) out[slot] = d;
  }
  return { reader: readers.join(' '), readers, aliases: [...aliases], table: out };
}

module.exports = { derive, deriveLayout, findOperandReader, findOperandReaders, findStateAliases, KNOWN_OLD };

if (require.main !== module) return;

const file = optOf('handlers', null);
if (!file) { console.error('usage: node opcode-table.cjs --handlers=handlers.json [--check]'); process.exit(2); }
const handlers = JSON.parse(fs.readFileSync(path.resolve(file), 'utf8'));
const { reader, aliases, table } = derive(handlers);

console.log('handlers        : ' + Object.keys(handlers).length);
console.log('operand reader  : ' + reader + '   (found by shape)');
console.log('state aliases   : ' + (aliases.length ? aliases.join(' ') : '(none — state is the parameter only)'));
console.log('layouts derived : ' + Object.keys(table).length);
console.log('');

if (argv.includes('--check')) {
  let ok = 0, wrong = 0, missing = 0;
  console.log('opcode  derived   expected   verdict');
  console.log('-'.repeat(46));
  for (const slot of Object.keys(KNOWN_OLD).sort((a, b) => a - b)) {
    const got = table[slot];
    const want = KNOWN_OLD[slot];
    if (!got) { console.log(String(slot).padStart(6) + '  —         ' + want.padEnd(10) + ' not derived'); missing++; continue; }
    const same = got.layout === want;
    console.log(String(slot).padStart(6) + '  ' + got.layout.padEnd(9) + ' ' + want.padEnd(10) + (same ? 'ok' : 'MISMATCH'));
    same ? ok++ : wrong++;
  }
  console.log('');
  console.log('correct ' + ok + ', wrong ' + wrong + ', not derived ' + missing + '  of ' + Object.keys(KNOWN_OLD).length);
} else {
  const rows = Object.entries(table).sort((a, b) => a[0] - b[0]);
  console.log('opcode  layout      via');
  console.log('-'.repeat(56));
  for (const [slot, d] of rows) console.log(String(slot).padStart(6) + '  ' + d.layout.padEnd(10) + '  ' + d.via);
}
