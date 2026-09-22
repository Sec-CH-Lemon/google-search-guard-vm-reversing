'use strict';
// ============================================================================
//  vm-deobfuscate.cjs — produce a readable version of the challenge interpreter.
//
//  The VM source that script #3 assembles is Closure-compiled and then obfuscated
//  with mixed boolean arithmetic (MBA): `-~(a&4) + -2 - ~(a|4)` instead of `a+4`,
//  `(M|0)-(M&K)+(~M&K)` instead of `M^K`, and so on.
//
//  This tool does NOT pattern-match those by eye. It parses the source, finds
//  pure integer expressions, and tests each proposed simplification numerically:
//  the original and candidate must agree on thousands of sampled int32
//  assignments before the rewrite is applied. Anything that disagrees is left
//  untouched. Passing the sample is evidence, not proof for every JavaScript value.
//
//  Passes
//    1. sampled MBA simplification and constant folding
//    2. rename the entities we identified during the analysis
//    3. prettier
//
//  Output: vm-deobfuscated.js  +  a report of every rewrite.
//
//     node vm-deobfuscate.cjs [--samples=4000] [--no-rename] [--out=vm-readable.js]
//
//  --no-rename keeps the original short names (so the bytecode's eval("$J") still
//  resolves); --out= writes elsewhere than the canonical vm-deobfuscated.js. The
//  pair `--no-rename --out=vm-readable.js` produces the source run-readable-vm.cjs
//  executes (readable VM + fingerprint compensation -> real token).
// ============================================================================
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const acorn = require('acorn');

const argv = process.argv.slice(2);
const optOf = (n, d) => { const h = argv.find((a) => a.startsWith('--' + n + '=')); return h ? h.slice(n.length + 3) : d; };
const SAMPLES = Number(optOf('samples', 3000));
const RENAME = !argv.includes('--no-rename');

// ---- 1. get the interpreter source out of the capture ----------------------
// --html= selects the page, because the interpreter is a constant of a BUILD and
// not of the system: see docs/13-builds.md. Located by parsing rather than by
// marker text, so a live minified page works too.
const crypto = require('crypto');
const HTML_ARG = (process.argv.find((a) => a.startsWith('--html=')) || '').slice(7);
const HTML_PATH = HTML_ARG
  ? (path.isAbsolute(HTML_ARG) ? HTML_ARG : path.join(__dirname, 'captures', HTML_ARG))
  : path.join(__dirname, 'captures', 'response.html');
const html = fs.readFileSync(HTML_PATH, 'utf8');
let src = require('./lib/challenge.js').parseChallenge(html).vm;
const ORIGINAL_SRC = src;   // kept for the sampled helper comparison at the end
console.log('capture            : ' + path.basename(HTML_PATH));
console.log('interpreter source : ' + src.length + ' chars, build sha '
  + crypto.createHash('sha256').update(src).digest('hex').slice(0, 12));

// ---- 2. sampled MBA simplification -----------------------------------------
const INT_OPS = new Set(['+', '-', '*', '&', '|', '^', '<<', '>>', '>>>']);
const UN_OPS = new Set(['~', '-', '+']);

/**
 * Is this subtree integer arithmetic over ATOMS?
 * An atom is an identifier or a member read (`X[U]`, `e.length`). Member reads
 * are treated as deterministic and evaluated once - true for this code, where
 * they are array/string indexing, and the rewrite is checked numerically
 * afterwards anyway. Calls are never atomised: they may have side effects.
 */
function pureInt(node, atoms, srcText) {
  switch (node.type) {
    case 'Literal':
      return typeof node.value === 'number' && Number.isFinite(node.value);
    case 'Identifier':
      atoms.set(srcText.slice(node.start, node.end), true);
      return true;
    case 'MemberExpression': {
      const t = srcText.slice(node.start, node.end);
      if (/[()]/.test(t)) return false;           // contains a call
      atoms.set(t, true);
      return true;
    }
    case 'UnaryExpression':
      return UN_OPS.has(node.operator) && pureInt(node.argument, atoms, srcText);
    case 'BinaryExpression':
      return INT_OPS.has(node.operator) && pureInt(node.left, atoms, srcText) && pureInt(node.right, atoms, srcText);
    case 'ParenthesizedExpression':
      return pureInt(node.expression, atoms, srcText);
    default:
      return false;
  }
}
/** replace each atom's source text with a synthetic variable so it can be fuzzed */
function atomise(text, atomList) {
  let out = text;
  const vars = [];
  atomList.forEach((a, i) => {
    const v = '__a' + i;
    vars.push(v);
    out = out.split(a).join(v);
  });
  return { text: out, vars };
}

const rnd32 = () => (Math.random() * 4294967296) | 0;

function sampleVectors(names, n) {
  const out = [];
  const interesting = [0, 1, -1, 2, 3, 4, 7, 8, 127, 128, 255, 256, 0x7fffffff, -0x80000000, 65535, 65536];
  for (let i = 0; i < n; i++) {
    const v = {};
    for (const nm of names) {
      v[nm] = i < interesting.length * 2 && Math.random() < 0.5
        ? interesting[(i + nm.length) % interesting.length]
        : rnd32();
    }
    out.push(v);
  }
  return out;
}

function evalExpr(text, names, vecs) {
  let f;
  try { f = new Function(...names, 'return (' + text + ');'); } catch (e) { return null; }
  const res = [];
  for (const v of vecs) {
    let r;
    try { r = f(...names.map((n) => v[n])); } catch (e) { return null; }
    if (typeof r !== 'number' || !Number.isFinite(r)) return null;
    res.push(r | 0); // the VM always coerces to int32 downstream
  }
  return res;
}

/**
 * Synthesise the simplification instead of guessing it.
 *
 * If the expression is a bitwise function of its atoms, every output bit depends
 * only on the corresponding input bits. Feeding the classic "column" constants
 * (0xAAAAAAAA / 0xCCCCCCCC / 0xF0F0F0F0) therefore exposes the whole truth table
 * in a single evaluation, and the table maps straight onto a minimal expression.
 * Anything derived this way is still checked on random vectors afterwards.
 */
const COLUMNS = [0xf0f0f0f0 | 0, 0xcccccccc | 0, 0xaaaaaaaa | 0];

const TT2 = {
  0x0: '0', 0x1: '~($a|$b)', 0x2: '~$a&$b', 0x3: '~$a', 0x4: '$a&~$b', 0x5: '~$b',
  0x6: '$a^$b', 0x7: '~($a&$b)', 0x8: '$a&$b', 0x9: '~($a^$b)', 0xa: '$b', 0xb: '~$a|$b',
  0xc: '$a', 0xd: '$a|~$b', 0xe: '$a|$b', 0xf: '-1',
};
const TT1 = { 0x0: '0', 0x1: '~$a', 0x2: '$a', 0x3: '-1' };

function sop3(table, vars) {
  // sum of products over the 8-entry truth table; checked numerically later
  const terms = [];
  for (let m = 0; m < 8; m++) {
    if (!(table & (1 << m))) continue;
    const lits = vars.map((v, i) => ((m >> (2 - i)) & 1 ? v : '~' + v));
    terms.push('(' + lits.join('&') + ')');
  }
  if (!terms.length) return '0';
  if (terms.length === 8) return '-1';
  return terms.join('|');
}

function synthesise(text, vars) {
  const n = vars.length;
  if (n < 1 || n > 3) return null;
  if (n === 3) {
    let f;
    try { f = new Function(...vars, 'return (' + text + ');'); } catch (e) { return null; }
    let r;
    try { r = f(COLUMNS[0], COLUMNS[1], COLUMNS[2]) | 0; } catch (e) { return null; }
    const table = r & 0xff;
    if (((table * 0x01010101) | 0) !== r) return null;
    return sop3(table, vars);
  }
  let f;
  try { f = new Function(...vars, 'return (' + text + ');'); } catch (e) { return null; }
  let r;
  try { r = f(...(n === 1 ? [COLUMNS[2]] : [COLUMNS[1], COLUMNS[2]])) | 0; } catch (e) { return null; }
  // collapse the 32 bits of the result to the truth table: all bit positions
  // carry the same pattern, so any nibble tells us the table
  const table = n === 1 ? (r & 3) : (r & 0xf);
  // ...but only if the result really is bit-uniform
  const rep = n === 1 ? (table * 0x55555555) | 0 : (table * 0x11111111) | 0;
  if (rep !== r) return null;
  const form = n === 1 ? TT1[table] : TT2[table];
  if (!form) return null;
  return form.split('$a').join(vars[0]).split('$b').join(vars[1] || vars[0]);
}

/** arithmetic fallbacks, for expressions that are not purely bitwise */
function candidates(names) {
  const c = [];
  const [a, b, d] = names;
  if (!names.length) return c;
  if (names.length === 1) {
    for (const k of [0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 255, 256, 2048, 4095]) {
      c.push(`${a}+${k}`, `${a}-${k}`, `${a}*${k}`);
    }
    c.push(a, `~${a}`, `-${a}`, `${a}|0`, `${a}*2`, `${a}*3`, `0`, `-1`, `1`);
    for (const k of [1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 2047, 4095]) {
      c.push(`${a}^${k}`, `${a}&${k}`, `${a}|${k}`);
    }
    return c;
  }
  if (names.length === 2) {
    c.push(`${a}+${b}`, `${a}-${b}`, `${b}-${a}`, `${a}*${b}`, `${a}+${b}+1`, `${a}-${b}-1`,
           `${a}+${b}*2`, `${a}*2+${b}`, `${a}+${b}+2`);
    for (const k of [1, 2, 3, 4, 8]) c.push(`${a}+${b}+${k}`, `${a}-${b}+${k}`);
    c.push(`${a}^${b}`, `${a}&${b}`, `${a}|${b}`, `~${a}^${b}`, `${a}&~${b}`, `~${a}&${b}`,
           `${a}|~${b}`, `~(${a}|${b})`, `~(${a}&${b})`, `~(${a}^${b})`);
    return c;
  }
  c.push(`${a}^${b}^${d}`, `${a}&${b}&${d}`, `${a}|${b}|${d}`, `${a}+${b}+${d}`,
         `(${a}&${b})|${d}`, `(${a}^${b})&${d}`, `${a}^(${b}&${d})`, `${a}+(${b}^${d})`,
         `${a}+${b}-${d}`, `${a}-${b}+${d}`);
  return c;
}

const rewrites = [];
let applied = 0;
for (let round = 1; round <= 4; round++) {
const ast = acorn.parse(src, { ecmaVersion: 2020, ranges: true, allowReturnOutsideFunction: true });
const taken = [];

(function walk(node, parent) {
  if (!node || typeof node.type !== 'string') return;
  if (node.type === 'BinaryExpression' || node.type === 'UnaryExpression') {
    const atoms = new Map();
    if (pureInt(node, atoms, src) && atoms.size <= 3) {
      const raw = src.slice(node.start, node.end);
      if (raw.length > 8 && /[~^&|]/.test(raw)) {
        // longest atoms first, so `X[U]` is not clobbered by `X`
        const atomList = [...atoms.keys()].sort((a, b) => b.length - a.length);
        const { text, vars } = atomise(raw, atomList);
        if (!/[.\[]/.test(text)) {                  // every atom really got replaced
          const vecs = sampleVectors(vars, SAMPLES);
          const base = evalExpr(text, vars, vecs);
          if (base) {
            const tried = [];
            const syn = synthesise(text, vars);
            if (syn) tried.push(syn);
            for (const cand of tried.concat(candidates(vars))) {
              const got = evalExpr(cand, vars, vecs);
              if (got && got.every((v, i) => v === base[i])) {
                // put the real operands back
                let real = cand;
                vars.forEach((v, i) => { real = real.split(v).join(atomList[i]); });
                if (real.length < raw.length) {
                  taken.push({ start: node.start, end: node.end, from: raw, to: real });
                  return;
                }
              }
            }
          }
        }
      }
    }
  }
  for (const k of Object.keys(node)) {
    if (k === 'start' || k === 'end' || k === 'range' || k === 'type') continue;
    const v = node[k];
    if (Array.isArray(v)) v.forEach((c) => walk(c, node));
    else if (v && typeof v.type === 'string') walk(v, node);
  }
})(ast, null);

// apply from the end so offsets stay valid; drop overlaps
taken.sort((x, y) => y.start - x.start);
let last = Infinity;
let roundCount = 0;
for (const t of taken) {
  if (t.end > last) continue;
  src = src.slice(0, t.start) + t.to + src.slice(t.end);
  rewrites.push(t);
  last = t.start;
  applied++; roundCount++;
}
console.log('  round ' + round + ': ' + roundCount + ' rewrites');
if (!roundCount) break;
}
console.log('MBA rewrites applied : ' + applied + '   (each passed ' + SAMPLES + ' sampled int32 vectors)');

// ---- 3. rename what the analysis identified --------------------------------
const NAMES = {
  $J: 'keystreamBlock',      // ARX block function, 14 rounds
  pm: 'readU32BE',           // big-endian 32-bit read
  jB: 'randomBytes',
  zV: 'pushWords',
  d3: 'dispatchLoop',
  Xa: 'readVarint',
  TV: 'writeStream',
  Qi: 'writeStreamAlt',
  Uy: 'decodeCallFrame',
  dC: 'queueShift',
  NL: 'vmThrow',
  hu: 'jumpTo',
  Ru: 'emitBytes',
  lP: 'emitFromSlot',
  X7: 'makeStream',
};
let renamed = 0;
if (RENAME) {
  for (const [from, to] of Object.entries(NAMES)) {
    const re = new RegExp('(?<![\\w$.])' + from.replace('$', '\\$') + '(?![\\w$])', 'g');
    const before = src;
    src = src.replace(re, to);
    if (src !== before) renamed++;
  }
  console.log('entities renamed     : ' + renamed + ' of ' + Object.keys(NAMES).length);
}

// ---- 4. prettier -----------------------------------------------------------
const OUT_ARG = optOf('out', 'vm-deobfuscated.js'); // --out= to avoid clobbering the canonical file
const RAW_OUT = path.isAbsolute(OUT_ARG) ? OUT_ARG : path.join(__dirname, 'lifted-source', OUT_ARG);
const EMPTY_IGNORE = path.join(require('os').tmpdir(), 'sgss-empty-prettierignore');
fs.writeFileSync(EMPTY_IGNORE, '');
fs.writeFileSync(RAW_OUT, src);
// prettier is optional and lives wherever this machine keeps it; a fixed path
// turns "no formatting" into a crash.
const PRETTIER = [
  path.join(__dirname, 'node_modules', '.bin', 'prettier'),
  path.join(__dirname, '..', 'node_modules', '.bin', 'prettier'),
  path.join(__dirname, '..', '..', 'node_modules', '.bin', 'prettier'),
].find((c) => fs.existsSync(c)) || 'prettier';

try {
  const pretty = execFileSync(
    PRETTIER,
    ['--no-config', '--ignore-path', EMPTY_IGNORE, '--print-width', '110', '--parser', 'babel', RAW_OUT],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  );
  fs.writeFileSync(RAW_OUT, pretty);
  console.log('prettier             : ok, ' + pretty.split('\n').length + ' lines');
} catch (e) {
  console.log('prettier             : skipped (' + String(e.message).split('\n')[0] + ')');
}

// ---- 5. report -------------------------------------------------------------
const REPORT = path.join(__dirname, 'lifted-source', 'vm-deobfuscation-report.txt');
const byPattern = new Map();
for (const r of rewrites) {
  const k = r.to.replace(/[A-Za-z_$][\w$]*/g, 'x');
  byPattern.set(k, (byPattern.get(k) || 0) + 1);
}
const lines = [];
lines.push('MBA rewrites, each passed ' + SAMPLES + ' sampled int32 vectors');
lines.push('='.repeat(78));
lines.push('');
lines.push('by resulting shape:');
for (const [k, v] of [...byPattern].sort((a, b) => b[1] - a[1])) lines.push('  ' + String(v).padStart(4) + '  ' + k);
lines.push('');
lines.push('full list (' + rewrites.length + '):');
for (const r of rewrites.slice().reverse()) {
  lines.push('  ' + r.from.replace(/\s+/g, ' ') + '\n      ->  ' + r.to);
}
fs.writeFileSync(REPORT, lines.join('\n') + '\n');

console.log('');
console.log('wrote ' + path.basename(RAW_OUT) + ' and vm-deobfuscation-report.txt');
console.log('');
console.log('top rewrite shapes:');
for (const [k, v] of [...byPattern].sort((a, b) => b[1] - a[1]).slice(0, 10)) {
  console.log('  ' + String(v).padStart(4) + '  ' + k);
}

// ---- 6. sampled helper comparison ------------------------------------------
// Pull the self-contained numeric helpers out of BOTH sources and fuzz them
// against each other. These are the functions the rewrites touched most.
(function verify() {
  const orig = ORIGINAL_SRC;
  const deob = fs.readFileSync(RAW_OUT, 'utf8');
  // The pairs are (original name, renamed name). Both are build-scoped: a new
  // observed rebuilds changed these names, so on a build this analysis has not
  // been redone for, `grab` finds nothing and the check reports 0/0 rather than
  // claiming a pass. See docs/13-builds.md.
  const pairs = [
    ['$J', 'keystreamBlock', 5],
    ['pm', 'readU32BE', 5],
  ];
  const grab = (text, name) => {
    const i = text.indexOf(name + ' = function');
    const j = i < 0 ? text.indexOf(name + '=function') : i;
    if (j < 0) return null;
    let k = text.indexOf('{', j), depth = 0, end = -1;
    for (let x = k; x < text.length; x++) {
      if (text[x] === '{') depth++;
      else if (text[x] === '}') { depth--; if (!depth) { end = x + 1; break; } }
    }
    if (end < 0) return null;
    return text.slice(text.indexOf('function', j), end);
  };
  let checked = 0, ok = 0;
  for (const [oname, dname, arity] of pairs) {
    const A = grab(orig, oname), B = grab(deob, dname);
    if (!A || !B) { console.log('  ' + dname + ': not extractable, skipped'); continue; }
    let fa, fb;
    try { fa = (0, eval)('(' + A + ')'); fb = (0, eval)('(' + B + ')'); } catch (e) { console.log('  ' + dname + ': eval failed'); continue; }
    let same = true;
    for (let i = 0; i < 5000; i++) {
      const args = [];
      for (let k = 0; k < arity; k++) args.push(k === 1 ? [0, 0, (Math.random() * 4294967296) | 0, (Math.random() * 4294967296) | 0] : (Math.random() * 4294967296) | 0);
      let ra, rb;
      try { ra = JSON.stringify(fa(...args)); rb = JSON.stringify(fb(...args)); } catch (e) { continue; }
      if (ra !== rb) { same = false; break; }
    }
    checked++; if (same) ok++;
    console.log('  ' + dname.padEnd(16) + (same ? 'MATCH on 5000 sampled vectors' : 'MISMATCH'));
  }
  console.log('sampled helper check : ' + ok + '/' + checked + ' helpers passed');
})();
