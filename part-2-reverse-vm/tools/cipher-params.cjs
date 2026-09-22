'use strict';
// ============================================================================
//  cipher-params.cjs — read a build's program-image stream cipher out of its own
//  interpreter, instead of hardcoding it.
//
//  static-disasm.cjs decrypts the bytecode with a Speck-style ARX construction
//  whose parameters were written down once, for 885c049eda50: 14 rounds, round
//  constant 1650, rotation 3. On c348580f3670 those are wrong — it uses 16 rounds
//  and constant 2738 — and a wrong keystream is not a degraded result, it is
//  noise. The disassembler decoded the first instruction as opcode 91 where the
//  dispatcher actually runs 484.
//
//  The function is found by shape. It is the only one in the interpreter that
//  rotates two 32-bit words right by eight and returns eight bytes:
//
//     d = (d >>> 8) | (d << 24)        ... twice, for the data and key halves
//     return [(n >>> 24) & 255, ..., (d >>> 0) & 255]
//
//  Its parameters are not all literals — each build makes a different subset
//  constant and passes the rest in, so the call site has to be read too:
//
//     old   $J(1650, [0, 0, Y[1], Y[2]], 3, K.Y, K.L)      constant + rotation passed
//     new   n4(0, 16, [0, 0, k[1], k[2]], F.P, F.h)        rounds passed, constant inline
//
//  Verified by an oracle that needs no key: the first instruction of the program
//  is the string-alphabet loader (tools/opcode-trace.cjs), and the operand reader
//  encodes an opcode above 127 as a lead byte (op >> 2) | 0x80. So the first
//  plaintext byte is known before anything is decrypted.
//
//     node cipher-params.cjs --html=<capture>.html
// ============================================================================
const fs = require('fs');
const path = require('path');
const { parseChallenge } = require('./lib/challenge.js');

const argv = process.argv.slice(2);
const optOf = (n, d) => { const h = argv.find((a) => a.startsWith('--' + n + '=')); return h ? h.slice(n.length + 3) : d; };

/**
 * The keystream block function, in one implementation for every build seen.
 *
 * The two builds write the round body in a different order — the new one folds
 * the key xor in earlier — but the dataflow is identical, and one function with
 * three parameters reproduces both exactly (verified against the oracle below).
 */
function keystream(k1, k2, dataHi, dataLo, rounds, roundConst, rot) {
  let B = k1 | 0, z = k2 | 0, d = dataHi | 0, n = dataLo | 0;
  for (let F = 0; F < rounds; F++) {
    d = (d >>> 8) | (d << 24);
    d = (d + n) | 0;
    d ^= (B + roundConst) | 0;
    z = (z >>> 8) | (z << 24);
    n = (n << rot) | (n >>> (32 - rot));
    n ^= d;
    z = (z + B) | 0;
    B = (B << rot) | (B >>> (32 - rot));
    z ^= (F + roundConst) | 0;
    B ^= z;
  }
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255,
    (d >>> 24) & 255, (d >>> 16) & 255, (d >>> 8) & 255, d & 255];
}

// The rotate-by-8 is the one step every build writes, but not the one every
// build writes the same way: 885c049eda50 hardcodes `Y<<24`, d4a6b4f0a2a5
// passes the amount in as a parameter (`J<<f`, f=24 from the call site).
// Match either, and let the call-site binding below turn the parameter into
// the number. Parentheses are optional because the shipped source has none.
// Third time this signature has needed widening, and each time in the same
// direction. 885c049eda50 wrote the rotate-by-8 as `Y>>>8 | Y<<24`, both
// literal. d4a6b4f0a2a5 passed the LEFT amount in as a parameter. 80056f9da7b2
// passes BOTH in. So match a rotate of one variable by anything, and let the
// call-site binding below turn the parameters into numbers — the shape that
// survives is `x >>> A | x << B`, not the constants in it.
const ROTR8 = /\(?\s*([A-Za-z_$][\w$]*)\s*>>>\s*(?:\d+|[A-Za-z_$][\w$]*)\s*\)?\s*\|\s*\(?\s*\1\s*<<\s*(?:\d+|[A-Za-z_$][\w$]*)\s*\)?/g;

/** find the ARX function and its call site, both by shape */
function locate(src) {
  const acorn = require('acorn');
  const ast = acorn.parse(src, { ecmaVersion: 2020, ranges: true, allowReturnOutsideFunction: true });
  const cands = [];
  const calls = [];

  (function walk(n, name) {
    if (!n || typeof n.type !== 'string') return;
    if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier') name = n.id.name;
    if (n.type === 'FunctionExpression' || n.type === 'FunctionDeclaration') {
      const body = src.slice(n.start, n.end);
      ROTR8.lastIndex = 0;
      const rots = (body.match(ROTR8) || []).length;
      // Eight byte extractions is the signature of the returned block. Count
      // `& 255`, not `>>> k & 255`: the old build writes the two low bytes with
      // no shift at all (`d & 255`), so a shift-anchored count sees six.
      const bytes = (body.match(/&\s*255/g) || []).length;
      if (rots >= 2 && bytes >= 8) cands.push({ name: (n.id && n.id.name) || name, node: n, src: body });
    }
    if (n.type === 'CallExpression' && n.callee.type === 'Identifier') calls.push(n);
    for (const k of Object.keys(n)) {
      if (['start', 'end', 'range', 'type'].includes(k)) continue;
      const v = n[k];
      if (Array.isArray(v)) v.forEach((c) => walk(c, name));
      else if (v && typeof v.type === 'string') walk(v, name);
    }
  })(ast, null);

  // Every function enclosing the block function matches the same shape, so take
  // the innermost one — the shortest source that still carries the signature.
  cands.sort((a, b) => a.src.length - b.src.length);
  const found = cands[0];
  if (!found) return null;
  // the call that matters passes the key as an array literal
  const site = calls.find((c) => c.callee.name === found.name
    && c.arguments.some((a) => a.type === 'ArrayExpression'));
  return { fn: found, site, src };
}

/**
 * Bind the function's parameters to whatever the call site passes as a literal,
 * then read the three numbers off the substituted text.
 */
function params(src) {
  const loc = locate(src);
  if (!loc) return { err: 'no ARX function found by shape' };
  const { fn, site } = loc;
  const bound = new Map();
  if (site) {
    fn.node.params.forEach((p, i) => {
      const a = site.arguments[i];
      if (p.type === 'Identifier' && a && a.type === 'Literal' && typeof a.value === 'number') {
        bound.set(p.name, a.value);
      }
    });
  }
  let body = fn.src;
  for (const [name, value] of bound) body = body.replace(new RegExp('\\b' + name + '\\b', 'g'), String(value));

  // `for (F = 0; F < 16; F++)` on one build, `while (h < 14)` on the other
  const rounds = (/<\s*(\d+)\s*[;)]/.exec(body) || [])[1];
  const rotM = /<<\s*(\d+)\s*\)?\s*\|\s*\(?\s*[A-Za-z_$][\w$]*\s*>>>\s*(\d+)/.exec(body);
  const rot = rotM && Number(rotM[1]) + Number(rotM[2]) === 32 ? rotM[1] : null;
  // The round constant is the number added inside the two `^= x + C` steps, and
  // that is how to find it — not by magnitude. A width filter looked safe while
  // the only known values were 1650 and 2738; d4a6b4f0a2a5 uses **72**, which a
  // three-digit floor silently drops, and the tool then reports a plausible
  // wrong constant instead of failing.
  const xored = {};
  for (const m of body.matchAll(/\^=?\s*\(?\s*[A-Za-z_$][\w$]*\s*\+\s*(\d+)/g)) xored[m[1]] = (xored[m[1]] || 0) + 1;
  let roundConst = Object.entries(xored).sort((a, b) => b[1] - a[1] || b[0] - a[0])[0];
  if (!roundConst) {
    // fallback: the constant is added twice per round, anything else once
    const adds = {};
    for (const m of body.matchAll(/\+\s*(\d{2,6})\b/g)) adds[m[1]] = (adds[m[1]] || 0) + 1;
    roundConst = Object.entries(adds).sort((a, b) => b[1] - a[1] || b[0] - a[0])[0];
  }

  return {
    fnName: fn.name,
    callSite: site ? src.slice(site.start, site.end).replace(/\s+/g, ' ') : null,
    bound: Object.fromEntries(bound),
    rounds: rounds ? Number(rounds) : null,
    rot: rot ? Number(rot) : null,
    roundConst: roundConst ? Number(roundConst[0]) : null,
  };
}

/**
 * Does this parameter set decrypt the program?
 *
 * The first instruction is the alphabet loader, whose opcode number the profile
 * already carries, and an opcode above 127 begins with the byte (op >> 2) | 0x80.
 * One byte is enough — a wrong keystream fails it with probability 255/256.
 */
function verify(payload, firstOpcode, p) {
  const P3 = Array.from(Buffer.from(payload.slice(3), 'base64'));
  const L = ((P3[0] << 24) | (P3[1] << 16) | (P3[2] << 8) | P3[3]) >>> 0;
  const plain = P3[4] ^ keystream(0, 0, 0, L, p.rounds, p.roundConst, p.rot)[4];
  const want = firstOpcode > 127 ? ((firstOpcode >> 2) | 0x80) : firstOpcode;
  return { ok: plain === want, plain, want, initialKey: L, bytes: P3.length };
}

module.exports = { keystream, params, verify, locate };

if (require.main !== module) return;

const htmlArg = optOf('html', 'response.html');
const htmlPath = path.isAbsolute(htmlArg) ? htmlArg : path.join(__dirname, 'captures', htmlArg);
const html = fs.readFileSync(htmlPath, 'utf8');
const ch = parseChallenge(html);
const crypto = require('crypto');
const sha = crypto.createHash('sha256').update(ch.vm).digest('hex').slice(0, 12);

// the parameters live in the interpreter, and the lifted source is what is
// readable — the shipped text is one line and acorn parses either
let src = ch.vm;
const { KNOWN_BUILDS } = require('./lib/builds.js');
const known = KNOWN_BUILDS[sha];
// --readable= points at a deobfuscated copy explicitly; without one, a build we
// already know names its own. The shipped interpreter is a single line and the
// shape search does not survive it, so this is not optional in practice.
const readableArg = optOf('readable', known && known.readable);
if (readableArg) {
  // a bare name is looked up next to the other lifted sources; anything with a
  // separator in it is a path the caller meant literally
  const lifted = path.isAbsolute(readableArg) ? readableArg
    : readableArg.includes(path.sep) ? path.resolve(readableArg)
    : path.join(__dirname, 'lifted-source', readableArg);
  if (fs.existsSync(lifted)) src = fs.readFileSync(lifted, 'utf8');
  else if (optOf('readable', null)) { console.error('no readable interpreter at ' + lifted); process.exit(1); }
}

const p = params(src);
console.log('build       : ' + sha);
if (p.err) { console.error('failed      : ' + p.err); process.exit(1); }
console.log('function    : ' + p.fnName + '   (found by shape)');
console.log('call site   : ' + (p.callSite || '(none found — parameters must all be literals)'));
console.log('bound params: ' + JSON.stringify(p.bound));
console.log('');
console.log('rounds      : ' + p.rounds);
console.log('round const : ' + p.roundConst);
console.log('rotation    : ' + p.rot);

if (known) {
  const v = verify(ch.payload, known.alphabet, p);
  console.log('');
  console.log('program     : ' + v.bytes + ' bytes, initial key ' + v.initialKey);
  console.log('oracle      : first plaintext byte ' + v.plain + ', expected ' + v.want
    + ' for opcode ' + known.alphabet + '  -> ' + (v.ok ? 'MATCH' : 'MISMATCH'));
  if (!v.ok) process.exit(1);
}
