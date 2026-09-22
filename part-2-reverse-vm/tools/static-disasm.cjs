'use strict';
// ============================================================================
//  static-disasm.cjs — disassemble challenge bytecode without executing it.
//
//  This command does not run or patch the challenge, so its self-integrity check
//  and anti-debug timer do not fire during disassembly. It reads a saved response
//  and a matching capture-specific profile produced separately:
//
//     program image   = base64decode(p.slice(3))     ("VrI" on the reference capture)
//     initial stream key = the first 32 bits of the image, in the clear
//     IV1 / IV2       = operands of SETPROP keyCtl[1] / keyCtl[2]
//     re-key          = the 32 clear bits right after SETPROP keyCtl[2]
//     keystream       = our own reimplementation of the VM's ARX block function
//     opcode roles and operand layouts = the capture-specific profile
//
//  The traversal and the opcode decoder are adapted from
//  from-scratch-2026-07-25/harness/walk.js, which needed artifacts from an
//  instrumented run. This command remains static, but creating a full profile can
//  require a prior instrumented run and manual bootstrap for an unseen build.
//
//     node static-disasm.cjs --html=response.html [--profile=profile-<build>-<capture>.json]
// ============================================================================
const fs = require('fs');
const path = require('path');
const SGSS = require('./sgss-token.js');

// ---- 1. saved challenge input -----------------------------------------------
const HTML_ARG = (process.argv.find((a) => a.startsWith('--html=')) || '').slice(7);
const HTML_PATH = HTML_ARG ? (path.isAbsolute(HTML_ARG) ? HTML_ARG : path.join(__dirname, 'captures', HTML_ARG)) : path.join(__dirname, 'captures', 'response.html');
const html = fs.readFileSync(HTML_PATH, 'utf8');
// The bytecode is located by parsing, not by cutting at the next `;\n`: a live
// page is minified onto one line, so that cut overshoots by thousands of
// characters and the eval dies on a stray semicolon.
const _ch = require('./lib/challenge.js').parseChallenge(html);
const p = _ch.payload;
// The sha identifies the interpreter build. The opcode profile is resolved by
// capture below because handlers installed at run time can receive different
// numbers in two responses of the same build. An unknown capture must fail loudly
// rather than inherit neighbouring answers.
const BUILD_SHA = require('crypto').createHash('sha256').update(_ch.vm).digest('hex').slice(0, 12);
const BUILD_TAG = p.slice(0, 3); // "VrI" — matches the VM export knitsail.VrI_
const P3 = Array.from(Buffer.from(p.slice(3), 'base64'));
const MASK = 7; // the reader indexes the 8-byte keystream with `& 7`
const TOTAL = P3.length * 8;

console.log('response           : ' + path.basename(HTML_PATH));
console.log('payload            : ' + p.length + ' chars, build tag ' + JSON.stringify(BUILD_TAG));
console.log('program image      : ' + P3.length + ' bytes = ' + TOTAL + ' bits');

// ---- 2. bit reader over the encrypted stream ------------------------------
// The cipher is build-scoped: 885c049eda50 uses 14 rounds and round constant
// 1650, c348580f3670 uses 16 and 2738. With a profile loaded the numbers come
// from it — read out of that build's own interpreter and checked against a
// plaintext byte that is known before anything is decrypted (cipher-params.cjs).
// sgss-token.js retains the reference values as implementation defaults, but the
// walk below refuses to proceed without a suitable profile.
let $J = (e, U, X, blk, L) => SGSS.keystreamBlock(U[2], U[3], blk, L);

class R {
  constructor(pos, L, iv1, iv2) {
    this.pos = pos; this.L = L; this.iv1 = iv1; this.iv2 = iv2; this.blk = -1; this.Pk = null;
  }
  read(n, enc = true) {
    let M = n, h = this.pos, f = 0;
    while (M > 0) {
      const F = h >> 3;
      if (F >= P3.length) return null;
      const v = h % 8, d = 8 - v;
      let H = P3[F];
      const V = d < M ? d : M;
      if (enc) {
        const b = h >> 6;
        if (b !== this.blk) { this.blk = b; this.Pk = $J(1650, [0, 0, this.iv1, this.iv2], 3, b, this.L); }
        H ^= this.Pk[F & MASK];
      }
      h += V;
      f |= ((H >> (8 - v - V)) & ((1 << V) - 1)) << (M - V);
      M -= V;
    }
    this.pos = h;
    return f;
  }
  V() { const b = this.read(8); if (b === null) return null; if (b & 0x80) { const e = this.read(2); return ((b ^ 0x80) << 2) + e; } return b; }
  A() { const b = this.read(8); if (b === null) return null; if (b & 0x80) { const e = this.read(8); return (b & 0x7f) | (e << 7); } return b; }
  B() { return this.read(8); }
  rekey() { const k = this.read(32, false); this.L = k; this.blk = -1; return k; }
}

// ---- 3. decoder ------------------------------------------------------------
const ALIAS = { 22: 402, 14: 192, 115: 149, 110: 192, 27: 262 };
const lit = (S, n) => (typeof S[n] === 'number' ? String(S[n]) : typeof S[n] === 'string' ? JSON.stringify(S[n]) : 's' + n);

// LOAD_STR encoding, solved against a known target (see solve-strings.cjs):
//   a = 0; char[i] = alphabet[a = (a + delta[i]) % alphabet.length]
let ALPHABET = null;
function decodeStr(deltas) {
  if (!ALPHABET || !ALPHABET.length) return null;
  const L = ALPHABET.length;
  let a = 0, out = '';
  for (const d of deltas) { a = (a + d) % L; out += String.fromCharCode(ALPHABET[a]); }
  return out;
}

// Opcode numbers for program-installed handlers are permuted PER RESPONSE. Each
// DEF_OPCODE carries the handler's source, and every stream read in that source
// is one operand — so the layout can be learned from the program itself.
const LEARNED = new Map();      // opcode number -> {plan, src}

// A table derived from THIS build's own handlers, seeded from opcode-table.cjs.
// The hardcoded cases below are 885c049eda50 numbers and mean something else on
// any other build, so without a seed the walk stops on its first instruction
// there (measured: 1 instruction, 0.0% coverage). See docs/13-builds.md.
// A capture profile (tools/build-profile.cjs) carries BOTH halves of what a walk
// needs on a build these cases were not written for: the operand layouts, and
// which opcode number plays which semantic role. With one loaded, the hardcoded
// numbers below stop being opcode numbers and become role names — every opcode
// this build does not map to a role decodes from its layout instead.
let PROFILE = null;
const ROLE_MAP = new Map();   // this build's opcode -> the role's canonical number
const VARIABLE = new Set();   // opcodes whose operand count is a run-time value
const EMIT = new Map();       // opcode -> the record-writing helper it calls
let PC_SLOT = 202;            // register that holds the program counter
let KEYCTL_SLOT = 28;         // writing here reloads the stream key
{
  // --cipher=rounds,const,rot is the small half of a profile: on a build whose
  // cipher differs, everything downstream decodes to plausible-looking noise
  // without it. cipher-params.cjs prints the three numbers.
  const cip = (process.argv.find((a) => a.startsWith('--cipher=')) || '').slice(9);
  if (cip) {
    const [rounds, roundConst, rot] = cip.split(',').map(Number);
    SGSS.cipherParams({ rounds, roundConst, rot });
    console.log('cipher             : rounds ' + rounds + ', const ' + roundConst + ', rot ' + rot + '   (given)');
  }
  // Resolve the profile, and resolve it by CHALLENGE rather than by build.
  //
  // Allowing a walk with no profile used to produce a silently wrong listing:
  // the defaults below are build 885c049eda50's, so on 80056f9da7b2 the decoder
  // read the counter from slot 202 (a data register there), knew no opcode roles,
  // and printed 27.5 % coverage and six emit instructions for a program that has
  // twelve emit opcodes. The command now exits when no suitable profile exists.
  //
  // Running with the RIGHT BUILD'S profile from a DIFFERENT CHALLENGE is the
  // quieter version of the same mistake, and it is the one that caught me.
  // Opcode numbers for the handlers the program installs itself are permuted per
  // response, so a profile is a property of the capture, not only of the build.
  // Two challenges of d4a6b4f0a2a5 taken an hour apart: with its own profile the
  // 08-28 capture decodes 63.3 % and 106 emit instructions; with the 08-27
  // profile of the same build, 45.5 % and 56. Nothing errors either way.
  const RECORDS = path.join(__dirname, 'records');
  const capBase = path.basename(HTML_PATH).replace(/\.html$/, '');
  let arg = (process.argv.find((a) => a.startsWith('--profile=')) || '').slice(10);
  if (!arg) {
    const exact = ['profile-' + BUILD_SHA + '-' + capBase + '.json', 'profile-' + capBase + '.json']
      .find((f) => fs.existsSync(path.join(RECORDS, f)));
    if (exact) { arg = path.join(RECORDS, exact); console.log('profile            : ' + exact + '  (this challenge)'); }
    else if (fs.existsSync(path.join(RECORDS, 'profile-' + BUILD_SHA + '.json'))) {
      arg = path.join(RECORDS, 'profile-' + BUILD_SHA + '.json');
      console.log('profile            : profile-' + BUILD_SHA + '.json  (build-wide)');
      console.log('  WARNING          : built from a different challenge of this build. Opcode');
      console.log('                     numbers for program-installed handlers are permuted per');
      console.log('                     response, so the listing will under-read. Generate one for');
      console.log('                     this capture: node build-profile.cjs --html=' + path.basename(HTML_PATH)
        + ' --out=profile-' + BUILD_SHA + '-' + capBase + '.json');
    } else {
      console.error('no profile for ' + path.basename(HTML_PATH) + '. Run:');
      console.error('  node build-profile.cjs --html=' + path.basename(HTML_PATH)
        + ' --out=profile-' + BUILD_SHA + '-' + capBase + '.json');
      process.exit(1);
    }
  }
  {
    PROFILE = JSON.parse(fs.readFileSync(path.isAbsolute(arg) ? arg
      : path.join(__dirname, 'records', arg), 'utf8'));
    const R_ = PROFILE.roles || {};
    PC_SLOT = R_.programCounter != null ? R_.programCounter : PC_SLOT;
    KEYCTL_SLOT = R_.keyCtlSlot != null ? R_.keyCtlSlot : KEYCTL_SLOT;
    for (const op of PROFILE.variableLayout || []) VARIABLE.add(op);
    for (const [op, h] of Object.entries(PROFILE.emit || {})) EMIT.set(Number(op), h);
    for (const op of R_.alphabet || []) ROLE_MAP.set(op, 262);
    for (const op of R_.string || []) ROLE_MAP.set(op, 402);
    for (const op of R_.rekeyVia || []) ROLE_MAP.set(op, 501);
    for (const op of R_.defOpcode || []) ROLE_MAP.set(op, 149);
    // Both call forms consume operands identically; only the listing text differs.
    for (const op of R_.variadic || []) ROLE_MAP.set(op, 192);
    // The profile splits the control-flow group into the three roles a walk has
    // to tell apart; the split is done there, where the handler sources are.
    const L = PROFILE.layouts || {};
    const CANON = { call: 346, cond: 451, ret: 485 };
    const notes = [];
    for (const k of ['call', 'cond', 'ret']) {
      const ops = R_[k] || [];
      for (const op of ops) ROLE_MAP.set(op, CANON[k]);
      notes.push(k + '=' + (ops.length ? ops.join('/') : 'not found'));
    }
    const C = PROFILE.cipher;
    if (C && !C.err && C.rounds && C.roundConst && C.rot) {
      const { keystream } = require('./cipher-params.cjs');
      $J = (e, U, X, blk, Lk) => keystream(U[2], U[3], blk, Lk, C.rounds, C.roundConst, C.rot);
      console.log('cipher             : ' + C.fn + '  rounds ' + C.rounds + ', const ' + C.roundConst
        + ', rot ' + C.rot + (C.verified ? '   (verified)' : '   (UNVERIFIED)'));
    }
    console.log('profile            : build ' + PROFILE.build + ', ' + Object.keys(L).length + ' layouts');
    console.log('  roles mapped     : alphabet=' + (R_.alphabet || []).join('/') + ' string=' + (R_.string || []).join('/')
      + ' rekey=' + (R_.rekeyVia || []).join('/') + ' def-opcode=' + (R_.defOpcode || []).join('/')
      + ' variadic=' + (R_.variadic || []).join('/') + ' pc-slot=' + PC_SLOT
      + ' keyctl-slot=' + KEYCTL_SLOT);
    console.log('  control flow     : ' + notes.join('  '));
  }
}
{
  const arg = PROFILE ? null : (process.argv.find((a) => a.startsWith('--table=')) || '').slice(8);
  if (arg) {
    const t = JSON.parse(fs.readFileSync(path.resolve(arg), 'utf8'));
    const rows = t.table || t;
    let n = 0;
    for (const [op, d] of Object.entries(rows)) {
      const layout = typeof d === 'string' ? d : d.layout;
      if (!layout) continue;
      LEARNED.set(Number(op), { plan: layout.split(''), src: 'derived: ' + layout });
      n++;
    }
    console.log('seeded layouts     : ' + n + ' from ' + path.basename(arg));
  }
}
if (PROFILE) {
  let n = 0;
  for (const [op, layout] of Object.entries(PROFILE.layouts || {})) {
    if (!layout) continue;
    LEARNED.set(Number(op), { plan: layout.split(''), src: 'profile: ' + layout });
    n++;
  }
  console.log('  layouts seeded   : ' + n);
}
let keyCtlSeen = 0;
const keyIdxRegs = new Set();   // the two registers that address a key block's fields
// Some handlers do not read operands with a literal `z(` — they delegate to an
// interpreter helper that reads for them. These three cover the families that
// matter, and their read pattern is recovered from the helper's own source.
function learnLayout(target, src) {
  if (typeof src !== 'string') return;
  // With a profile, the layout of an installed handler is read the same way the
  // profile's own layouts were — by parsing it against THIS build's operand
  // reader and state aliases. The patterns below name the old build's helpers
  // (`pm`, `lP`, `Ru`, `z`) and mean nothing anywhere else.
  if (PROFILE) {
    try {
      const { deriveLayout } = require('./opcode-table.cjs');
      const d = deriveLayout(src, PROFILE.primitives.operandReader,
        new Set(PROFILE.primitives.stateAliases || []));
      if (d && d.layout) { LEARNED.set(target, { plan: d.layout.split(''), src }); return; }
    } catch (e) { /* fall through to the old-build patterns */ }
  }
  let m;
  //   pm(8, N, a, 2, K)  ->  one varint (destination slot) then N raw bytes
  if ((m = /\bpm\(\s*8\s*,\s*(\d+)\s*,\s*a\s*,\s*2\s*,\s*\d+\s*\)/.exec(src))) {
    LEARNED.set(target, { plan: ['V', ...Array(Number(m[1])).fill('B')], src });
    return;
  }
  //   lP(a, K) / Ru(K, a)  ->  two varints each (see the helpers' sources)
  if (/\blP\(\s*a\s*,/.test(src) || /\bRu\(\s*\d+\s*,\s*a\s*\)/.test(src)) {
    LEARNED.set(target, { plan: ['V', 'V'], src });
    return;
  }
  const reads = (src.match(/z\(|Xa\(/g) || []).length;
  LEARNED.set(target, { plan: Array(reads).fill('V'), src });
}

function decode(r, S) {
  const raw = r.V();
  if (raw === null) return null;
  // With a profile, only opcodes the profile gives a ROLE take a semantic case;
  // everything else decodes from its layout. Without one, the old build's own
  // aliases apply. Mixing the two would be worse than either: an unmapped opcode
  // that happens to collide with a case number would decode as that case.
  const op = PROFILE
    ? (ROLE_MAP.has(raw) ? ROLE_MAP.get(raw) : -1)
    : (ALIAS[raw] !== undefined ? ALIAS[raw] : raw);
  const at = r.pos;
  const rec = { op: raw, canon: op };
  switch (op) {
    case 5: { const o = r.V(), k = r.V(), d = r.V(); S[d] = undefined; rec.t = `s${d} = s${o}[${lit(S, k)}]`; break; }
    case 8: { const d = r.V(), v = r.B(); S[d] = v; rec.t = `s${d} = ${v}`; break; }
    case 49: { const d = r.V(), v = (r.B() << 8) | r.B(); S[d] = v; rec.t = `s${d} = ${v}`; break; }
    case 459: { const d = r.V(); const v = ((r.B() << 24) | (r.B() << 16) | (r.B() << 8) | r.B()) >>> 0; S[d] = v; rec.t = `s${d} = ${v}`; if (d === PC_SLOT) { rec.jump = v; rec.t += '   // JUMP'; } break; }
    case 88: { const s = r.V(), d = r.V(); S[d] = S[s]; rec.t = `s${d} = s${s}`; break; }
    case 184: { const s = r.V(), d = r.V(); S[d] = undefined; rec.t = `s${d} += s${s}`; break; }
    case 141: { const s = r.V(), d = r.V(); S[d] = undefined; rec.t = `s${d} = "" + s${s}`; break; }
    case 285: { const a = r.V(), b = r.V(), d = r.V(); S[d] = undefined; rec.t = `s${d} = s${a} || s${b}`; break; }
    case 430: { const a = r.V(), b = r.V(), d = r.V(); S[d] = undefined; rec.t = `s${d} = +(s${a} == s${b})`; break; }
    case 37: { const a = r.V(), b = r.V(), d = r.V(); S[d] = undefined; rec.t = `s${d} = +(s${a} > s${b})`; break; }
    case 10: { const s = r.V(), d = r.V(); S[d] = undefined; rec.t = `s${d} *= s${s}`; break; }
    case 11: { const s = r.V(), d = r.V(); S[d] = undefined; rec.t = `s${d} -= s${s}`; break; }
    case 153: { const s = r.V(), n = r.B(), d = r.V(); S[d] = undefined; rec.t = `s${d} = s${s} >>> ${n}`; break; }
    case 123: { const a = r.V(), b = r.V(), d = r.V(); S[d] = undefined; rec.t = `s${d} = (s${a} in s${b})`; break; }
    case 451: { const c = r.V(), t = r.V(); rec.t = `if (s${c}) pc = s${t}`; rec.cond = t; break; }
    case 346: { const s = r.V(); rec.t = `call sub @ ${S[s] !== undefined ? S[s] : 's' + s}`; rec.call = S[s]; break; }
    case 101: { const s = r.V(); rec.t = `removeEventListener(s${s})`; break; }
    case 140: { const s = r.V(), d = r.V(); S[d] = undefined; rec.t = `s${d} = splice(s${s})`; break; }
    case 149: {
      const s = r.V(), d = r.V();
      learnLayout(d, S[s]);
      // A handler installed now can itself hold a role — DEF_OPCODE installs a
      // second copy of DEF_OPCODE under another number, and a walk that only
      // knows the profile's numbers stops there. The source is in hand, so ask.
      if (PROFILE && typeof S[s] === 'string') {
        try {
          const { roleOfSource } = require('./build-profile.cjs');
          const role = roleOfSource(S[s], new Set(PROFILE.primitives.stateAliases || []), PC_SLOT);
          const CANON = { defOpcode: 149, variadic: 192, string: 402 };
          if (CANON[role] !== undefined) ROLE_MAP.set(d, CANON[role]);
        } catch (e) { /* leave it to its layout */ }
      }
      S[d] = undefined;
      const info = LEARNED.get(d);
      rec.t = `opcode[${d}] = eval(${lit(S, s)})` + (info ? `   // operands: ${info.plan.join(',') || 'none'}` : '');
      break;
    }
    case 262: {
      const d = r.V(), n = r.A(); const b = [];
      for (let i = 0; i < n; i++) b.push(r.B());
      S[d] = { bytes: b };
      // Slot 486 is where the old build happens to put it. The build-independent
      // fact (tools/opcode-trace.cjs) is that the alphabet load comes FIRST —
      // nothing can decode a string before the table exists — so take the first
      // load big enough to be an alphabet.
      if (ALPHABET === null && n >= 16) { ALPHABET = b; rec.t = `alphabet[${n}] (slot ${d})`; }
      else rec.t = `s${d} = <${n} raw bytes>`;
      break;
    }
    case 402: {
      const d = r.V(), n = r.A(); const ds = [];
      for (let i = 0; i < n; i++) ds.push(r.A());
      const str = decodeStr(ds);
      if (str !== null) { S[d] = str; rec.t = `s${d} = ${JSON.stringify(str)}`; }
      else { S[d] = { str: n }; rec.t = `s${d} = <string, ${n} chars>`; }
      break;
    }
    case 268: { const s = r.V(), b = r.V(); rec.t = `emitLenPrefixed(s${b}, s${s})`; break; }
    case 297: { const s = r.V(), b = r.V(); rec.t = `emitU8(s${b}, ${lit(S, s)})`; break; }
    case 371: { const s = r.V(), b = r.V(); rec.t = `emitU32(s${b}, ${lit(S, s)})`; break; }
    case 375: { const s = r.V(), b = r.V(); rec.t = `emitNumber(s${b}, s${s})`; break; }
    case 408: { const a = r.V(), b = r.V(), c = r.V(), d = r.V(); S[d] = undefined; rec.t = `s${d} = arith(s${a}, s${b}, s${c})`; break; }
    case 237: { const o = []; for (let i = 0; i < 13; i++) o.push(r.V()); rec.t = `bigTransform(${o.join(', ')})`; break; }
    case 501: {
      const o = r.V(), k = r.V(), v = r.V();
      rec.t = `s${o}[s${k}] = ${lit(S, v)}`;
      if (o === KEYCTL_SLOT) {
        // Slot numbers are permuted per response, so the index register may be
        // unknown. The pattern is always keyCtl[1] then keyCtl[2] + 32 clear
        // bits, so fall back to position when the value is not tracked.
        let kv = S[k];
        if (typeof kv !== 'number') { kv = keyCtlSeen % 2 === 0 ? 1 : 2; rec.inferredIdx = kv; }
        keyCtlSeen++;
        keyIdxRegs.add(k);
        if (kv === 1) { rec.setIV1 = S[v]; rec.t += `   // IV1 = ${S[v]}` + (rec.inferredIdx ? ' (index inferred)' : ''); }
        else { rec.setIV2 = S[v]; const nk = r.rekey(); rec.rekey = nk; rec.t += `   // IV2 = ${S[v]}, REKEY -> 0x${(nk >>> 0).toString(16).padStart(8, '0')}` + (rec.inferredIdx ? ' (index inferred)' : ''); }
      }
      // The OUTPUT cipher's IV is written the same way, to a different object.
      // Slot 244 is where the old build happens to keep it. What is build-
      // independent is the pair of INDEX registers: the two fields of the key
      // control block and the two fields of the output IV are addressed by the
      // same two registers, whatever the objects are called.
      //
      //   old   s28[s94] / s28[s30]     then   s244[s94] / s244[s30]
      //   new   s292[s5] / s292[s109]   then   s15[s5]   / s15[s109]
      else if (keyIdxRegs.has(k) && typeof S[v] === 'number') {
        rec.streamKey = { slot: k, value: S[v] };
      }
      break;
    }
    case 192: case 412: {
      const fn = r.V(), d = r.V(), n = r.B() - 1, self = r.V();
      const a = []; for (let i = 0; i < n; i++) a.push('s' + r.V());
      S[d] = undefined;
      rec.t = `${op === 412 ? 'new ' : ''}s${fn}.call(s${self}${a.length ? ', ' + a.join(', ') : ''}) -> s${d}`;
      break;
    }
    case 485: {
      const n = r.B(); const k = [];
      for (let i = 0; i < n; i++) k.push(r.V());
      rec.t = `return   // live-out: ${k.map((x) => 's' + x).join(', ')}`;
      rec.ret = true;
      // The handler does not just jump back: it restores the caller's register
      // frame and carries only these slots across. The walk has to do the same or
      // the caller resumes with the callee's registers.
      rec.liveOut = k;
      break;
    }
    default: {
      const learned = LEARNED.get(raw);
      if (VARIABLE.has(raw)) {
        // Decoding it would desynchronise the stream and everything after would
        // be fiction. Stopping this path is the honest outcome.
        rec.t = `<opcode ${raw}: operand count is a run-time value — not statically decodable>`;
        rec.unknown = true;
        break;
      }
      if (learned) {
        const plan = learned.plan.join('');
        const vals = [];
        for (const kind of learned.plan) vals.push(kind === 'B' ? r.B() : r.V());
        // A layout of one operand followed by K raw bytes is a constant load:
        // the operand is the destination register and the bytes are a big-endian
        // immediate. That is what opcodes 8 (VB), 49 (VBB) and 459 (VBBBB) are on
        // the build the cases were written for, and the shape is the same on any
        // build — so the walk gets its register values, and its JUMPs, without
        // knowing a single opcode number.
        //
        // Without this the profile-driven walk sees only the four named roles,
        // never learns a register value, and cannot resolve a call target: on the
        // old build that is 7 instructions instead of 400.
        if (/^VB+$/.test(plan)) {
          const d = vals[0];
          let v = 0;
          for (let i = 1; i < vals.length; i++) v = ((v << 8) | vals[i]) >>> 0;
          S[d] = v;
          rec.t = `s${d} = ${v}`;
          if (d === PC_SLOT) { rec.jump = v; rec.t += '   // JUMP'; }
        } else if (EMIT.has(raw)) {
          // Print tracked constants rather than register numbers, so the emitted
          // record reads the same way it does on the build the cases were written
          // for — `emitU8(s215, 242)` against `emit[Oz](s88, 242)`.
          rec.t = `emit[${EMIT.get(raw)}](${vals.map((v) => lit(S, v)).join(', ')})`;
        } else {
          rec.t = `op${raw}(${vals.join(', ')})   // layout ${plan} from its own source`;
        }
        rec.learned = true;
      } else { rec.t = `<unknown opcode ${raw}>`; rec.unknown = true; }
      break;
    }
  }
  rec.end = r.pos;
  rec.at = at;
  return rec;
}

// ---- 4. walk ---------------------------------------------------------------
const initL = ((P3[0] << 24) | (P3[1] << 16) | (P3[2] << 8) | P3[3]) >>> 0;
console.log('initial stream key : ' + initL + ' (first 32 bits, in the clear)');
console.log('');

const listing = [];
const visited = new Set();
const work = [{ pos: 32, L: initL, iv1: 0, iv2: 0, S: {} }];

// Optional: seed the walk with cipher states recovered elsewhere. Opcodes 27 and
// 237 read a run-time-determined number of operands, so a purely static walk
// desynchronises at the first one and cannot derive the later section keys. With
// the states supplied, the decode itself is still static - only the keys are not.
let seeded = 0;
if (process.argv.includes('--seed')) {
  try {
    const st = JSON.parse(fs.readFileSync(path.join(__dirname, 'from-scratch-2026-07-25', 'cipher_sections.json'), 'utf8'));
    for (const x of st.states) {
      work.push({ pos: x.firstBit, L: x.L | 0, iv1: x.iv1 | 0, iv2: x.iv2 | 0, S: {} });
      seeded++;
    }
    console.log('seeded with ' + seeded + ' cipher states from a previous run (decode stays static)');
  } catch (e) { console.log('--seed: cipher_sections.json not readable'); }
}
let unknown = 0, deadEnds = 0, computedJumps = 0, steps = 0, budgetHit = false;
const BUDGET = Number(process.env.BUDGET || 200000);

// ---- trace mode ------------------------------------------------------------
// With a recorded program-counter trace there is nothing to predict: the run says
// where every instruction begins and what the cipher state was. Decode exactly one
// instruction at each recorded address and the listing is of the path the program
// actually took, not the path a walk could guess. This is the difference between
// a fifth of the image and three quarters of it.
const TRACE_ARG = (process.argv.find((a) => a.startsWith('--trace=')) || '').slice(8);
if (TRACE_ARG) {
  const tp = path.isAbsolute(TRACE_ARG) ? TRACE_ARG : path.join(__dirname, 'records', TRACE_ARG);
  const tr = JSON.parse(fs.readFileSync(tp, 'utf8'));
  const seen = new Set();
  let decoded = 0, failed = 0, skipped = 0;
  const bits = [];
  // Walk in EXECUTION order and carry one register file forward. Decoding each
  // address in isolation loses the string a LOAD_STR just built, so DEF_OPCODE
  // cannot be resolved and the opcodes it installs stay unknown — and those are
  // exactly the ones permuted per response. In order, the state fills in as the
  // program fills it, and the decoder learns each installed layout from the very
  // instruction that installs it.
  const S = {};
  for (const e of tr.pcs) {
    if (!e) { skipped++; continue; }
    const [pc, L, iv1, iv2] = Array.isArray(e) ? e : [e, initL, 0, 0];
    const r = new R(pc, L | 0, iv1 | 0, iv2 | 0);
    let ins;
    try { ins = decode(r, S); } catch (err) { failed++; continue; }
    if (!ins) { failed++; continue; }
    if (!seen.has(pc)) {
      seen.add(pc); decoded++;
      listing.push(Object.assign({ pc }, ins));
      if (r.pos > pc && r.pos - pc < 8192) bits.push([pc, r.pos]);
    }
  }
  listing.sort((a, b) => a.pc - b.pc);
  bits.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const b of bits) { const l = merged[merged.length - 1];
    if (l && b[0] <= l[1]) l[1] = Math.max(l[1], b[1]); else merged.push([b[0], b[1]]); }
  const cov = merged.reduce((a, [x, y]) => a + (y - x), 0);
  console.log('');
  console.log('=== trace-driven decode ===');
  const dispatcherCalls = tr.dispatcherCalls != null ? tr.dispatcherCalls : tr.pcs.length;
  const opcodeFetches = tr.opcodeFetches != null ? tr.opcodeFetches : tr.pcs.length - skipped;
  console.log('  trace                : ' + dispatcherCalls + ' dispatcher calls, ' + opcodeFetches
    + ' opcode fetches, ' + seen.size + ' distinct addresses');
  console.log('  instructions decoded : ' + decoded + (failed ? '   (failed at ' + failed + ')' : ''));
  if (skipped) console.log('  queued dispatches    : ' + skipped
    + '   (handler/operands came from state.o/state.N; stale outer start omitted)');
  console.log('  bit coverage         : ' + (100 * cov / TOTAL).toFixed(1) + '%  (' + cov + '/' + TOTAL + ')');
  const emits = listing.filter((x) => /emit/.test(x.t || ''));
  console.log('  emit instructions    : ' + emits.length);
  // ---- the branches this run did not take -----------------------------------
  // The honest-accounting section calls the never-executed part "decryptable
  // offline", and that was an inference from where those runs sit, never a
  // measurement. With the trace in hand it becomes one: we know every cipher state
  // the program passed through, so try each untouched run under each of them and
  // ask whether its prefix yields at least three plausible instructions.
  if (process.argv.includes('--dark')) {
    bits.sort((a, b) => a[0] - b[0]);
    const mg = [];
    for (const b of bits) { const l = mg[mg.length - 1];
      if (l && b[0] <= l[1]) l[1] = Math.max(l[1], b[1]); else mg.push([b[0], b[1]]); }
    const gaps = []; let prev = 0;
    for (const [x, y] of mg) { if (x - prev > 64) gaps.push([prev, x]); prev = y; }
    if (TOTAL - prev > 64) gaps.push([prev, TOTAL]);
    const states = [...new Set(tr.pcs.filter(Boolean)
      .map((e) => (e[1] | 0) + ':' + (e[2] | 0) + ':' + (e[3] | 0)))].map((k) => k.split(':').map(Number));
    console.log('');
    console.log('=== branches this run did not take ===');
    console.log('  untouched runs : ' + gaps.length + '   cipher states seen : ' + states.length);
    let ok = 0, dead = 0;
    let bitsOk = 0, bitsDead = 0;
    const sorted = gaps.sort((a, b) => (b[1] - b[0]) - (a[1] - a[0]));
    for (const [lo, hi] of sorted) {
      let best = null;
      for (const [L, i1, i2] of states) {
        const r = new R(lo, L, i1, i2);
        let n = 0;
        try { for (; r.pos < hi && n < 400; n++) { const ins = decode(r, {}); if (!ins || ins.unknown) break; } }
        catch (e) { /* fell off */ }
        if (!best || n > best.n) best = { n, L, i1, i2, end: r.pos };
      }
      const span = hi - lo;
      const verdict = best && best.n >= 3 ? 'PARSABLE PREFIX (' + best.n + ' insns under key ' + (best.L >>> 0) + ')'
        : 'no visited state yields a 3-instruction prefix';
      if (best && best.n >= 3) { ok++; bitsOk += span; } else { dead++; bitsDead += span; }
      if (sorted.indexOf([lo, hi]) < 0 && span >= 200) {
        console.log('  bits ' + String(lo).padStart(6) + '..' + String(hi).padStart(6)
          + String(span).padStart(7) + ' bits  ' + verdict);
      }
    }
    console.log('');
    console.log('  runs with a >=3-instruction prefix under a visited state : ' + ok
      + '   (' + bitsOk + ' bits, ' + (100 * bitsOk / TOTAL).toFixed(1) + '% of the image)');
    console.log('  runs without such a prefix under any visited state       : ' + dead
      + '   (' + bitsDead + ' bits, ' + (100 * bitsDead / TOTAL).toFixed(1) + '%)');
    console.log('');
    console.log('  Re-keying is data-driven — the key is reloaded from the stream by an');
    console.log('  instruction — so a branch never taken can sit past a re-key that never');
    console.log('  happened. Those bytes are not decryptable from this run at any effort.');
  }

  const f = path.join(__dirname, 'trace-disassembly-' + (tr.build || 'build') + '.txt');
  fs.writeFileSync(f, listing.map((x) => 'bit ' + String(x.pc).padStart(6) + '  ' + (x.t || ('op' + x.op))).join('\n') + '\n');
  console.log('  wrote                : ' + path.basename(f));
  process.exit(0);
}

while (work.length) {
  const job = work.pop();
  const r = new R(job.pos, job.L, job.iv1, job.iv2);
  let S = Object.assign({}, job.S);
  const stack = [];
  for (;;) {
    if (r.pos >= TOTAL) break;
    if (++steps > BUDGET) { budgetHit = true; break; }
    const key = r.pos + ':' + (r.L >>> 0) + ':' + (r.iv1 >>> 0) + ':' + (r.iv2 >>> 0);
    const seen = visited.has(key);
    visited.add(key);
    const pc = r.pos;
    const ins = decode(r, S);          // decoding is deterministic: re-decode is free
    if (!ins) break;
    if (!seen) listing.push(Object.assign({ pc }, ins));
    if (ins.unknown) { unknown++; break; }
    if (ins.setIV1 !== undefined) { r.iv1 = ins.setIV1 | 0; r.blk = -1; }
    if (ins.setIV2 !== undefined) { r.iv2 = ins.setIV2 | 0; r.blk = -1; }
    if (ins.jump !== undefined) { r.pos = ins.jump; r.blk = -1; continue; }
    if (ins.call !== undefined) {
      if (typeof ins.call === 'number') {
        // A subroutine gets its own register frame. Carrying the caller's forward
        // and letting the callee scribble on it is why the new build's walk
        // collapsed from 388 instructions to 143 the moment calls started being
        // followed: on return, a register the caller had loaded with an address
        // held a string the callee had put there.
        stack.push({ pos: r.pos, S });
        S = Object.assign({}, S);
        r.pos = ins.call; r.blk = -1;
        continue;
      }
      computedJumps++; deadEnds++; break;   // CALL_SUB through a slot we cannot evaluate
    }
    if (ins.ret) {
      if (stack.length) {
        const f = stack.pop();
        const callee = S;
        S = f.S;
        for (const slot of ins.liveOut || []) S[slot] = callee[slot];
        r.pos = f.pos; r.blk = -1;
        continue;
      }
      break;
    }
    if (ins.cond !== undefined) {
      const t = S[ins.cond];
      if (typeof t === 'number' && t < TOTAL) work.push({ pos: t, L: r.L, iv1: r.iv1, iv2: r.iv2, S: Object.assign({}, S) });
      else computedJumps++;
    }
  }
}

listing.sort((a, b) => a.pc - b.pc);
const cov = new Uint8Array(TOTAL);
for (const i of listing) for (let x = i.pc; x < i.end && x < TOTAL; x++) cov[x] = 1;
let covered = 0;
for (const b of cov) covered += b;

console.log('=== static walk, zero execution ===');
console.log('  instructions decoded : ' + listing.length);
console.log('  bit coverage         : ' + ((covered / TOTAL) * 100).toFixed(1) + '%  (' + covered + '/' + TOTAL + ')');
console.log('  unknown opcodes      : ' + unknown);
console.log('  targets we cannot resolve statically : ' + computedJumps);
const learnedCount = listing.filter((l) => l.learned).length;
console.log('  opcode layouts learned from DEF_OPCODE: ' + LEARNED.size +
  ', used for ' + learnedCount + ' instructions');
console.log('  strings resolved     : ' + listing.filter((l) => /= "/.test(l.t || '')).length +
  (ALPHABET ? '  (alphabet ' + ALPHABET.length + ' bytes)' : ''));
console.log('  dispatch steps walked : ' + steps + (budgetHit ? '  (budget hit)' : ''));

const keyOps = listing.filter((i) => i.streamKey);
if (keyOps.length) {
  console.log('\n  output-stream key recovered statically:');
  for (const k of keyOps) console.log('    bit ' + k.pc + '  cipherIV[' + (k.streamKey.slot) + '] slot -> ' + k.streamKey.value);
}
const rekeys = listing.filter((i) => i.rekey !== undefined);
console.log('\n  section re-keys seen : ' + rekeys.length +
  (rekeys.length ? ' -> ' + rekeys.map((k) => '0x' + (k.rekey >>> 0).toString(16)).join(', ') : ''));
const emits = listing.filter((i) => /emit/.test(i.t || ''));
console.log('  emit instructions    : ' + emits.length);
for (const e of emits.slice(0, 12)) console.log('    bit ' + String(e.pc).padStart(6) + '  ' + e.t);

const LISTING_FILE = 'static-disassembly' + (HTML_ARG ? '-' + path.basename(HTML_ARG).replace(/\.html$/, '') : '') + '.txt';
fs.writeFileSync(path.join(__dirname, LISTING_FILE),
  listing.map((i) => 'bit' + String(i.pc).padStart(7) + '  op' + String(i.op).padEnd(4) + ' ' + i.t).join('\n') + '\n');
console.log('\n  wrote ' + LISTING_FILE);

if (process.argv.includes('--listing')) {
  console.log('');
  for (const i of listing) console.log('bit' + String(i.pc).padStart(7) + '  op' + String(i.op).padEnd(4) + ' ' + i.t);
}
