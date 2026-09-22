'use strict';
// ============================================================================
//  opcode-trace.cjs — find the two roles a static signature cannot see.
//
//  opcode-roles.cjs reads handler SOURCE and recognises four roles by shape. On
//  build c348580f3670 two of them did not fire — the string-alphabet loader and
//  the re-key — because signatures written against one build's handlers do not
//  necessarily match another's regeneration of the same job.
//
//  Both were identifiable from observed behaviour on the measured builds:
//
//    alphabet   was the FIRST instruction the measured programs executed;
//               nothing decoded a string before the table existed.
//    re-key     was the instruction after which the stream key first changed.
//
//  These are trace heuristics to verify on a new sample, not guarantees about a
//  future generator or every possible program path.
//
//  So tap the dispatcher, which knows the opcode number of every handler it
//  calls, and snapshot the interpreter state's numeric fields around each call.
//  The dispatch site is located by shape — a guarded call of the form
//  `? handler(state, budget) : error(0, …)` — so no name is hardcoded.
//
//     node opcode-trace.cjs old      validate against the known answers
//     node opcode-trace.cjs new
//
//  Validated on 885c049eda50, where both answers are known from
//  06-vm-mechanics §6: first executed 262 (the alphabet loader), and the key
//  field L first changes after 501 (the re-key). Both come out right, and the
//  token stays at 1660 so the tap is invisible.
//
//  Results:
//
//    885c049eda50   alphabet 262   re-key 501 (field L)
//    c348580f3670   alphabet 484   re-key 107 (field P)
//
//  A caveat on the re-key: the key field keeps changing as the stream is read,
//  so only the FIRST attribution is meaningful — the later ones name whatever
//  instruction happened to run next.
// ============================================================================
const fs = require('fs');
const path = require('path');
const R_ = __dirname;   // the bundle is self-contained
const { dep, parseChallenge } = require(path.join(R_, 'lib', 'challenge.js'));
// Plain relative require, not one built from the repo root: in a published bundle
// every tool sits in one flat directory, and `R_/tools/...` does not exist there.
const { sourceRoles } = require('./build-profile.cjs');
const { JSDOM } = require('jsdom');
const acorn = require('acorn');

// Named shortcuts kept for the two builds this tool was written against; any
// other capture is selected with --html= and its readable source is resolved
// from the build sha, so a build nobody has looked at needs no entry here.
const BUILDS = {
  old: { capture: 'response.html', readable: 'vm-readable.js' },
  new: { capture: 'challenge-2026-08-21.html', readable: 'vm-readable.js' },
};
const crypto = require('crypto');
const HTML_ARG = (process.argv.find((a) => a.startsWith('--html=')) || '').slice(7);
const READ_ARG = (process.argv.find((a) => a.startsWith('--readable=')) || '').slice(11);
const which = process.argv.slice(2).find((a) => !a.startsWith('--')) || (HTML_ARG ? null : 'new');
const cfg = which ? BUILDS[which] : {};
if (which && !cfg) { console.error('unknown build name ' + which + '; use --html=<capture>'); process.exit(1); }

const capture = HTML_ARG || cfg.capture;
const html = fs.readFileSync(path.isAbsolute(capture) ? capture : path.join(R_, 'captures', capture), 'utf8');
const ch = parseChallenge(html);
const BUILD_SHA = crypto.createHash('sha256').update(ch.vm).digest('hex').slice(0, 12);
// The readable source is a per-BUILD artifact. Resolve it from the sha rather
// than from the capture name: two captures of one build share it, and a capture
// of a build nobody deobfuscated yet must fail loudly, not silently read another
// build's file and report its opcode numbers as this build's.
// Same fallback chain as build-profile.cjs. The repo names one file per build,
// a published bundle names its single one plainly, and the very first build's
// file predates the convention and is just `vm-readable.js` — so try the
// build-scoped name, then whatever the answer table records, then the plain one.
const { KNOWN_BUILDS } = require('./lib/builds.js');
const readableDir = path.join(R_, 'lifted-source');
const readableTries = [
  READ_ARG,
  cfg.readable,
  'vm-readable-' + BUILD_SHA + '.js',
  (KNOWN_BUILDS[BUILD_SHA] || {}).readable,
  'vm-readable.js',
].filter(Boolean);
const readablePath = readableTries
  .map((f) => (path.isAbsolute(f) ? f : path.join(readableDir, f)))
  .find((f) => fs.existsSync(f));
if (!readablePath) {
  console.error('no readable source for build ' + BUILD_SHA + '. Looked for '
    + readableTries.join(', ') + ' under ' + readableDir);
  console.error('run: node vm-deobfuscate.cjs --html=' + path.basename(capture)
    + ' --no-rename --out=vm-readable-' + BUILD_SHA + '.js');
  process.exit(1);
}
const readable = path.basename(readablePath);
const SRC = fs.readFileSync(readablePath, 'utf8');
const WANT_PCS = process.argv.includes('--pcs');
// Read the build's own numbers out of its source rather than defaulting to the
// last build's. A stale default does not degrade the trace, it empties it: on
// 80056f9da7b2 the previous key-control slot (376 instead of 327) made the read
// throw on an unrelated slot and 1893 recorded addresses came back as 0. The
// flags stay, for overriding a derivation while investigating one.
const DERIVED = sourceRoles(SRC);
const numFlag = (name, fallback) => {
  const f = process.argv.find((a) => a.startsWith('--' + name + '='));
  return f ? Number(f.slice(name.length + 3)) : fallback;
};
// The handler runs after the live bit cursor has consumed the opcode and its
// operands. The dispatcher preserves the instruction's start in the other
// extend-only slot before that happens; trace that snapshot so every recorded
// address is a real instruction boundary.
const PC_SLOT = numFlag('pc-slot', DERIVED.instructionStart ?? DERIVED.pcShadow);
const KEYCTL_SLOT = numFlag('keyctl', DERIVED.keyCtlSlot);
const WANT_OUTPUT_KEY = process.argv.includes('--output-key');
const OUTPUT_KEY_FACTS = (KNOWN_BUILDS[BUILD_SHA] || {});
const OUTPUT_KEY_SLOT = numFlag('output-key-slot', OUTPUT_KEY_FACTS.outputKeySlot);
const OUTPUT_KEY_WORDS = OUTPUT_KEY_FACTS.outputKeyWords || [1, 2];
let covCalls = 0, covBits = 0;
const REGFILE = (process.argv.find((a) => a.startsWith('--regfile=')) || ('--regfile=' + DERIVED.registerFile)).slice(10);
// The two state fields the stream cipher lives in. Build-scoped letters, and the
// collision is not hypothetical: build 4 calls its register file `.N`, which is
// build 3's KEY field.
const KEYFIELD = DERIVED.keyField, BLOCKFIELD = DERIVED.blockField;
for (const [what, v] of [['instruction-start slot', PC_SLOT], ['key-control slot', KEYCTL_SLOT],
  ['register file', REGFILE], ['cipher key field', KEYFIELD], ['cipher block field', BLOCKFIELD]]) {
  if (v == null || v === '' || (typeof v === 'number' && !Number.isFinite(v))) {
    console.error('could not work out the ' + what + ' for build ' + BUILD_SHA + ' from '
      + path.basename(readablePath) + '; pass it with a flag');
    process.exit(1);
  }
}
if (WANT_OUTPUT_KEY && !Number.isFinite(OUTPUT_KEY_SLOT)) {
  console.error('the SG_SS output-key slot is not profiled for build ' + BUILD_SHA
    + '; pass --output-key-slot=<slot> after reviewing the writer');
  process.exit(1);
}
// A register holds a wrapper, not a value, so the seeds can only be read through
// the interpreter's own accessor — and exactly once each, because that read is not
// idempotent (part 2, section 7). Find one by shape: the function that throws a
// three-element array when the slot is void 0.
const READER = (() => {
  // Pick the accessor the DISPATCHER uses, not the first one in the file that
  // happens to throw an array. Scanning the whole source picked `P` on
  // 80056f9da7b2 and inferred the wrong argument order, so every program-counter
  // read threw and the trace came back empty. The dispatcher reads the counter
  // itself — `c(I, 6)` there — so the call that does it names both the function
  // and the order.
  const dm = /\?\s*[A-Za-z_$][\w$]*\([A-Za-z_$][\w$]*,\s*[A-Za-z_$][\w$]*\)\s*:/.exec(SRC);
  const around = dm ? SRC.slice(Math.max(0, dm.index - 1200), dm.index + 400) : SRC;
  // NAME(state, N) or NAME(N, state), N a slot number.
  //
  // Two things this has to get right, and it got each of them wrong once.
  //
  // A method call is not the accessor. `.call(this, 16)` matches the shape
  // exactly, and on d4a6b4f0a2a5 it sits closer to the dispatcher than the real
  // read does — so the tap was installed on `call`, the interpreter came apart,
  // and the run produced a degraded token and zero dispatches. Anything preceded
  // by a dot is a property, not a free function.
  //
  // And of the remaining candidates, the right one is the read of the PROGRAM
  // COUNTER, whose slot number we already derived. Matching on that instead of on
  // proximity makes the choice exact rather than lucky: `k(K, 302)` here,
  // `c(I, 6)` on 80056f9da7b2.
  const cand = [];
  for (const m2 of around.matchAll(/([A-Za-z_$][\w$]*)\(\s*([A-Za-z_$][\w$]*)\s*,\s*(\d{1,4})\s*\)/g)) {
    if (around[m2.index - 1] === '.') continue;
    cand.push({ name: m2[1], stateFirst: true, slot: Number(m2[3]) });
  }
  for (const m2 of around.matchAll(/([A-Za-z_$][\w$]*)\(\s*(\d{1,4})\s*,\s*([A-Za-z_$][\w$]*)\s*\)/g)) {
    if (around[m2.index - 1] === '.') continue;
    cand.push({ name: m2[1], stateFirst: false, slot: Number(m2[2]) });
  }
  const best = cand.find((c) => c.slot === DERIVED.programCounter)
    || cand.find((c) => c.slot === DERIVED.pcShadow)
    || cand[0];
  if (best) return { name: best.name, stateFirst: best.stateFirst };
  // fall back to the old whole-file scan
  const re = /([A-Za-z_$][\w$]*)\s*=\s*function\s*\((\w+),\s*(\w+)[^)]*\)\s*\{([^}]{0,160}?)throw\s*\[/g;
  for (let c; (c = re.exec(SRC)); ) {
    const [, name, x, y, body] = c;
    const m3 = new RegExp('(' + x + '|' + y + ')\\.\\w+\\[').exec(body);
    if (!m3) continue;
    return { name, stateFirst: m3[1] === x };
  }
  return null;
})();
console.log('reader accessor by shape: ' + (READER && READER.name) + '  (state ' + (READER && READER.stateFirst ? 'first' : 'second') + ')');

console.log('build     : ' + BUILD_SHA + '   capture ' + path.basename(capture));

// The dispatch call: a conditional whose consequent invokes a variable holding
// the handler with (state, budget), guarded by a check of that handler's tag.
// Both builds write it the same shape, only the names differ.
// The dispatch site is `<guard> ? handler(state, budget) : <error>(…)`. Only the
// consequent is stable across builds: the guard is an MBA expression whose shape
// is regenerated, and the error call's argument order moves too — 885c049eda50
// puts the 0 first (`E(0, …)`), d4a6b4f0a2a5 puts it third (`ZY(K, 95, 0, …)`).
// So match the consequent loosely and confirm the site by the one thing the
// error path always carries: the throw tuple `[tag, number, opcodeVar]`, whose
// last element names the opcode variable this tool needs.
const DISPATCH = /\?\s*([A-Za-z_$][\w$]*)\(([A-Za-z_$][\w$]*),\s*([A-Za-z_$][\w$]*)\)\s*:\s*([A-Za-z_$][\w$]*)\(/g;
const THROW_TUPLE = /\[\s*[A-Za-z_$][\w$]*\s*,\s*\d+\s*,\s*([A-Za-z_$][\w$]*)\s*\]/;
let m = null, slotVar = null;
for (let c; (c = DISPATCH.exec(SRC)); ) {
  const hit = THROW_TUPLE.exec(SRC.slice(c.index, c.index + 300));
  if (hit) { m = c; slotVar = hit[1]; break; }
}
if (!m) { console.error('dispatch site not found'); process.exit(1); }
console.log('dispatch  : ' + m[1] + '(' + m[2] + ', ' + m[3] + ')   opcode variable: ' + (slotVar || '?'));
if (!slotVar) { console.error('could not identify the opcode variable at the dispatch site'); process.exit(1); }

const PATCHED = SRC.slice(0, m.index)
  + '? (typeof __exec === "function" && __exec(' + slotVar + ', ' + m[2] + (READER ? ', ' + READER.name : '') + '), ' + m[1] + '(' + m[2] + ', ' + m[3] + '))'
  + SRC.slice(m.index + m[0].length - (': ' + m[4] + '( 0 ,').length + 0).replace(/^/, '')
    .slice(0);

// simpler and safer: rebuild by replacing only the consequent
// --coverage: also tap the bit reader, so we can say how much of the program
// image a real run actually decodes. WS(state, nbits, encrypted) is the one door
// every byte of bytecode comes through, and it advances the PC itself — so
// logging (pc, nbits) at entry gives exact coverage with no PC read of our own,
// which matters because register reads are not idempotent.
const WSFN = (() => {
  const re = /([A-Za-z_$][\w$]*)\s*=\s*function\s*\(([^)]*)\)\s*\{\s*if\s*\(\(\(\w+\s*=\s*\w+\((\d+),\s*\w+\)\)/;
  const c = re.exec(SRC);
  return c ? { name: c[1], params: c[2].split(',').map((x) => x.trim()) } : null;
})();
let SRC2 = SRC;
if (process.argv.includes('--coverage') && WSFN) {
  const idx = SRC2.indexOf(WSFN.name + ' = function');
  const open = SRC2.indexOf('{', idx);
  const [st, nb] = WSFN.params;
  SRC2 = SRC2.slice(0, open + 1)
    + 'try{typeof __ws==="function"&&__ws(' + st + ',' + nb + ');}catch(e){}'
    + SRC2.slice(open + 1);
}

// --emit-log : log the VALUE every record-writing helper is handed.
//
// The build profile names the helpers (`nS` and `SS` on 80056f9da7b2). Logging
// their first argument gives the record's contents in the order the program
// produced them — which is how to ask "what computed this field" once the
// differential oracle has gone blind, as it has for 0xc512.
//
// Inserted as a STATEMENT at the top of each helper, never as a wrapper: the
// fingerprint compensation below pairs functions positionally between the
// original and this source, and an extra function shifts every pair after it.
const EMIT_LOG = process.argv.includes('--emit-log');
if (EMIT_LOG) {
  const prof = (() => {
    const dir = path.join(R_, 'records');
    const base = path.basename(capture).replace(/\.html$/, '');
    for (const f of ['profile-' + BUILD_SHA + '-' + base + '.json', 'profile-' + BUILD_SHA + '.json']) {
      const at = path.join(dir, f);
      if (fs.existsSync(at)) return JSON.parse(fs.readFileSync(at, 'utf8'));
    }
    return null;
  })();
  const helpers = [...new Set(Object.values((prof && prof.emit) || {}))];
  if (!helpers.length) { console.error('--emit-log needs a build profile with an emit map'); process.exit(1); }
  console.log('emit helpers   : ' + helpers.join(', '));
  for (const h of helpers) {
    const idx = SRC2.indexOf(h + ' = function');
    if (idx < 0) { console.error('  helper ' + h + ' not found in the readable source'); continue; }
    const open = SRC2.indexOf('{', SRC2.indexOf(')', idx));
    const args = SRC2.slice(SRC2.indexOf('(', idx) + 1, SRC2.indexOf(')', idx)).split(',').map((x) => x.trim()).filter(Boolean);
    SRC2 = SRC2.slice(0, open + 1)
      + 'try{typeof __emit==="function"&&__emit(' + JSON.stringify(h) + ',' + (args[0] || 'undefined') + ');}catch(e){}'
      + SRC2.slice(open + 1);
  }
}

// Rebuild the matched site verbatim except for the inserted call. The old form
// hardcoded `: <err>( 0 ,` because both earlier builds wrote the error path that
// way; d4a6b4f0a2a5 does not, so reconstruct from what was actually matched.
// The register accessor is handed in too, so the tap can read the program counter
// through the interpreter's own reader rather than poking at the wrapper.
const PATCHED2 = SRC2.replace(m[0],
  '? (typeof __exec === "function" && __exec(' + slotVar + ', ' + m[2]
  + (READER ? ', ' + READER.name : ', undefined') + ', ' + m[1] + '), '
  + m[1] + '(' + m[2] + ', ' + m[3] + ')) : ' + m[4] + '(');

function fnTexts(src) {
  const ast = acorn.parse(src, { ecmaVersion: 2020, ranges: true, allowReturnOutsideFunction: true });
  const out = [];
  (function walk(n) {
    if (!n || typeof n.type !== 'string') return;
    if (n.type === 'FunctionExpression' || n.type === 'FunctionDeclaration' || n.type === 'ArrowFunctionExpression') out.push(src.slice(n.start, n.end));
    for (const k of Object.keys(n)) {
      if (['start', 'end', 'range', 'type'].includes(k)) continue;
      const v = n[k];
      if (Array.isArray(v)) v.forEach(walk); else if (v && typeof v.type === 'string') walk(v);
    }
  })(ast);
  return out;
}
const MAP = new Map();
{
  let of_, pf;
  try { of_ = fnTexts(ch.vm); pf = fnTexts(PATCHED2); }
  catch (e) { console.error('patched source does not parse: ' + e.message); process.exit(1); }
  if (of_.length !== pf.length) { console.error('function count mismatch ' + pf.length + ' vs ' + of_.length); process.exit(1); }
  for (let i = 0; i < pf.length; i++) MAP.set(pf[i], of_[i]);
}

(async () => {
  const seq = [];
  const queuedSources = [];
  const keyChanges = [];
  const dom = new JSDOM(html, { url: 'https://www.google.com/search?q=anything', referrer: 'https://www.google.com/', pretendToBeVisual: true, runScripts: 'outside-only' });
  const w = dom.window;
  w.Math.random = () => 0.4242424242424242;
  const D = w.Date;
  function FD(...a) { return a.length ? new D(...a) : new D(17e11); }
  FD.prototype = D.prototype; FD.now = () => 17e11; FD.parse = D.parse; FD.UTC = D.UTC;
  w.Date = FD;
  let c = 0;
  w.performance.now = () => ++c;
  try { Object.defineProperty(w.performance, 'timeOrigin', { configurable: true, value: 17e11 }); } catch (e) {}
  w.navigator.sendBeacon = () => true;

  let prev = null;
  // --seed dumps the register file as it stands at the FIRST dispatch: the values
  // the interpreter's own startup put there before a single bytecode instruction
  // ran. Capture-specific profile consumers need them, and they are a property
  // of the build, so this is captured once per sha and then reused for every
  // challenge that build serves.
  let seeded = null;
  // A tap on the bit reader is useless here and the reason is worth recording:
  // the fingerprint pass re-installs WS from the source it harvests, so the tap is
  // overwritten part-way through the run and silently stops counting. It reported
  // 21.2 % where the truth is higher — trap 2 of part 2 section 8, walked into
  // again.
  //
  // The cipher block index survives, because it is a field of the state rather
  // than a function: the reader sets it whenever the 64-bit block changes. Collect
  // the distinct blocks and the coverage falls out at 64-bit granularity, with no
  // patch beyond the dispatch tap that was byte-invisible in the checked runs.
  const blocks = new Set();
  const pcs = []; let pcErr = null;

  // --output-key: the program-image cipher state (`.v`, key-control slot 377 on
  // this build) is not the key that encrypts the SG_SS record. The record writer
  // reads a separate three-element array from a VM slot and takes words [1]/[2].
  // Capture that slot only when the first encrypted output buffer exposes its
  // eight-byte keystream sibling. At that point the writer has already performed
  // its own read, so this observation cannot change the bytes being pushed now;
  // the final token hash still has to match the untapped control.
  let outputKeyState = null, outputKeyReader = null, outputKey = null;
  if (WANT_OUTPUT_KEY) {
    const opKey = w.Array.prototype.push;
    w.Array.prototype.push = function push(...a) {
      try {
        if (!outputKey && outputKeyState && outputKeyReader
          && a.length === 1 && typeof a[0] === 'number') {
          let hasKeystream = false;
          for (const k of Object.getOwnPropertyNames(this)) {
            let v; try { v = this[k]; } catch (e) { continue; }
            if (Array.isArray(v) && v.length === 8
              && v.every((x) => typeof x === 'number' && x >= 0 && x <= 255)) {
              hasKeystream = true; break;
            }
          }
          if (hasKeystream) {
            const raw = READER.stateFirst
              ? outputKeyReader(outputKeyState, OUTPUT_KEY_SLOT)
              : outputKeyReader(OUTPUT_KEY_SLOT, outputKeyState);
            const i1 = OUTPUT_KEY_WORDS[0], i2 = OUTPUT_KEY_WORDS[1];
            if (Array.isArray(raw) && Number.isFinite(raw[i1]) && Number.isFinite(raw[i2])) {
              outputKey = {
                slot: OUTPUT_KEY_SLOT,
                words: [i1, i2],
                raw: Array.from(raw),
                k1: raw[i1] | 0,
                k2: raw[i2] | 0,
              };
            }
          }
        }
      } catch (e) { /* keep looking; a register read here is accepted only with a final token match */ }
      return opKey.apply(this, a);
    };
  }

  // --origin=N : which instruction wrote byte N of the record.
  //
  // The dispatch tap says where the machine is; the push hook says which record
  // byte just appeared. Sampling the first at the moment of the second attributes
  // a byte to a program point — which is the only way left to ask what a field
  // means once the differential oracle has gone blind to it. record-origin.cjs
  // did this on the first build by tapping a function that later builds do not
  // contain; this does it through the dispatcher, which every build has.
  const ORIGIN = process.argv.find((x) => x.startsWith('--origin='));
  // --origin-find=c512 : locate a tag in the recovered record instead of being
  // told an offset. Offsets move with the environment; a tag does not.
  const OFIND = process.argv.find((x) => x.startsWith('--origin-find='));
  const originAt = ORIGIN ? Number(ORIGIN.slice(9)) : (OFIND ? -1 : null);
  const findBytes = OFIND ? OFIND.slice(14).match(/../g).map((h) => parseInt(h, 16)) : null;
  let lastOp = null, lastPc = null;
  const origins = [];
  if (originAt !== null) {
    const findKs = (buf) => {
      for (const k of Object.getOwnPropertyNames(buf)) {
        let v; try { v = buf[k]; } catch (e) { continue; }
        if (Array.isArray(v) && v.length === 8 && v.every((x) => typeof x === 'number' && x >= 0 && x <= 255)) return k;
      }
      return null;
    };
    let lastKs = null;
    const bufId = new WeakMap();
    var diag = new WeakMap(); var diagList = [];
    const op0 = w.Array.prototype.push;
    w.Array.prototype.push = function push(...a) {
      try {
        if (this && a.length === 1 && typeof a[0] === 'number') {
          // Looked up on EVERY push, not cached. Two reasons, each of which cost a
          // run: the record and the itinerary keep their keystream under different
          // property names, so one cached name skips the other buffer; and the
          // sibling is not attached yet at a buffer's first push, so caching the
          // answer from then caches "none". A remembered name is only a fallback.
          let k = findKs(this);
          if (!k && lastKs && Array.isArray(this[lastKs])) k = lastKs;
          if (k) lastKs = k;
          const ks = k && this[k];
          if (Array.isArray(ks) && ks.length === 8) {
            let id = bufId.get(this);
            if (id === undefined) { id = bufId.size; bufId.set(this, id); }
            origins.push([this.length, (a[0] ^ ks[this.length & 7]) & 255, lastOp, lastPc, id]);
          }
        }
      } catch (e) { /* not our buffer */ }
      // диагностика: считаем ВСЕ числовые push, даже те, у которых соседа не нашли
      try {
        if (this && a.length === 1 && typeof a[0] === 'number') {
          let d = diag.get(this);
          if (!d) { d = { n: 0, ks: null, keys: null }; diag.set(this, d); diagList.push(d); }
          d.n++;
          if (d.ks === null) { d.ks = findKs(this); if (!d.ks) d.keys = Object.getOwnPropertyNames(this).slice(0, 8).join(','); }
        }
      } catch (e) {}
      return op0.apply(this, a);
    };
  }

  // --watch=N : the first dispatches at which N appears in the register file.
  //
  // The record is serialised in one burst by a single instruction, so asking who
  // WROTE a byte only ever names the serialiser. Asking where the VALUE first
  // exists names the instruction that computed it. Scanned raw, never through the
  // accessor: a read there is not idempotent and would perturb the run.
  const WATCH = process.argv.find((x) => x.startsWith('--watch='));
  const watchFor = WATCH ? Number(WATCH.slice(8)) : null;
  const watchHits = [];
  let watchStep = 0;

  w.__exec = (op, state, reader, handler) => {
    if (WANT_OUTPUT_KEY) { outputKeyState = state; outputKeyReader = reader; }
    if (watchFor !== null) {
      watchStep++;
      if (watchHits.length < 6) {
        try {
          const D = state[REGFILE];
          for (const k of Object.keys(D)) {
            const v = D[k];
            // A slot holds a WRAPPER, not a value (part 2 §7). Look one level in —
            // at `.value`, and at the ten-element decoy array the other wrapper
            // kind uses — but never through the accessor, whose read mutates.
            let hit = v === watchFor;
            if (!hit && v && typeof v === 'object') {
              try {
                if (v.value === watchFor) hit = true;
                else if (Array.isArray(v) && v.indexOf(watchFor) >= 0) hit = true;
                else for (const kk of Object.keys(v)) {
                  const vv = v[kk];
                  if (vv === watchFor) { hit = true; break; }
                  if (Array.isArray(vv) && vv.indexOf(watchFor) >= 0) { hit = true; break; }
                }
              } catch (e) {}
            }
            if (hit) {
              let pc = null;
              try { pc = READER.stateFirst ? reader(state, PC_SLOT) : reader(PC_SLOT, state); } catch (e) {}
              watchHits.push({ step: watchStep, op, slot: Number(k), pc });
              break;
            }
          }
        } catch (e) {}
      }
    }
    if (originAt !== null) {
      lastOp = op;
      try { lastPc = READER.stateFirst ? reader(state, PC_SLOT) : reader(PC_SLOT, state); } catch (e) { lastPc = null; }
    }
    if (!seeded && process.argv.includes('--seed')) {
      seeded = {};
      try {
        const D = state[REGFILE];
        for (const k of Object.keys(D)) {
          if (D[k] === undefined) continue;
          let v;
          try { v = reader ? (READER.stateFirst ? reader(state, Number(k)) : reader(Number(k), state)) : D[k]; } catch (e) { continue; }
          if (v === undefined) continue;
          const t = typeof v;
          seeded[k] = t === 'number' || t === 'string' || t === 'boolean' ? { t, v }
            : Array.isArray(v) ? { t: 'array', v: v.filter((x) => typeof x !== 'function').slice(0, 64) }
            : t === 'function' ? { t: 'function' }
            : { t: 'object', ctor: (v && v.constructor && v.constructor.name) || '?',
                // a register holds a WRAPPER, not the value; peek at its own fields
                keys: Object.getOwnPropertyNames(v).slice(0, 8),
                boxed: (() => { try { const x = v.value; return x === undefined ? undefined
                  : (typeof x === 'object' ? (Array.isArray(x) ? 'array[' + x.length + ']' : 'obj')
                    : typeof x === 'function' ? 'fn' : x); } catch (e) { return 'ERR'; } })() };
        }
      } catch (e) { seeded = { err: e.message }; }
    }
    // numeric fields of the interpreter state, so a key change is visible
    const snap = {};
    try {
      for (const k of Object.getOwnPropertyNames(state)) {
        const v = state[k];
        if (typeof v === 'number') snap[k] = v;
      }
    } catch (e) {}
    if (prev) {
      for (const k of Object.keys(snap)) {
        // A clock ticking by one is not a re-key. A key is a 32-bit value that
        // jumps somewhere unrelated, so require both a large magnitude and a
        // large delta.
        const d = prev.snap[k] === undefined ? 0 : Math.abs(snap[k] - prev.snap[k]);
        if (prev.snap[k] !== undefined && prev.snap[k] !== snap[k]
          && Math.abs(snap[k]) > 65535 && d > 100000 && keyChanges.length < 12) {
          keyChanges.push({ afterOp: prev.op, field: k, from: prev.snap[k], to: snap[k] });
        }
      }
    }
    prev = { op, snap };
    if (seq.length < 40000) {
      seq.push(op);
      if (!Number.isInteger(op)) {
        let src = null;
        try { src = w.Function.prototype.toString.call(handler); } catch (e) {}
        queuedSources.push(src);
      }
    }
    // --pcs records WHERE the machine is at each step, plus the cipher state, which
    // is what a trace-driven disassembler needs: it never has to predict a boundary,
    // it is told one. Reading the program counter goes through the interpreter's own
    // accessor exactly once per dispatch — and the run is only trusted if the token
    // comes out unchanged, because a register read here is not idempotent.
    if (WANT_PCS && !Number.isInteger(op)) {
      // `state.o` is a second input stream: it supplies the next handler from a
      // queue while the operand readers consume the matching values from
      // `state.N`. No opcode is fetched from the encrypted outer image, so the
      // opcode variable is deliberately undefined and the instruction-start
      // slot still names the previous outer fetch. Keep the queued dispatch in
      // sequence order, but do not feed that stale boundary to the decoder.
      pcs.push(null);
    } else if (WANT_PCS) {
      try {
        const pc = READER.stateFirst ? reader(state, PC_SLOT) : reader(PC_SLOT, state);
        // The key-control slot holds a wrapper too, so poking at it directly gives
        // nothing and the recorded cipher state comes out as (key, 0, 0) — which
        // decrypts most of the program to garbage. Read it through the accessor,
        // the same way the reader itself does.
        const kc = READER.stateFirst ? reader(state, KEYCTL_SLOT) : reader(KEYCTL_SLOT, state);
        const iv = Array.isArray(kc) ? kc : (kc && kc.value) || null;
        pcs.push([Number(pc) | 0, state[KEYFIELD] | 0,
          iv && iv[1] !== undefined ? iv[1] | 0 : 0, iv && iv[2] !== undefined ? iv[2] | 0 : 0]);
      } catch (e) { if (!pcErr) pcErr = (Array.isArray(e) ? 'thrown array [' + e.join(',') + ']' : String(e && e.message || e)) + '  (reader=' + typeof reader + ', slot=' + PC_SLOT + ')'; pcs.push(null); }
    }
    try { if (typeof state[BLOCKFIELD] === 'number') blocks.add(state[BLOCKFIELD]); } catch (e) {}
  };

  const d0 = Object.getOwnPropertyDescriptor(w.HTMLIFrameElement.prototype, 'contentWindow');
  const g0 = d0.get, seen = new WeakSet();
  Object.defineProperty(w.HTMLIFrameElement.prototype, 'contentWindow', {
    configurable: true, enumerable: d0.enumerable,
    get() {
      const cw = g0.call(this);
      if (cw && !seen.has(cw)) {
        seen.add(cw);
        const fp = cw.Function.prototype, orig = fp.toString;
        fp.toString = function () { const t = orig.apply(this, arguments); const o = MAP.get(t); return o !== undefined ? o : t; };
      }
      return cw;
    },
  });

  const before = new Set(Object.getOwnPropertyNames(w));
  const emits = [];
  if (EMIT_LOG) w.__emit = (h, v) => { emits.push([h, v, lastPc]); };
  w.eval('(function(){\n' + PATCHED2 + '\n}).call(this);');
  let g = null;
  for (const k of Object.getOwnPropertyNames(w)) {
    if (before.has(k)) continue;
    let v; try { v = w[k]; } catch (e) { continue; }
    if (v && typeof v === 'object' && typeof v.a === 'function' && 'm' in v) { g = k; break; }
  }
  const token = await new Promise((res) => {
    let settled = false;
    let watchdog = null;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (watchdog) clearTimeout(watchdog);
      res(value);
    };
    w.__p = ch.payload;
    w.__done = finish;
    // --bindings=<json> fills content_bindings, the one piece of server data other
    // than the program itself that the bytecode reads. The loader marshals it into
    // an object and hands it to the VM as the second callback element, so this is
    // where a flag-gated branch can be switched on from outside.
    // --args=<json> overrides the trailing flags of the entry call.
    const BIND = (process.argv.find((a) => a.startsWith('--bindings=')) || '').slice(11);
    const ARGS = (process.argv.find((a) => a.startsWith('--args=')) || '').slice(7);
    // The loader builds it as `var h = [ja()]`, where ja() folds content_bindings
    // into ONE object — so the bindings are h[0], the array's only element, not a
    // second element beside an empty one.
    const hInit = BIND ? '[' + BIND + ']' : '[{}]';
    const tail = ARGS || 'false,undefined,undefined,undefined,undefined,true';
    watchdog = setTimeout(() => finish(null), 30000);
    w.eval('(function(){var h=' + hInit + ';window.' + g + '.a(window.__p,function(e){return void e(window.__done,h)},' + tail + ');})();');
  });

  console.log('build     : ' + BUILD_SHA + '   token ' + (token && token.length));
  const queuedCalls = seq.filter((op) => !Number.isInteger(op)).length;
  const opcodeFetches = seq.length - queuedCalls;
  console.log('dispatcher calls: ' + seq.length + '  (' + opcodeFetches
    + ' outer opcode fetches, ' + queuedCalls + ' queued-handler dispatches)');
  const queueBursts = [];
  for (let i = 0; i < seq.length; ) {
    if (Number.isInteger(seq[i])) { i++; continue; }
    const start = i;
    while (i < seq.length && !Number.isInteger(seq[i])) i++;
    queueBursts.push({ owner: start ? seq[start - 1] : null, length: i - start });
  }
  if (queueBursts.length) {
    const lengths = new Map(), owners = new Map();
    for (const b of queueBursts) {
      lengths.set(b.length, (lengths.get(b.length) || 0) + 1);
      owners.set(b.owner, (owners.get(b.owner) || 0) + 1);
    }
    console.log('queue bursts    : ' + queueBursts.length + '   lengths '
      + [...lengths].sort((a, b) => a[0] - b[0]).map(([n, k]) => n + '×' + k).join(', '));
    console.log('queue owners    : ' + [...owners].sort((a, b) => b[1] - a[1])
      .map(([op, n]) => String(op) + '×' + n).join(', '));
    console.log('queued bodies   : ' + new Set(queuedSources.filter(Boolean)).size + ' distinct source texts');
  }
  if (WANT_OUTPUT_KEY) {
    console.log('token SHA-256  : ' + crypto.createHash('sha256').update(token || '').digest('hex'));
    if (outputKey) console.log('SG_SS output key: slot ' + outputKey.slot
      + ' words [' + outputKey.words.join(', ') + ']  k1=' + (outputKey.k1 >>> 0)
      + ' k2=' + (outputKey.k2 >>> 0)
      + '  (signed ' + outputKey.k1 + ', ' + outputKey.k2 + ')');
    else console.log('SG_SS output key: NOT CAPTURED');
  }
  if (watchFor !== null) {
    console.log('');
    console.log('watching for ' + watchFor + ' (0x' + (watchFor >>> 0).toString(16) + ') in the register file:');
    if (!watchHits.length) console.log('  never appears as a plain number in a slot');
    for (const h of watchHits) console.log('  step ' + String(h.step).padStart(5) + '   slot ' + String(h.slot).padStart(4)
      + '   after opcode ' + String(h.op).padStart(4) + '   bit ' + (h.pc === null ? '?' : h.pc));
  }
  if (EMIT_LOG) {
    console.log('');
    console.log('record writes : ' + emits.length);
    const tally = {};
    for (const e of emits) tally[e[0]] = (tally[e[0]] || 0) + 1;
    console.log('  by helper   : ' + Object.entries(tally).map(([k, v]) => k + '=' + v).join(' '));
    for (let i = 0; i < Math.min(emits.length, 20); i++) {
      const x = emits[i];
      console.log('    #' + String(i).padStart(3) + '  ' + x[0] + '  '
        + (typeof x[1] === 'number' ? x[1] + ' (0x' + (x[1] >>> 0).toString(16) + ')' : typeof x[1] + ' ' + String(x[1]).slice(0, 46)));
    }
    const want = process.argv.find((x) => x.startsWith('--find='));
    if (want) {
      const target = Number(want.slice(7));
      const hits = emits.map((e, i) => [i, e]).filter(([, e]) => e[1] === target);
      console.log('looking for value ' + target + ' (0x' + (target >>> 0).toString(16) + '): '
        + (hits.length ? hits.length + ' hit(s)' : 'NOT WRITTEN BY ANY EMIT'));
      for (const [i, e] of hits) {
        console.log('  write #' + i + '   helper ' + e[0] + '   bit ' + (e[2] === null ? '?' : e[2]));
        for (let k = Math.max(0, i - 4); k <= Math.min(emits.length - 1, i + 4); k++) {
          const x = emits[k];
          console.log('     ' + (k === i ? '>>' : '  ') + ' #' + String(k).padStart(3) + '  ' + x[0]
            + '  ' + (typeof x[1] === 'number' ? x[1] + ' (0x' + (x[1] >>> 0).toString(16) + ')' : String(x[1]).slice(0, 40))
            + '   bit ' + (x[2] === null ? '?' : x[2]));
        }
      }
    }
  }
  if (originAt !== null) {
    // Several buffers are written through the same hook — the record, the 50-byte
    // itinerary, and a few hundred scratch arrays. Take the longest ASCENDING RUN
    // across all of them, the way record-recover.cjs does: picking the longest
    // BUFFER and then its last pass is not the same thing, and on this build it
    // returned the 50-byte itinerary while the 611-byte record sat in the data.
    const byBuf = new Map();
    for (const e of origins) { const l = byBuf.get(e[4]) || []; l.push(e); byBuf.set(e[4], l); }
    let run = [];
    for (const [, l] of byBuf) {
      let cur = [];
      for (let i = 0; i < l.length; i++) {
        if (cur.length && l[i][0] !== cur[cur.length - 1][0] + 1) { if (cur.length > run.length) run = cur; cur = []; }
        cur.push(l[i]);
      }
      if (cur.length > run.length) run = cur;
    }
    console.log('');
    console.log('record bytes seen : ' + run.length);
    console.log('buffers pushed to : ' + diagList.length);
    for (const d of diagList.sort((x, y) => y.n - x.n).slice(0, 6)) {
      console.log('    ' + String(d.n).padStart(5) + ' numeric pushes   keystream sibling: '
        + (d.ks ? d.ks : 'НЕ НАЙДЕН  (props: ' + (d.keys || '') + ')'));
    }
    let target = originAt;
    if (findBytes) {
      target = -1;
      for (let i = 0; i + findBytes.length <= run.length; i++) {
        let ok = true;
        for (let k = 0; k < findBytes.length; k++) if (run[i + k][1] !== findBytes[k]) { ok = false; break; }
        if (ok) { target = run[i][0]; break; }
      }
      console.log('tag ' + OFIND.slice(14) + (target < 0 ? ' : not in the record' : ' found at record offset ' + target));
      if (target < 0) return;
    }
    // How concentrated the serialisation is. Part 3 §10 says collection and
    // serialisation are separated in time; this counts by how much.
    const byPoint = new Map();
    for (const [, , op, pc] of run) {
      const key = op + '@' + pc;
      byPoint.set(key, (byPoint.get(key) || 0) + 1);
    }
    const pts = [...byPoint.entries()].sort((a, b) => b[1] - a[1]);
    console.log('program points that wrote it : ' + pts.length);
    for (const [k, n] of pts.slice(0, 5)) {
      const [op, pc] = k.split('@');
      console.log('    ' + String(n).padStart(4) + ' bytes  (' + (100 * n / run.length).toFixed(1) + '%)   opcode '
        + op.padStart(4) + '   bit ' + pc);
    }
    const base = run[0][0];
    const lo = Math.max(base, target - 6), hi = target + 8;
    console.log('who wrote record bytes ' + lo + '..' + hi + ':');
    for (const [idx, plain, op, pc] of run) {
      if (idx < lo || idx > hi) continue;
      console.log('  @' + String(idx).padStart(4) + '  0x' + plain.toString(16).padStart(2, '0')
        + '   opcode ' + String(op).padStart(4) + '   bit ' + (pc === null ? '?' : pc));
    }
  }
  console.log('');
  console.log('first 24 opcodes executed:');
  console.log('  ' + seq.slice(0, 24).join(' '));
  console.log('');
  const counts = new Map();
  for (const o of seq) counts.set(o, (counts.get(o) || 0) + 1);
  if (process.argv.includes('--set')) {
    const all=[...new Set(seq)].sort((a,b)=>a-b);
    console.log('distinct opcodes dispatched: '+all.length);
    console.log('  '+all.join(' '));
    for (const q of (process.argv.find(a=>a.startsWith('--is='))||'--is=').slice(5).split(',').filter(Boolean))
      console.log('  opcode '+q+' dispatched: '+(new Set(seq).has(Number(q))?'YES':'NO'));
  }
  const __DUMPSET=1;
  console.log('most executed: ' + [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8)
    .map(([o, n]) => (Number.isInteger(o) ? o : '[queued]') + '×' + n).join('  '));
  console.log('');
  if (seeded) {
    console.log('register file at the first dispatch (build seeds):');
    for (const k of Object.keys(seeded).sort((a, b) => a - b)) {
      const e = seeded[k];
      console.log('  s' + k.padEnd(4) + ' ' + e.t + (e.v !== undefined ? '  ' + JSON.stringify(e.v).slice(0, 60) : '')
        + (e.ctor ? '  keys=[' + (e.keys || []).join(',') + ']  value=' + JSON.stringify(e.boxed) : ''));
    }
    console.log('');
  }
  if (process.argv.includes('--coverage')) {
    const imgBits = Buffer.from(ch.payload.slice(3), 'base64').length * 8;
    const covered = blocks.size * 64;
    // Report it, but do not trust it as coverage. Two things spoil it: the block
    // field is sampled once per dispatch, so blocks an instruction crossed while
    // reading operands are missed; and the field's NAME is build-scoped, so this
    // reads 0 on 885c049eda50. It is a lower bound on one build, not a number to
    // publish. The honest coverage figure still comes from trace-disasm.cjs.
    console.log('blocks touched : ' + blocks.size + ' of ' + Math.ceil(imgBits / 64)
      + '  (~' + (100 * covered / imgBits).toFixed(1) + '%)'
      + '   LOWER BOUND — sampled once per dispatch, field name is build-scoped');
    console.log('');
  }
  if (WANT_PCS) {
    const good = pcs.filter(Boolean).length;
    const out = path.join(R_, 'records',
      'pc-trace-' + BUILD_SHA + '-' + path.basename(capture).replace(/\.html$/, '') + '.json');
    fs.writeFileSync(out, JSON.stringify({
      build: BUILD_SHA,
      capture: path.basename(capture),
      liveCursorSlot: DERIVED.liveCursor ?? DERIVED.programCounter,
      instructionStartSlot: PC_SLOT,
      dispatcherCalls: seq.length,
      opcodeFetches,
      queuedDispatches: queuedCalls,
      queueBursts,
      queuedHandlerSourceCount: new Set(queuedSources.filter(Boolean)).size,
      outputKey,
      pcs,
    }));
    console.log('pc trace       : ' + good + '/' + opcodeFetches + ' opcode fetches carried an instruction start'
      + (pcErr ? '   first failure: ' + pcErr : ''));
    if (queuedCalls) console.log('queued dispatch: ' + queuedCalls
      + ' handler calls used state.o/state.N and fetched no outer opcode');
    console.log('wrote          : ' + path.relative(R_, out));
    console.log('');
  }
  console.log('large state-field changes (candidate re-keys):');
  for (const k of keyChanges.slice(0, 8)) {
    console.log('  after op ' + String(k.afterOp).padStart(4) + '  ' + k.field + ': ' + k.from + ' -> ' + k.to);
  }
  if (!keyChanges.length) console.log('  (none seen)');
  try { w.close(); } catch (e) {}
})();
