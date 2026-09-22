'use strict';
// ============================================================================
//  build-profile.cjs — assemble one capture-specific VM profile after its build
//  has been manually bootstrapped and reviewed.
//
//  Six separate discoveries have to line up before anything can read a build
//  nobody has looked at:
//
//    build-compare.cjs     which build this page is on
//    build-primitives.cjs  the interpreter's primitives, by shape
//    dump-handlers.cjs     the opcode handlers, filtered by the interpreter's tag
//    opcode-table.cjs      each handler's operand layout
//    opcode-roles.cjs      the roles a walk needs semantics for
//    opcode-trace.cjs      the two roles a source signature cannot see
//
//  For a build already recorded in KNOWN_BUILDS, this command runs the remaining
//  capture and derivation chain and writes the result. An unseen build still needs
//  the full repository's tools/build-primitives.cjs, an opcode trace and a reviewed
//  KNOWN_BUILDS entry before this command can proceed.
//
//     node build-profile.cjs --html=capture.html --out=profile-<sha>-<capture>.json
//
//  The profile is data, not code: layouts, role numbers, primitive names, the
//  handler tag. Feed it to static-disasm.cjs with --profile= instead of relying
//  on cases hardcoded for one build.
// ============================================================================
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseChallenge } = require('./lib/challenge.js');
const { capture, findTag, PRESETS } = require('./dump-handlers.cjs');
const { derive } = require('./opcode-table.cjs');
const { roles } = require('./opcode-roles.cjs');
const { params: cipherParams, verify: cipherVerify } = require('./cipher-params.cjs');

const argv = process.argv.slice(2);
const optOf = (n, d) => { const h = argv.find((a) => a.startsWith('--' + n + '=')); return h ? h.slice(n.length + 3) : d; };

// What each build's store primitives are called and in which order they take
// their arguments. From build-primitives.cjs — and the metamorphic twins do NOT
// share a parameter order, which is the trap this table exists to record.
const { KNOWN_BUILDS } = require('./lib/builds.js');

// A variadic call handler is recognised by what it DOES with the frame it just
// read, which is stable across builds, rather than by the shape of the call to
// the argument-list helper, which is not — `Uy(18, 2, a, 1)` puts the state
// third, `Ua(26, O, 2, 4)` puts it second.
//
//   call form         `p.apply(H, v.l)`        old 192   new 126, 170
//   constructor form  `new Q[H](v[0], v[1])`   old 412   new 57
const APPLY = /\.apply\(/;
const NEW_INDEXED = /new\s+[A-Za-z_$][\w$]*\[[A-Za-z_$][\w$]*\]\(/;
function isVariadic(src) {
  return typeof src === 'string' && (APPLY.test(src) || NEW_INDEXED.test(src));
}
/**
 * A whitespace- and parenthesis-insensitive identity for a handler.
 *
 * The same function reaches the profile by two routes and does not look the same
 * either way: the interpreter's own handlers come from the pretty-printed lifted
 * source, and the ones DEF_OPCODE installs come back from `toString` minified.
 * Prettier also adds parentheses the original did not have —
 *
 *   485   ((p = B(((v = c(((m = ((H = z(a, 79)), z(a, 69))), H), a) != 0), m), a)), …)
 *    12   p=B((v=c((m=(H=z(a,79),z(a,69)),H),a)!=0,m),a),…
 *
 * — so exact text matches nothing, and opcodes 9, 12 and 98 were not recognised
 * as aliases of 485, 451 and 346. Without that, the control-flow group holds two
 * distinct handlers per operand layout, nothing can be told apart by layout, and
 * the walk resolves no calls at all: 58 on the hand-written path, 0 on the
 * profile path.
 *
 * Comparing the token stream with parentheses dropped identifies them exactly.
 */
const keyCache = new Map();
function sourceKey(src) {
  if (typeof src !== 'string') return null;
  if (keyCache.has(src)) return keyCache.get(src);
  let out;
  try {
    const acorn = require('acorn');
    const raw = [];
    for (const t of acorn.tokenizer('(' + src + ')', { ecmaVersion: 2020 })) {
      raw.push(t.value === undefined ? t.type.label : String(t.value));
    }
    // Parentheses, semicolons and trailing commas are all things a printer adds
    // or removes. Opcode 9 and opcode 485 differ by exactly one semicolon.
    const toks = [];
    for (let i = 0; i < raw.length; i++) {
      const v = raw[i];
      if (v === '(' || v === ')' || v === ';') continue;
      if (v === ',' && raw[i + 1] === ')') continue;
      toks.push(v);
    }
    out = toks.join('\u0001');
  } catch (e) { out = src.replace(/\s+/g, ''); }
  keyCache.set(src, out);
  return out;
}

const isDefOpcode = (src) => typeof src === 'string' && /\beval\b|\bFunction\b/.test(src);

/**
 * The role of a handler that did not exist when the profile was taken.
 *
 * DEF_OPCODE installs handlers at run time, and one of the things it installs is
 * another DEF_OPCODE under a second number — so a walk that only knows the
 * numbers in the profile stops at the first of those (measured: opcode 115 on
 * 885c049eda50, at 203 instructions). The source is in hand at that moment, so
 * the same shape tests that built the profile answer the question again.
 */
function roleOfSource(src, aliases, pc) {
  if (isDefOpcode(src)) return 'defOpcode';
  if (isVariadic(src)) return 'variadic';
  try {
    const r = roles({ 0: src }, pc);
    if (r.string.length) return 'string';
    if (r.control.length) return 'control';
  } catch (e) { /* not parseable as a handler */ }
  return null;
}

async function build(htmlPath) {
  const html = fs.readFileSync(htmlPath, 'utf8');
  const ch = parseChallenge(html);
  const sha = crypto.createHash('sha256').update(ch.vm).digest('hex').slice(0, 12);
  const known = KNOWN_BUILDS[sha];
  if (!known) {
    throw new Error('build ' + sha + ' has no reviewed bootstrap entry. In the full '
      + 'repository run tools/build-primitives.cjs and opcode-trace.cjs against the '
      + 'capture, then add and review KNOWN_BUILDS.');
  }
  // Resolve the deobfuscated interpreter by BUILD first, the way opcode-trace.cjs
  // does. The name in the table is only a last-resort hint: this repo keeps one
  // file per build and names them apart, a published bundle keeps one capture and
  // names it plainly, and hardcoding either convention breaks the other. It used
  // to break the bundle — every entry there was rewritten to `vm-readable.js`, so
  // a reader with a fourth-build capture got ENOENT on the first build's filename.
  const dir = path.join(__dirname, 'lifted-source');
  const candidates = [
    optOf('readable', null),
    'vm-readable-' + sha + '.js',
    known.readable,
    'vm-readable.js',
  ].filter(Boolean);
  const readablePath = candidates
    .map((f) => (path.isAbsolute(f) ? f : path.join(dir, f)))
    .find((f) => fs.existsSync(f));
  if (!readablePath) {
    throw new Error('no deobfuscated interpreter for build ' + sha + '. Looked for '
      + candidates.join(', ') + ' under ' + dir + '. Run: node vm-deobfuscate.cjs --html='
      + path.basename(htmlPath) + ' --no-rename --out=vm-readable-' + sha + '.js');
  }
  const readableSrc = fs.readFileSync(readablePath, 'utf8');

  const r = await capture({ html, readableSrc, stores: known.stores });
  if (r.err) throw new Error('handler capture: ' + r.err);
  const tag = findTag(r.stored);
  const taggedStored = tag ? r.stored.filter((s) =>
    Object.prototype.hasOwnProperty.call(s.props, tag.k)
      && ((Number(s.props[tag.k]) | 0) & 0x800) !== 0) : [];
  const installedSlots = [...new Set(taggedStored
    .map((s) => Number(s.slot)).filter(Number.isInteger))].sort((a, b) => a - b);
  const tagValues = {};
  const bodiesBySlot = new Map();
  for (const s of taggedStored) {
    const v = String(s.props[tag.k]);
    tagValues[v] = (tagValues[v] || 0) + 1;
    const slot = Number(s.slot);
    if (Number.isInteger(slot)) {
      if (!bodiesBySlot.has(slot)) bodiesBySlot.set(slot, new Set());
      bodiesBySlot.get(slot).add(s.src);
    }
  }
  const redefinedSlots = Object.fromEntries([...bodiesBySlot]
    .filter(([, bodies]) => bodies.size > 1)
    .map(([slot, bodies]) => [slot, bodies.size]));

  // Filter with the dispatcher's bit guard, not exact value equality. The value
  // is a section stamp: on 885c049eda50 the handlers carry `{"": 2796}` and
  // `{"": 133120}` in two groups, and keeping only the commonest value drops fourteen real
  // opcodes — among them 8, 49 and 88, which the walk needs for its register
  // values. With the value ignored the derivation scores 20 correct, 0 wrong
  // against the hand-written table; with it, 17 and six of the misses are simply
  // absent.
  // Two sources, and the dispatcher is the better one.
  //
  // Tapping the store primitives only sees handlers the PROGRAM installs — never
  // the ones the interpreter shipped with, and those are what a walk meets first:
  // opcode 134 on c348580f3670 stopped it at 24 instructions, and 115, 10, 11 and
  // 37 are the same gap on the old build, which is why the disassembler carried a
  // hand-written alias table.
  //
  // Snapshotting the opcode table after the run does not fix it either: opcodes
  // and registers share one slot space, so the program overwrites every handler
  // slot with data before it finishes — 346 numeric slots at the end, not one
  // function among them.
  //
  // The dispatcher sees each opcode with its handler at the moment it runs,
  // whatever installed it. That takes 46 opcodes to 84 on the old build, and it
  // recovers the aliases as a side effect: opcode 115 arrives holding the
  // DEF_OPCODE body, 22 the string decoder, 27 the byte loader.
  // Order matters, and it is the installed handler that wins.
  //
  // Opcodes and registers share one slot space, so the program overwrites opcode
  // slots as it runs and an opcode's meaning changes over the program's life. On
  // 885c049eda50, slots 101 and 123 are both holding one re-installed two-operand
  // handler by the time they are first dispatched, and taking the dispatched body
  // derives VV for both where the truth at the start of the program is V and VVV.
  //
  // So: the first handler INSTALLED at a slot decides its layout, and the
  // dispatcher fills in every opcode that was never installed — the ones the
  // interpreter shipped with, which the store tap cannot see at all.
  const handlers = {};
  for (const s of taggedStored) {
    if (!(s.slot in handlers)) handlers[s.slot] = s.src;
  }
  for (const s of r.table || []) {
    if (Number.isInteger(s.slot) && s.src && !(s.slot in handlers)) handlers[s.slot] = s.src;
  }

  // The stream cipher over the program image is build-scoped too, and a wrong
  // keystream is noise rather than a degraded result — so it is read out of the
  // interpreter and then checked against a plaintext byte that is known before
  // anything is decrypted. See cipher-params.cjs.
  const sr = sourceRoles(readableSrc);
  const { keyCtlSlot, streamSlots, programCounter, pcShadow, registerFile } = sr;
  const cipher = cipherParams(readableSrc);
  const cipherOk = cipher.err ? null : cipherVerify(ch.payload, known.alphabet, cipher);

  const { reader, aliases, table } = derive(handlers);
  // Derived, not looked up. known.pc stays as a cross-check: if the two ever
  // disagree the derivation has drifted and the caller should hear about it
  // rather than silently trace the wrong slot.
  if (known.registerFile && registerFile && registerFile !== known.registerFile) {
    console.error('warning: derived register file .' + registerFile
      + ' disagrees with the recorded .' + known.registerFile + ' for build ' + sha);
  }
  if (known.pc != null && programCounter !== known.pc) {
    console.error('warning: derived program counter ' + programCounter
      + ' disagrees with the recorded ' + known.pc + ' for build ' + sha);
  }
  if (known.instructionStart != null && pcShadow !== known.instructionStart) {
    console.error('warning: derived instruction-start slot ' + pcShadow
      + ' disagrees with the recorded ' + known.instructionStart + ' for build ' + sha);
  }
  const found = roles(handlers, programCounter);

  // DEF_OPCODE — the instruction that installs a new handler at run time. It is
  // the one handler whose source contains `eval`, on every build seen so far, and
  // it has to be known: the opcodes it installs are NOT in this table (they do
  // not exist yet when the table is captured), so without it a profile-driven
  // walk stops at the first program-installed opcode. Measured on the old build:
  // 7 instructions instead of 400.
  const defOpcode = Object.keys(handlers)
    .filter((k) => /\beval\b|\bFunction\b/.test(handlers[k]))
    .map(Number)
    .sort((a, b) => a - b);

  // Variable-arity calls. A layout written as letters cannot describe them: the
  // operand count is an operand. They do not read the stream themselves either —
  // they hand the state to an argument-list helper, `Uy(18, 2, a, 1)`, which
  // consumes the whole call frame at once. So they are found by that call shape:
  // four arguments, three of them numeric literals, the remaining one the state
  // (or a field of it — the constructor form passes `a.R`).
  const variadic = Object.keys(handlers)
    .filter((k) => isVariadic(handlers[k]))
    .map(Number)
    .sort((a, b) => a - b);

  const layouts = {};
  const variable = [];
  // The instructions that write the record. The derivation already names the
  // helper each one calls, and there are two families per build — `lP` and `Ru`
  // on 885c049eda50, `uz` and `Oz` on c348580f3670. That is enough to LABEL them
  // in a listing; it is not enough to separate the four kinds the hand-written
  // cases distinguish (length-prefixed, u8, u32, number), because each family
  // covers two of them. Recorded as the family, not guessed as the kind.
  const emit = {};
  for (const [op, d] of Object.entries(table)) {
    layouts[op] = d.layout;
    if (d.variable) variable.push(Number(op));
    const m = /^emit (\S+)/.exec(d.via || '');
    if (m) emit[op] = m[1];
  }
  variable.sort((a, b) => a - b);

  // One handler, many opcode numbers. The program installs the same function
  // under several numbers, so a role found for one of them holds for all of
  // them — and a walk that knows only the representative stops dead at the first
  // alias (measured: opcode 115, an alias of DEF_OPCODE 149, at 203
  // instructions). The grouping is exact source identity, so it needs no table:
  // static-disasm.cjs used to carry one, written by hand for this build.
  const groups = new Map();
  for (const [slot, src] of Object.entries(handlers)) {
    const k = sourceKey(src);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(Number(slot));
  }
  const expand = (list) => {
    const out = new Set();
    for (const op of list) {
      out.add(op);
      const k = handlers[op] && sourceKey(handlers[op]);
      if (k && groups.has(k)) for (const a of groups.get(k)) out.add(a);
    }
    return [...out].sort((a, b) => a - b);
  };
  const aliasGroups = [...groups.values()].filter((g) => g.length > 1);

  // Split the control-flow group into the three roles a walk needs to tell apart.
  //
  // A source signature finds the group; it does not say which member is the call
  // and which the return. Layout does — the call reads one operand, the
  // conditional two, the return a count byte and then that many — but only once
  // aliases are folded together. Before that, `V` matched three opcodes (98, 120,
  // 346) that are one handler under three numbers, the class looked ambiguous,
  // and nothing was assigned.
  const controlSet = expand(found.control.filter((c) => !defOpcode.includes(c) && !variadic.includes(c)));
  const control = { call: [], cond: [], ret: [] };
  {
    const byGroup = new Map();
    for (const op of controlSet) {
      const k = handlers[op] && sourceKey(handlers[op]);
      if (!k) continue;
      if (!byGroup.has(k)) byGroup.set(k, []);
      byGroup.get(k).push(op);
    }
    const classes = { call: [], cond: [], ret: [] };
    for (const [, ops] of byGroup) {
      const lay = ops.map((o) => (table[o] && table[o].layout)).find(Boolean);
      if (!lay) continue;
      const c = lay[0] === 'B' ? 'ret' : lay === 'V' ? 'call' : lay === 'VV' ? 'cond' : null;
      if (c) classes[c].push(ops);
    }
    for (const c of ['call', 'cond', 'ret']) {
      if (classes[c].length === 1) control[c] = classes[c][0].sort((a, b) => a - b);
    }
  }

  return {
    build: sha,
    capturedFrom: path.basename(htmlPath),
    interpreterChars: ch.vm.length,
    bytecodeChars: ch.payload.length,
    token: r.token ? r.token.length : null,
    tokenSha256: r.token ? crypto.createHash('sha256').update(r.token).digest('hex') : null,
    primitives: {
      registerFile: registerFile || known.registerFile,
      operandReader: reader,
      // identifiers that hold the interpreter state outside the parameter list —
      // a build can keep it in a closure and read operands through either name
      stateAliases: aliases,
      stores: known.stores.map((s) => s.name),
      handlerTag: tag ? { property: tag.k, commonestValue: tag.v, onCount: tag.n } : null,
    },
    installation: {
      taggedStores: taggedStored.length,
      distinctSlots: installedSlots.length,
      slots: installedSlots,
      tagValues,
      redefinedSlots,
    },
    roles: {
      programCounter,
      liveCursor: programCounter,
      keyCtlSlot,
      pcShadow,
      instructionStart: pcShadow,
      streamSlots,
      outputKeySlot: known.outputKeySlot != null ? known.outputKeySlot : null,
      outputKeyWords: known.outputKeyWords || null,
      // a handler that installs opcodes is not a branch, whatever its shape
      // a handler that installs opcodes, or that applies a call frame, is not a
      // branch however its control flow is written
      control: controlSet,
      call: control.call,
      cond: control.cond,
      ret: control.ret,
      defOpcode: expand(defOpcode),
      variadic: expand(variadic),
      string: expand(found.string),
      // These two do not yield to a source signature on every build; the numbers
      // come from opcode-trace.cjs, which reads them off behaviour instead.
      alphabet: expand([known.alphabet]),
      rekeyVia: expand([known.rekeyVia]),
    },
    cipher: cipher.err ? { err: cipher.err } : {
      fn: cipher.fnName,
      rounds: cipher.rounds,
      roundConst: cipher.roundConst,
      rot: cipher.rot,
      verified: !!(cipherOk && cipherOk.ok),
      firstPlainByte: cipherOk ? cipherOk.plain : null,
      expected: cipherOk ? cipherOk.want : null,
    },
    // operand counts that depend on run-time data — see opcode-table.cjs
    variableLayout: variable,
    emit,
    handlerCount: Object.keys(handlers).length,
    dispatched: (r.table || []).filter((x) => Number.isInteger(x.slot)).length,
    aliasGroups,
    layouts,
    // The handler BODIES, not just their operand shapes. A profile carrying only
    // layouts describes how to walk the bytecode; carrying the sources describes
    // how to RUN it, which a separate interpreter implementation needs. They are a
    // property of the build, so this is captured once per sha and then reused for
    // every challenge that build serves.
    sources: handlers,
  };
}

// Everything about a build that can be read straight out of its deobfuscated
// source, with no capture and no run. Four numbers a walk cannot work without —
// and every one of them used to be typed in by hand, which is exactly how a
// trace on 80056f9da7b2 came back empty: it was handed the previous build's
// key-control slot and threw on an unrelated read.
function sourceRoles(src) {
  // The re-key is a special case of the property write: writing to one particular
  // slot reloads the stream key and resets the block. The interpreter says which
  // slot, in as many words —
  //
  //   old   e == 28  && ((U.L = W(32, U, false)),  (U.Y = void 0));
  //   new   I == 292 && ((p.P = LC(false, 32, p)), (p.h = void 0));
  // It also names the two state fields the stream cipher lives in: the key it
  // reloads, and the decoded-block cache it drops. Both were typed into
  // opcode-trace.cjs as build 3's letters, and on build 4 `.N` happens to be the
  // REGISTER FILE — so `state.N | 0` recorded 0 as the key for every instruction
  // and a trace-driven decode had nothing to decrypt with.
  const keyCtlM = /==\s*(\d+)\s*&&\s*\(\(\s*\w+\.(\w+)\s*=\s*([A-Za-z_$][\w$]*)\([^)]*\b32\b[^)]*\)\s*\)\s*,\s*\(\s*\w+\.(\w+)\s*=\s*void 0\s*\)\)/.exec(src);
  const keyCtlSlot = keyCtlM ? Number(keyCtlM[1]) : null;
  const keyField = keyCtlM ? keyCtlM[2] : null;
  const bitReaderName = keyCtlM ? keyCtlM[3] : null;
  const blockField = keyCtlM ? keyCtlM[4] : null;

  // The program counter and its shadow are the two slots the store EXTENDS rather
  // than replaces — written as `slot == A || slot == B` in every store twin.
  const streamM = /\(\s*(\w+)\s*==\s*(\d+)\s*\|\|\s*\1\s*==\s*(\d+)\s*\)/.exec(src);
  const streamSlots = streamM ? [Number(streamM[2]), Number(streamM[3])] : [];
  // Telling the two apart by whole-file frequency is unsafe: unrelated flattened
  // code can contain either small integer many times. Instead, find the function
  // used to read the 32-bit stream key and inspect that function alone. It is the
  // bytecode bit reader, so exactly one of the extend-only slots in its body is
  // the live cursor. The other slot is where the dispatcher saves the instruction
  // start immediately before it reads the opcode.
  let bitReaderSrc = '';
  if (bitReaderName) {
    try {
      const acorn = require('acorn');
      const ast = acorn.parse(src, { ecmaVersion: 2020 });
      const stack = [ast];
      while (stack.length && !bitReaderSrc) {
        const n = stack.pop();
        if (!n || typeof n !== 'object') continue;
        const assigned = n.type === 'AssignmentExpression' && n.operator === '='
          && n.left && n.left.type === 'Identifier' && n.left.name === bitReaderName
          ? n.right
          : n.type === 'VariableDeclarator' && n.id && n.id.type === 'Identifier'
            && n.id.name === bitReaderName ? n.init : null;
        if (assigned && (assigned.type === 'FunctionExpression' || assigned.type === 'ArrowFunctionExpression')) {
          bitReaderSrc = src.slice(assigned.start, assigned.end);
          break;
        }
        for (const v of Object.values(n)) {
          if (Array.isArray(v)) for (let i = v.length - 1; i >= 0; i--) stack.push(v[i]);
          else if (v && typeof v === 'object' && typeof v.type === 'string') stack.push(v);
        }
      }
    } catch (e) { /* fall through to the conservative frequency fallback */ }
  }
  const readerSlots = streamSlots.filter((n) => new RegExp('\\b' + n + '\\b').test(bitReaderSrc));
  const freq = (n) => (src.match(new RegExp('\\b' + n + '\\b', 'g')) || []).length;
  const programCounter = streamSlots.length === 2
    ? (readerSlots.length === 1 ? readerSlots[0]
      : (freq(streamSlots[0]) >= freq(streamSlots[1]) ? streamSlots[0] : streamSlots[1]))
    : null;
  const pcShadow = streamSlots.find((x) => x !== programCounter);

  // The register file — the property on the state object holding the slot array.
  // The extend branch names it twice in one expression, which is a shape no other
  // line in the file has: `y.N[b] ? y.N[b].concat(...)`.
  const rfM = /(\w+)\.(\w+)\[(\w+)\]\s*\?\s*\1\.\2\[\3\]\.concat\(/.exec(src);
  const registerFile = rfM ? rfM[2] : null;

  return {
    keyCtlSlot, keyField, blockField, streamSlots,
    programCounter, pcShadow,
    liveCursor: programCounter,
    instructionStart: pcShadow,
    registerFile,
  };
}

module.exports = { build, sourceRoles, roleOfSource, isVariadic, isDefOpcode, KNOWN_BUILDS };

if (require.main !== module) return;

(async () => {
  const htmlArg = optOf('html', 'response.html');
  const htmlPath = path.isAbsolute(htmlArg) ? htmlArg : path.join(__dirname, 'captures', htmlArg);
  let p;
  try { p = await build(htmlPath); }
  catch (e) { console.error('failed: ' + e.message); process.exit(1); }

  console.log('build           : ' + p.build + '   (' + p.interpreterChars + ' chars, bytecode ' + p.bytecodeChars + ')');
  console.log('capture         : ' + p.capturedFrom + '   token ' + p.token);
  console.log('register file   : .' + p.primitives.registerFile);
  console.log('operand reader  : ' + p.primitives.operandReader
    + (p.primitives.stateAliases.length ? '   aliases ' + p.primitives.stateAliases.join(' ') : ''));
  console.log('stores          : ' + p.primitives.stores.join(' '));
  console.log('handler tag     : ' + (p.primitives.handlerTag
    ? 'property ' + JSON.stringify(p.primitives.handlerTag.property) + ', value & 0x800' : '(none)'));
  console.log('runtime installs: ' + p.installation.taggedStores + ' tagged writes / '
    + p.installation.distinctSlots + ' distinct slots   stamps '
    + Object.entries(p.installation.tagValues).map(([v, n]) => v + '×' + n).join(', '));
  if (Object.keys(p.installation.redefinedSlots).length) console.log('slot rewrites   : '
    + Object.entries(p.installation.redefinedSlots).map(([slot, n]) => slot + '×' + n + ' bodies').join(', '));
  console.log('handlers        : ' + p.handlerCount + ' (' + p.dispatched + ' seen at dispatch)   layouts '
    + Object.keys(p.layouts).length);
  console.log('cipher          : ' + (p.cipher.err ? 'NOT FOUND — ' + p.cipher.err
    : p.cipher.fn + '  rounds ' + p.cipher.rounds + ', const ' + p.cipher.roundConst
      + ', rot ' + p.cipher.rot + '   ' + (p.cipher.verified ? 'verified against the first opcode'
        : 'FAILS the first-opcode check (' + p.cipher.firstPlainByte + ' vs ' + p.cipher.expected + ')')));
  console.log('');
  console.log('roles');
  console.log('  live bit cursor : ' + p.roles.programCounter);
  console.log('  key-control slot: ' + (p.roles.keyCtlSlot != null ? p.roles.keyCtlSlot : '(not found)')
    + '   instruction start: ' + (p.roles.pcShadow != null ? p.roles.pcShadow : '(not found)'));
  console.log('  SG_SS key slot  : ' + (p.roles.outputKeySlot != null ? p.roles.outputKeySlot : '(not profiled)')
    + (p.roles.outputKeyWords ? '   words [' + p.roles.outputKeyWords.join(', ') + ']' : ''));
  console.log('  control flow    : ' + p.roles.control.join(', ')
    + '   [call ' + (p.roles.call.join('/') || '?')
    + '  cond ' + (p.roles.cond.join('/') || '?')
    + '  ret ' + (p.roles.ret.join('/') || '?') + ']');
  console.log('  string          : ' + p.roles.string.join(', '));
  console.log('  def-opcode      : ' + (p.roles.defOpcode.join(', ') || '(none found)'));
  console.log('  variadic call   : ' + (p.roles.variadic.join(', ') || '(none found)'));
  console.log('  emit            : ' + (Object.keys(p.emit).length
    ? Object.entries(p.emit).map(([o, h]) => o + ':' + h).join(' ') : '(none found)'));
  console.log('  variable length : ' + (p.variableLayout.join(', ') || '(none)')
    + '   (operand count depends on run-time data)');
  console.log('  alphabet        : ' + p.roles.alphabet.join(', '));
  console.log('  rekey via       : ' + p.roles.rekeyVia.join(', '));
  console.log('  source groups   : ' + (p.aliasGroups.length
    ? p.aliasGroups.map((g) => g.join('=')).join('  ') : '(none — every opcode is its own handler)'));
  console.log('                    identical source fixes layout; closures can still carry different programs');

  const out = optOf('out', null);
  if (out) {
    // A bare name lands next to the other profiles; anything carrying a separator
    // is a path the caller meant literally. Without the second case `--out=../results/
    // records/x.json` resolved under results/records/ and wrote results/results/
    // records/x.json — the file existed, just not where anyone would look for it.
    const dest = path.isAbsolute(out) ? out
      : out.includes('/') || out.includes(path.sep) ? path.resolve(out)
      : path.join(__dirname, 'records', out);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, JSON.stringify(p, null, 1));
    console.log('');
    console.log('wrote           : ' + path.relative(path.join(__dirname, '..'), dest));
  }
})();
