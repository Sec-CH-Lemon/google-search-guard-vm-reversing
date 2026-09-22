'use strict';
// ============================================================================
//  dump-handlers.cjs — capture a build's opcode handlers, and ONLY those.
//
//  opcode-table.cjs and opcode-roles.cjs both work off a map of
//  slot -> handler source. Producing that map by tapping the store primitive is
//  the obvious move, and it is what the first attempt did — but the store
//  primitive carries more than handlers. On build c348580f3670 the raw capture
//  put jsdom's own `createElement` and `appendChild` into the set, because the
//  interpreter had grabbed them and stored them in registers. Two of the four
//  semantic roles then failed to resolve against a polluted set.
//
//  The interpreter itself draws the line: it TAGS a function as an installed
//  handler at the moment it stores it (`Y[xA] = 2796` on the old build), and the
//  dispatcher checks that tag before calling. So the tag is the filter.
//
//  The tag's property name and value are build-scoped, so they are found by
//  shape: capture every stored function with its own properties, then take the
//  (name, value) pair that the most stored functions share. Environment
//  functions do not carry it.
//
//     node dump-handlers.cjs --html=capture.html --readable=vm-readable-X.js \
//                            --stores='g:X:p,R:X:p,N:I:X' --out=handlers.json
//
//  --stores lists the store primitives as name:slotParam:valueParam. Get them
//  from build-primitives.cjs — and mind that the metamorphic twins do NOT share
//  a parameter order.
// ============================================================================
const fs = require('fs');
const path = require('path');
const { parseChallenge } = require('./lib/challenge.js');
const { JSDOM } = require('jsdom');
const acorn = require('acorn');

const argv = process.argv.slice(2);
const optOf = (n, d) => { const h = argv.find((a) => a.startsWith('--' + n + '=')); return h ? h.slice(n.length + 3) : d; };

// The two builds looked at so far, so the common cases need no flags.
const PRESETS = {
  '885c049eda50': { readable: 'vm-readable.js', stores: 'w:e:X,C:e:X,R:U:X' },
  c348580f3670: { readable: 'vm-readable.js', stores: 'g:X:p,R:X:p,N:I:X' },
};

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

function capture({ html, readableSrc, stores }) {
  return new Promise((resolve) => {
    const ch = parseChallenge(html);
    let patched = readableSrc;
    for (const spec of stores) {
      // A word boundary is required: a plain indexOf for "g = function (" also
      // matches inside "Vg = function (", and the tap then lands on the wrong
      // function. On the old build the names w/C/R happened not to collide, so
      // the bug only showed on c348580f3670 — 6 stores captured instead of 103.
      const re = new RegExp('(?<![A-Za-z0-9_$])' + spec.name.replace(/\$/g, '\\$') + '\\s*=\\s*function\\s*\\(');
      const m = re.exec(patched);
      if (!m) return resolve({ err: 'store anchor not found: ' + spec.name });
      const open = patched.indexOf('{', m.index);
      // Hand the tap every parameter as well as the slot and the value. One of
      // them is the interpreter state, and the state is what holds the opcode
      // TABLE — `U.S[e] = fn`. Recording only the stores that pass through this
      // primitive misses every opcode the interpreter was born with, and those
      // are the ones a walk trips over first (measured: opcode 134 on
      // c348580f3670, at 24 instructions).
      const params = patched.slice(m.index + m[0].length, patched.indexOf(')', m.index + m[0].length))
        .split(',').map((x) => x.trim()).filter((x) => /^[A-Za-z_$][\w$]*$/.test(x));
      patched = patched.slice(0, open + 1)
        + " if (typeof __store === 'function') __store(" + spec.slot + ', ' + spec.value
        + (params.length ? ', [' + params.join(', ') + ']' : ', []') + ');'
        + patched.slice(open + 1);
    }

    // The dispatch site, by shape: a guarded call of the handler with the state
    // and the step budget, whose else-branch raises.
    //
    // Only the consequent is stable across builds. The else-branch's argument
    // order is not — 885c049eda50 writes `E(0, …)`, d4a6b4f0a2a5 writes
    // `ZY(K, 95, 0, [sr, 21, f])` — so anchoring on a leading 0 silently matched
    // nothing on the third build. The tap then never fired, the profile came back
    // "0 seen at dispatch", every base opcode lost its layout, and the walk died
    // on the first one it met. Match the consequent loosely instead and confirm
    // the site by the throw tuple `[tag, number, opcodeVar]` that the error path
    // always carries.
    {
      const D = /\?\s*([A-Za-z_$][\w$]*)\(([A-Za-z_$][\w$]*),\s*([A-Za-z_$][\w$]*)\)\s*:\s*([A-Za-z_$][\w$]*)\(/g;
      const TUPLE = /\[\s*[A-Za-z_$][\w$]*\s*,\s*\d+\s*,\s*([A-Za-z_$][\w$]*)\s*\]/;
      for (let dm; (dm = D.exec(patched)); ) {
        const opVar = (TUPLE.exec(patched.slice(dm.index, dm.index + 300)) || [])[1];
        if (!opVar) continue;
        patched = patched.replace(dm[0],
          '? (typeof __dispatch === "function" && __dispatch(' + opVar + ', ' + dm[1] + '), '
          + dm[1] + '(' + dm[2] + ', ' + dm[3] + ')) : ' + dm[4] + '(');
        break;
      }
    }

    const map = new Map();
    {
      const of_ = fnTexts(ch.vm), pf = fnTexts(patched);
      if (of_.length !== pf.length) return resolve({ err: 'function count mismatch: ' + pf.length + ' vs ' + of_.length });
      for (let i = 0; i < pf.length; i++) map.set(pf[i], of_[i]);
    }

    const dom = new JSDOM(html, {
      url: optOf('url', 'https://www.google.com/search?q=anything'),
      referrer: 'https://www.google.com/', pretendToBeVisual: true, runScripts: 'outside-only',
    });
    const w = dom.window;
    let settled = false;
    let watchdog = null;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (watchdog) clearTimeout(watchdog);
      try { w.close(); } catch (e) {}
      resolve(result);
    };
    w.Math.random = () => 0.4242424242424242;
    const D = w.Date;
    function FD(...a) { return a.length ? new D(...a) : new D(17e11); }
    FD.prototype = D.prototype; FD.now = () => 17e11; FD.parse = D.parse; FD.UTC = D.UTC;
    w.Date = FD;
    let c = 0;
    w.performance.now = () => ++c;
    try { Object.defineProperty(w.performance, 'timeOrigin', { configurable: true, value: 17e11 }); } catch (e) {}
    w.navigator.sendBeacon = () => true;

    // Keep the function OBJECT, not a snapshot of it. The interpreter tags a
    // handler AFTER storing it — `store(slot, state, fn), (fn[tag] = 2796)` — so
    // reading its properties inside the tap sees an untagged function every time.
    // The properties are read once the run is over.
    const stored = [];
    const containers = new Set();
    const dispatched = new Map();     // opcode -> the handler the first time it ran
    w.__dispatch = (op, fn) => {
      if (typeof fn !== 'function' || dispatched.has(op)) return;
      dispatched.set(op, fn);
    };
    w.__store = (slot, val, args) => {
      // Find the opcode table among the primitive's arguments, by shape: an
      // object one of whose properties holds this very slot. That property is
      // the register file, and opcodes and registers share its slot space.
      // The tap fires on entry, BEFORE the assignment, so the table cannot be
      // recognised by already holding this value. Keep the candidates and look
      // for the table once the run is over.
      if (args) for (const a of args) if (a && typeof a === 'object') containers.add(a);
      if (typeof val !== 'function') return;
      stored.push({ slot, fn: val });
    };
    // Capturing the opcode table AFTER the run does not work, and the reason is
    // worth recording: opcodes and registers share one slot space, so by the time
    // the program finishes it has overwritten every handler slot with data. The
    // register file holds 346 numeric slots at the end and not one function in
    // any of them.
    //
    // The dispatcher is the right place. It sees every opcode that actually runs,
    // with its handler in hand, whether the interpreter shipped with it or the
    // program installed it a moment ago.
    const dispatchSnapshot = () => {
      const out = [];
      for (const [op, fn] of dispatched) {
        let src = null; const props = {};
        try { src = Function.prototype.toString.call(fn); } catch (e) { continue; }
        try {
          for (const k of Object.getOwnPropertyNames(fn)) {
            if (k === 'length' || k === 'name' || k === 'prototype') continue;
            const v = fn[k];
            if (typeof v === 'number' || typeof v === 'string' || typeof v === 'boolean') props[k] = v;
          }
        } catch (e) {}
        out.push({ slot: op, src, props });
      }
      return out.sort((a, b) => a.slot - b.slot);
    };

    const tableSnapshot = () => {
      const out = [];
      const seenSlot = new Set();
      // The opcode table is a property of the interpreter state whose own keys
      // are numbers and whose values include many functions. Opcodes and
      // registers share that slot space, so most entries are not functions.
      const tables = [];
      for (const cand of containers) {
        let names; try { names = Object.getOwnPropertyNames(cand); } catch (e) { continue; }
        for (const k of names) {
          let v; try { v = cand[k]; } catch (e) { continue; }
          if (!v || typeof v !== 'object') continue;
          let sub; try { sub = Object.getOwnPropertyNames(v); } catch (e) { continue; }
          let fns = 0;
          for (const sk of sub) {
            if (!/^\d+$/.test(sk)) continue;
            let sv; try { sv = v[sk]; } catch (e) { continue; }
            if (typeof sv === 'function') fns++;
          }
          if (fns >= 5) tables.push(v);
        }
      }
      for (const c of tables) {
        let names; try { names = Object.getOwnPropertyNames(c); } catch (e) { continue; }
        for (const k of names) {
          if (!/^\d+$/.test(k) || seenSlot.has(k)) continue;
          let v; try { v = c[k]; } catch (e) { continue; }
          if (typeof v !== 'function') continue;
          let src = null; const props = {};
          try { src = Function.prototype.toString.call(v); } catch (e) { continue; }
          try {
            for (const pk of Object.getOwnPropertyNames(v)) {
              if (pk === 'length' || pk === 'name' || pk === 'prototype') continue;
              const pv = v[pk];
              if (typeof pv === 'number' || typeof pv === 'string' || typeof pv === 'boolean') props[pk] = pv;
            }
          } catch (e) {}
          seenSlot.add(k);
          out.push({ slot: Number(k), src, props });
        }
      }
      return out;
    };

    const snapshot = () => stored.map((s) => {
      let src = null;
      const props = {};
      try { src = Function.prototype.toString.call(s.fn); } catch (e) { return null; }
      try {
        for (const k of Object.getOwnPropertyNames(s.fn)) {
          if (k === 'length' || k === 'name' || k === 'prototype') continue;
          const v = s.fn[k];
          if (typeof v === 'number' || typeof v === 'string' || typeof v === 'boolean') props[k] = v;
        }
      } catch (e) {}
      return { slot: s.slot, src, props };
    }).filter(Boolean);

    const d0 = Object.getOwnPropertyDescriptor(w.HTMLIFrameElement.prototype, 'contentWindow');
    const g0 = d0.get, seen = new WeakSet();
    Object.defineProperty(w.HTMLIFrameElement.prototype, 'contentWindow', {
      configurable: true, enumerable: d0.enumerable,
      get() {
        const cw = g0.call(this);
        if (cw && !seen.has(cw)) {
          seen.add(cw);
          const fp = cw.Function.prototype, orig = fp.toString;
          fp.toString = function () { const t = orig.apply(this, arguments); const o = map.get(t); return o !== undefined ? o : t; };
        }
        return cw;
      },
    });

    const before = new Set(Object.getOwnPropertyNames(w));
    try { w.eval('(function(){\n' + patched + '\n}).call(this);'); }
    catch (e) { return finish({ err: 'source: ' + e.message }); }
    let g = null;
    for (const k of Object.getOwnPropertyNames(w)) {
      if (before.has(k)) continue;
      let v; try { v = w[k]; } catch (e) { continue; }
      if (v && typeof v === 'object' && typeof v.a === 'function' && 'm' in v) { g = k; break; }
    }
    if (!g) return finish({ err: 'the interpreter did not register its global object' });
    w.__p = ch.payload;
    w.__done = (t) => finish({ token: t, stored: snapshot(), table: dispatchSnapshot() });
    watchdog = setTimeout(() => finish({ token: null, stored: snapshot(), table: dispatchSnapshot() }), 30000);
    w.eval('(function(){var h=[{}];window.' + g +
      '.a(window.__p,function(e){return void e(window.__done,h)},false,undefined,undefined,undefined,undefined,true);})();');
  });
}

/**
 * Find the handler-tag PROPERTY from the most common (property, value) pair.
 *
 * The value is only a section stamp. A single run can use several values, so
 * callers must apply the dispatcher's `value & 0x800` guard rather than compare
 * with this one representative value.
 */
function findTag(stored) {
  const votes = new Map();
  for (const s of stored) {
    for (const [k, v] of Object.entries(s.props)) {
      const key = k + '=' + JSON.stringify(v);
      if (!votes.has(key)) votes.set(key, { k, v, n: 0 });
      votes.get(key).n++;
    }
  }
  const ranked = [...votes.values()].sort((a, b) => b.n - a.n);
  return ranked.length ? ranked[0] : null;
}

module.exports = { capture, findTag };

if (require.main !== module) return;

(async () => {
  const htmlArg = optOf('html', 'response.html');
  const htmlPath = path.isAbsolute(htmlArg) ? htmlArg : path.join(__dirname, 'captures', htmlArg);
  const html = fs.readFileSync(htmlPath, 'utf8');
  const crypto = require('crypto');
  const build = crypto.createHash('sha256').update(parseChallenge(html).vm).digest('hex').slice(0, 12);
  const preset = PRESETS[build] || {};
  const readableArg = optOf('readable', preset.readable);
  if (!readableArg) { console.error('no preset for build ' + build + ' — pass --readable= and --stores='); process.exit(1); }
  const readableSrc = fs.readFileSync(path.isAbsolute(readableArg) ? readableArg
    : path.join(__dirname, 'lifted-source', readableArg), 'utf8');
  const stores = (optOf('stores', preset.stores) || '').split(',').filter(Boolean).map((s) => {
    const [name, slot, value] = s.split(':');
    return { name, slot, value };
  });
  if (!stores.length) { console.error('pass --stores=name:slotParam:valueParam,… (see build-primitives.cjs)'); process.exit(1); }

  console.log('capture   : ' + path.basename(htmlPath));
  console.log('build     : ' + build);
  console.log('readable  : ' + path.basename(readableArg));
  console.log('stores    : ' + stores.map((s) => s.name + '(' + s.slot + ',' + s.value + ')').join(' '));

  const r = await capture({ html, readableSrc, stores });
  if (r.err) { console.error('failed: ' + r.err); process.exit(1); }
  console.log('token     : ' + r.token.length + ' chars');
  console.log('token sha : ' + crypto.createHash('sha256').update(r.token).digest('hex'));
  console.log('stored    : ' + r.stored.length + ' functions');

  const tag = findTag(r.stored);
  console.log('handler tag property: ' + (tag ? JSON.stringify(tag.k)
    + '   (most common value ' + JSON.stringify(tag.v) + ' occurs on ' + tag.n + ' stores)' : '(none found)'));

  const handlers = {};
  let dropped = 0;
  const tagValues = new Map();
  for (const s of r.stored) {
    // Mirror the dispatcher. The stamp changes between installation sections
    // (133120 and 444792 on the publication capture), while bit 0x800 remains
    // the actual admission flag.
    const tagged = tag && Object.prototype.hasOwnProperty.call(s.props, tag.k)
      && ((Number(s.props[tag.k]) | 0) & 0x800) !== 0;
    if (!tagged) { dropped++; continue; }
    const stamp = JSON.stringify(s.props[tag.k]);
    tagValues.set(stamp, (tagValues.get(stamp) || 0) + 1);
    if (!(s.slot in handlers)) handlers[s.slot] = s.src;
  }
  if (tagValues.size) console.log('tag values : ' + [...tagValues]
    .map(([v, n]) => v + '×' + n).join(', '));
  console.log('kept      : ' + Object.keys(handlers).length + ' distinct slots  ('
    + [...tagValues.values()].reduce((a, b) => a + b, 0) + ' tagged stores, '
    + dropped + ' untagged dropped)');

  const out = optOf('out', null);
  if (out) {
    fs.writeFileSync(path.resolve(out), JSON.stringify(handlers, null, 1));
    console.log('wrote     : ' + out);
  }
})();
