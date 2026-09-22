'use strict';
// ============================================================================
//  run-readable-vm.cjs — RUN the human-readable interpreter and get a real token.
//
//  results/lifted-source/vm-readable.js is the deobfuscated VM with the ORIGINAL
//  short names kept (MBA removed + prettier, no renaming). Names are kept so the
//  bytecode's `eval("$J")` name-lookups still resolve. But the VM also fingerprints
//  its OWN source text (folds Function.toString of ~28 functions into the bytecode
//  key), and MBA removal changes that text. On the reference build a naive run
//  degrades to 871; later builds need the byte comparison below rather than that
//  build-specific length as a proxy.
//
//  This tool compensates for exactly that: it wraps the iframe realm's
//  Function.prototype.toString so the fingerprint sees each function's ORIGINAL
//  text, while EXECUTION runs the readable code. A byte-identical result confirms
//  the same output on this mixed-code execution; it does not establish equivalent
//  intermediate values, unexecuted branches or other inputs.
//
//     node run-readable-vm.cjs [--readable=path] [--html=response.html]
// ============================================================================
const fs = require('fs');
const path = require('path');
const { degradedLength } = require('./lib/challenge.js');
const crypto = require('crypto');
const { JSDOM } = require('jsdom');
const acorn = require('acorn');

const optOf = (n, d) => { const h = process.argv.find((a) => a.startsWith('--' + n + '=')); return h ? h.slice(n.length + 3) : d; };
const READABLE_PATH = (() => { const a = optOf('readable', 'vm-readable.js'); return path.isAbsolute(a) ? a : path.join(__dirname, 'lifted-source', a); })();
const HTML_PATH = (() => { const a = optOf('html', 'response.html'); return path.isAbsolute(a) ? a : path.join(__dirname, 'captures', a); })();

// ---- sources: original VM (for the fingerprint mapping) + payload + readable --
const html = fs.readFileSync(HTML_PATH, 'utf8');
// Located by parsing, not by marker text: a live minified page carries neither
// the sourceMappingURL comment this used to anchor on nor a `;\n` after `var p`.
const { parseChallenge } = require('./lib/challenge.js');
const CH = parseChallenge(html);

// The failure length belongs to the build, so it is looked up rather than
// written down. --degraded=N covers a build the table has never seen.
const DEG = (() => {
  const h = process.argv.find((a) => a.startsWith('--degraded='));
  return h ? Number(h.slice(11)) : degradedLength(CH.vm);
})();

const ORIG = CH.vm;
const payload = CH.payload;
const READABLE = fs.readFileSync(READABLE_PATH, 'utf8');

// ---- map each function's readable text -> its original text, by AST position --
// MBA removal / prettier neither add, remove nor reorder functions, so the i-th
// function of the readable source is the i-th of the original.
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
const ORIG_FN = fnTexts(ORIG), READ_FN = fnTexts(READABLE);
const READ_TO_ORIG = new Map();
if (ORIG_FN.length === READ_FN.length) for (let i = 0; i < READ_FN.length; i++) READ_TO_ORIG.set(READ_FN[i], ORIG_FN[i]);

// ---- run a VM source against the real bytecode, resolve with the token --------
function run(src, compensate) {
  return new Promise((resolve) => {
    let dom;
    try {
      dom = new JSDOM('<!doctype html><html lang="pl"><head><meta charset="utf-8"><title>Google Search</title></head><body><div id="yvlrue" style="display:none">x</div></body></html>',
        { url: 'https://www.google.com/search?q=anything', referrer: 'https://www.google.com/', pretendToBeVisual: true, runScripts: 'outside-only' });
    } catch (e) { return resolve({ err: 'jsdom: ' + e.message }); }
    const w = dom.window;
    w.Math.random = () => 0.4242424242424242;
    const D = w.Date;
    function FD(...a) { return a.length ? new D(...a) : new D(17e11); }
    FD.prototype = D.prototype; FD.now = () => 17e11; FD.parse = D.parse; FD.UTC = D.UTC;
    w.Date = FD;
    let c = 0;
    w.performance.now = () => ++c;
    try { Object.defineProperty(w.performance, 'timeOrigin', { configurable: true, value: 17e11 }); } catch {}
    w.navigator.sendBeacon = () => true;

    // feed the self-fingerprint the ORIGINAL text of each function, via the iframe
    // realm's toString (reached through contentWindow; a pass-through getter is
    // tolerated, a Proxy is not).
    if (compensate) {
      const d0 = Object.getOwnPropertyDescriptor(w.HTMLIFrameElement.prototype, 'contentWindow');
      if (d0 && d0.get) {
        const g0 = d0.get, seen = new WeakSet();
        Object.defineProperty(w.HTMLIFrameElement.prototype, 'contentWindow', {
          configurable: true, enumerable: d0.enumerable,
          get() {
            const cw = g0.call(this);
            if (cw && !seen.has(cw)) {
              seen.add(cw);
              try {
                const fp = cw.Function.prototype, orig = fp.toString;
                fp.toString = function () { const t = orig.apply(this, arguments); const o = READ_TO_ORIG.get(t); return o !== undefined ? o : t; };
              } catch {}
            }
            return cw;
          },
        });
      }
    }

    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    try { w.eval('(function(){\n' + src + '\n}).call(this);'); } catch (e) { return finish({ err: 'source eval: ' + e.message }); }
    let g = null; // the global the source registered (name differs per response)
    for (const k of Object.getOwnPropertyNames(w)) { let v; try { v = w[k]; } catch { continue; } if (v && typeof v === 'object' && typeof v.a === 'function' && 'm' in v) g = k; }
    if (!g) return finish({ err: 'VM global not found' });
    w.__p = payload;
    w.__done = (t) => finish({ token: t, len: t.length });
    try { w.eval('(function(){var h=[{}];window.' + g + '.a(window.__p,function(e){return void e(window.__done,h)},false,undefined,undefined,undefined,undefined,true);})();'); } catch (e) { return finish({ err: 'VM run: ' + e.message }); }
    setTimeout(() => finish({ err: 'timeout' }), 25000);
  });
}

const sha = (t) => (t ? crypto.createHash('sha256').update(t).digest('hex').slice(0, 16) : '-');

(async () => {
  console.log('readable VM        : ' + path.relative(path.join(__dirname, '..'), READABLE_PATH) + ' (' + (READABLE.length / 1024 | 0) + ' KB, original short names)');
  console.log('functions paired   : ' + READ_FN.length + '/' + ORIG_FN.length + (READ_FN.length === ORIG_FN.length ? '  (ok)' : '  !! mismatch — compensation impossible'));
  console.log('');

  const orig = await run(ORIG, false);
  const compensated = await run(READABLE, true);
  const direct = await run(READABLE, false);

  console.log('original VM                         : ' + (orig.err ? 'ERR ' + orig.err : orig.len + ' chars, sha ' + sha(orig.token)));
  console.log('readable VM + fingerprint compensation: ' + (compensated.err ? 'ERR ' + compensated.err : compensated.len + ' chars, sha ' + sha(compensated.token)));
  const directState = direct.err ? ''
    : direct.token === orig.token ? '   <- BYTE-IDENTICAL; this control does not distinguish the gate on this capture'
      : DEG !== null && direct.len === DEG ? '   <- degraded to ' + DEG + '; fingerprint caught the changed text'
        : '   <- DIFFERENT from original';
  console.log('readable VM, no compensation (gate) : ' + (direct.err ? 'ERR ' + direct.err : direct.len + ' chars, sha ' + sha(direct.token)) + directState);
  console.log('');

  if (!orig.err && !compensated.err) {
    const same = orig.token === compensated.token;
    console.log('RESULT: the readable VM produced ' + (same
      ? 'a token BYTE-IDENTICAL to the original on this execution.'
      : 'a DIFFERENT token (orig ' + sha(orig.token) + ' vs readable ' + sha(compensated.token) + ') — investigate.'));
    if (same) { console.log(''); console.log('token: ' + compensated.token.slice(0, 48) + '…  (' + compensated.len + ' chars)'); }
    process.exit(same ? 0 : 1);
  }
  console.log('RESULT: could not complete — see error above.');
  process.exit(1);
})();
