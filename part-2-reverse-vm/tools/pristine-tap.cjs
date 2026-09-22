'use strict';
// ============================================================================
// pristine-tap.cjs — observe the clean-realm String.prototype.replace calls
// used to manufacture run-time opcode handlers.
//
// The challenge creates a hidden iframe and borrows natives from that realm.
// This tool installs a pass-through wrapper in the iframe before the VM reaches
// it, records handler-shaped String.prototype.replace results, and then compares
// the COMPLETE token with an untapped control run.
//
//   node pristine-tap.cjs --html=<saved-challenge.html>
// ============================================================================
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseChallenge } = require('./lib/challenge.js');
const { JSDOM } = require('jsdom');

const argv = process.argv.slice(2);
const optOf = (n, d) => {
  const h = argv.find((a) => a.startsWith('--' + n + '='));
  return h ? h.slice(n.length + 3) : d;
};
const R_ = __dirname;   // the bundle is self-contained
const htmlArg = optOf('html', 'response.html');
const htmlPath = path.isAbsolute(htmlArg) ? htmlArg
  : fs.existsSync(htmlArg) ? htmlArg : path.join(R_, 'captures', htmlArg);
const pageUrl = optOf('url', 'https://www.google.com/search?q=anything');

const sha256 = (s) => crypto.createHash('sha256').update(s || '').digest('hex');

function freezeWindow(w) {
  w.Math.random = () => 0.4242424242424242;
  const D = w.Date;
  function FD(...a) { return a.length ? new D(...a) : new D(17e11); }
  FD.prototype = D.prototype;
  FD.now = () => 17e11;
  FD.parse = D.parse;
  FD.UTC = D.UTC;
  w.Date = FD;
  let c = 0;
  w.performance.now = () => ++c;
  try { Object.defineProperty(w.performance, 'timeOrigin', { configurable: true, value: 17e11 }); } catch (e) {}
  w.navigator.sendBeacon = () => true;
}

function solve(html, tapped) {
  const ch = parseChallenge(html);
  return new Promise((resolve, reject) => {
    const dom = new JSDOM(html, {
      url: pageUrl,
      referrer: 'https://www.google.com/',
      pretendToBeVisual: true,
      runScripts: 'outside-only',
    });
    const w = dom.window;
    freezeWindow(w);

    const replacements = [];
    let realms = 0;
    if (tapped) {
      const d = Object.getOwnPropertyDescriptor(w.HTMLIFrameElement.prototype, 'contentWindow');
      if (!d || typeof d.get !== 'function') {
        try { w.close(); } catch (e) {}
        return reject(new Error('iframe contentWindow getter not found'));
      }
      const get = d.get;
      const seen = new WeakSet();
      Object.defineProperty(w.HTMLIFrameElement.prototype, 'contentWindow', {
        configurable: true,
        enumerable: d.enumerable,
        get() {
          const iw = get.call(this);
          if (!iw || seen.has(iw)) return iw;
          seen.add(iw);
          realms++;

          try {
            const replace = iw.String.prototype.replace;
            const valueOf = iw.String.prototype.valueOf;
            Object.defineProperty(iw.String.prototype, 'replace', {
              configurable: true,
              writable: true,
              value: function (...a) {
                const out = replace.apply(this, a);
                if (typeof out === 'string' && /^0\s*,\s*function/.test(out)) {
                  let input = null;
                  try { input = valueOf.call(this); } catch (e) {}
                  replacements.push({
                    search: typeof a[0] === 'string' ? a[0] : String(a[0]),
                    replacement: typeof a[1] === 'string' ? a[1] : String(a[1]),
                    input,
                    output: out,
                  });
                }
                return out;
              },
            });
          } catch (e) {}

          return iw;
        },
      });
    }

    let settled = false;
    const finish = (err, token) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const result = { token, replacements, realms };
      try { w.close(); } catch (e) {}
      err ? reject(err) : resolve(result);
    };
    const timer = setTimeout(() => finish(new Error('the interpreter never called back')), 30000);

    const before = new Set(Object.getOwnPropertyNames(w));
    try { w.eval('(function(){\n' + ch.vm + '\n}).call(this);'); }
    catch (e) { return finish(new Error('interpreter source failed: ' + e.message)); }

    let globalName = null;
    for (const k of Object.getOwnPropertyNames(w)) {
      if (before.has(k)) continue;
      let v;
      try { v = w[k]; } catch (e) { continue; }
      if (v && typeof v === 'object' && typeof v.a === 'function' && 'm' in v) {
        globalName = k;
        break;
      }
    }
    if (!globalName) return finish(new Error('the interpreter did not register its global object'));

    w.__p = ch.payload;
    w.__done = (token) => finish(null, token);
    try {
      w.eval('(function(){var h=[{}];window.' + globalName
        + '.a(window.__p,function(e){return void e(window.__done,h)},false,undefined,undefined,undefined,undefined,true);})();');
    } catch (e) { finish(new Error('interpreter run failed: ' + e.message)); }
  });
}

(async () => {
  const html = fs.readFileSync(htmlPath, 'utf8');
  const control = await solve(html, false);
  const tapped = await solve(html, true);
  const identical = control.token === tapped.token;

  const uniq = [];
  const seen = new Set();
  for (const e of tapped.replacements) {
    const k = JSON.stringify([e.search, e.replacement, e.output]);
    if (!seen.has(k)) { seen.add(k); uniq.push(e); }
  }
  console.log('capture             : ' + path.basename(htmlPath));
  console.log('control token       : ' + control.token.length + ' chars, sha256 ' + sha256(control.token));
  console.log('tapped token        : ' + tapped.token.length + ' chars, sha256 ' + sha256(tapped.token));
  console.log('tap invisible       : ' + (identical ? 'YES — byte-identical' : 'NO'));
  console.log('iframe realms       : ' + tapped.realms);
  console.log('handler replacements: ' + uniq.length);
  for (const e of uniq) console.log('  ' + JSON.stringify(e.search) + ' -> '
    + JSON.stringify(e.replacement) + '   ' + e.output.slice(0, 100));

  const outArg = optOf('out', 'pristine-tap.json');
  const out = path.isAbsolute(outArg) ? outArg : path.join(R_, 'records', outArg);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify({
    capture: path.basename(htmlPath),
    tokenChars: tapped.token.length,
    tokenSha256: sha256(tapped.token),
    byteIdenticalToControl: identical,
    iframeRealms: tapped.realms,
    replacements: uniq,
  }, null, 1));
  console.log('wrote               : ' + path.relative(R_, out));
  process.exit(identical ? 0 : 1);
})().catch((e) => {
  console.error('failed: ' + (e && e.message || e));
  process.exit(1);
});
