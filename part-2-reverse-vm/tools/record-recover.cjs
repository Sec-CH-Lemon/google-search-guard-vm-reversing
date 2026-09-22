'use strict';
// ============================================================================
//  record-recover.cjs — recover the DECRYPTED record from a challenge run
//  without knowing the output-stream key.
//
//  The record is the encrypted payload inside the token, and the interesting
//  half of the analysis is about what is in it. There are two ways to read it:
//  decrypt the token with that challenge's output key, or watch the interpreter
//  write it. This does the second, and does it WITHOUT knowing the key.
//
//  How, without the key: the output stream is written one byte at a time as
//  `push(keystream[index & 7] ^ plainByte)`, and the keystream block lives on the
//  buffer itself. So hooking Array.prototype.push and reading the sibling gives
//  the plaintext for free — `plain = pushed ^ keystream[len & 7]`.
//
//  sgss-extract.cjs did this by hardcoding the sibling's name (`.aX`). That name
//  is build-scoped and a new build renames it, so this looks for it BY SHAPE
//  instead: the property of the buffer that is an 8-element array of bytes. That
//  made the tool work on every tested build, including then-unprofiled builds.
//  That is measured compatibility, not a guarantee for every future loader/VM.
//
//     node record-recover.cjs [--html=capture.html] [--out=record.json]
//
//  Verified invisible the usual way: the run is compared with an untapped one and
//  the tokens must be byte-identical, because a tap the challenge notices
//  collapses the token to that build's degraded length.
// ============================================================================
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseChallenge } = require('./lib/challenge.js');
const { JSDOM } = require('jsdom');

const argv = process.argv.slice(2);
const optOf = (n, d) => { const h = argv.find((a) => a.startsWith('--' + n + '=')); return h ? h.slice(n.length + 3) : d; };
const HTML_ARG = optOf('html', 'response.html');
const HTML_PATH = path.isAbsolute(HTML_ARG) ? HTML_ARG : path.join(__dirname, 'captures', HTML_ARG);

/** the keystream sibling: an own property that is an 8-element array of bytes */
function findKeystream(buf) {
  for (const k of Object.getOwnPropertyNames(buf)) {
    let v;
    try { v = buf[k]; } catch (e) { continue; }
    if (!Array.isArray(v) || v.length !== 8) continue;
    if (v.every((x) => typeof x === 'number' && x >= 0 && x <= 255)) return k;
  }
  return null;
}

function run(html, tapped) {
  return new Promise((resolve) => {
    const ch = parseChallenge(html);
    const dom = new JSDOM(html, {
      url: optOf('url', 'https://www.google.com/search?q=anything'),
      referrer: 'https://www.google.com/', pretendToBeVisual: true, runScripts: 'outside-only',
    });
    const w = dom.window;
    let settled = false;
    let timer = null;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try { w.close(); } catch (e) {}
      resolve(value);
    };
    // Frozen, so two runs are comparable byte for byte.
    w.Math.random = () => 0.4242424242424242;
    const D = w.Date;
    function FD(...a) { return a.length ? new D(...a) : new D(17e11); }
    FD.prototype = D.prototype; FD.now = () => 17e11; FD.parse = D.parse; FD.UTC = D.UTC;
    w.Date = FD;
    let c = 0;
    w.performance.now = () => ++c;
    try { Object.defineProperty(w.performance, 'timeOrigin', { configurable: true, value: 17e11 }); } catch (e) {}
    w.navigator.sendBeacon = () => true;

    const streams = new Map();
    let ksName = null;
    if (tapped) {
      const op = w.Array.prototype.push;
      w.Array.prototype.push = function push(...a) {
        try {
          if (this && a.length === 1 && typeof a[0] === 'number') {
            const k = ksName || (ksName = findKeystream(this));
            const ks = k && this[k];
            if (Array.isArray(ks) && ks.length === 8) {
              let ev = streams.get(this);
              if (!ev) streams.set(this, (ev = []));
              ev.push([this.length, a[0] & 255, ks[this.length & 7] & 255]);
            }
          }
        } catch (e) { /* not our buffer */ }
        return op.apply(this, a);
      };
    }

    const before = new Set(Object.getOwnPropertyNames(w));
    w.eval('(function(){\n' + ch.vm + '\n}).call(this);');
    let g = null;
    for (const k of Object.getOwnPropertyNames(w)) {
      if (before.has(k)) continue;
      let v; try { v = w[k]; } catch (e) { continue; }
      if (v && typeof v === 'object' && typeof v.a === 'function' && 'm' in v) { g = k; break; }
    }
    if (!g) return finish({ err: 'the interpreter did not register its global object' });
    timer = setTimeout(() => finish({ err: 'timed out' }), 30000);
    w.__p = ch.payload;
    w.__done = (t) => finish({ token: t, streams, ksName, challenge: ch });
    w.eval('(function(){var h=[{}];window.' + g +
      '.a(window.__p,function(e){return void e(window.__done,h)},false,undefined,undefined,undefined,undefined,true);})();');
  });
}

/** the longest contiguous run of pushes into one buffer is the record */
function longestRecord(streams) {
  let best = { plain: [], cipher: [], iv: [] };
  for (const [buf, ev] of streams) {
    let start = 0;
    for (let i = 1; i < ev.length; i++) if (ev[i][0] <= ev[i - 1][0]) start = i;
    const iv = [buf[0], buf[1], buf[2], buf[3]];
    const cipher = iv.slice();
    const plain = [];
    for (let i = start; i < ev.length; i++) {
      const [idx, cb, ks] = ev[i];
      if (idx !== cipher.length) break;
      cipher.push(cb & 255);
      plain.push((cb ^ ks) & 255);
    }
    if (plain.length > best.plain.length) best = { plain, cipher, iv };
  }
  return best;
}

module.exports = { run, longestRecord, findKeystream };

if (require.main !== module) return;

(async () => {
  const html = fs.readFileSync(HTML_PATH, 'utf8');
  const plainRun = await run(html, false);
  const tapRun = await run(html, true);
  if (plainRun.err || tapRun.err) { console.error('failed: ' + (plainRun.err || tapRun.err)); process.exit(1); }

  const invisible = plainRun.token === tapRun.token;
  const rec = longestRecord(tapRun.streams);
  const sha = (s) => crypto.createHash('sha256').update(Buffer.from(s)).digest('hex').slice(0, 16);

  console.log('capture          : ' + path.basename(HTML_PATH));
  console.log('build            : ' + crypto.createHash('sha256').update(tapRun.challenge.vm).digest('hex').slice(0, 12)
    + '  (interpreter ' + tapRun.challenge.vm.length + ' chars)');
  console.log('token            : ' + tapRun.token.length + ' chars');
  console.log('tap invisible    : ' + (invisible ? 'YES — the record below is trustworthy'
    : 'NO — untapped ' + plainRun.token.length + ' vs tapped ' + tapRun.token.length + ', do not trust it'));
  console.log('keystream sibling: .' + (tapRun.ksName || '(not found)') + '   (found by shape, not by name)');
  console.log('record           : ' + rec.plain.length + ' bytes, sha ' + sha(rec.plain));
  console.log('IV (clear)       : ' + rec.iv.map((b) => b.toString(16).padStart(2, '0')).join(' '));

  const OUT = optOf('out', null);
  if (OUT) {
    fs.writeFileSync(path.isAbsolute(OUT) ? OUT : path.resolve(OUT),
      JSON.stringify({ capture: path.basename(HTML_PATH), token: tapRun.token, record: rec.plain, iv: rec.iv }, null, 1));
    console.log('wrote            : ' + OUT);
  }
})();
