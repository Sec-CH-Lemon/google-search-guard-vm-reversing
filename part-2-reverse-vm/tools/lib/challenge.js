'use strict';
// ============================================================================
//  lib/challenge.js - pull the two halves of the challenge out of a saved page,
//  plus the two facts every tool in this bundle needs about the build it got.
//
//      const { extract, vmGlobalName, degradedLength } = require('./lib/challenge');
//      const { vm, payload, eid, ce } = extract('captures/response.html');
//
//  Located by PARSING, not by matching marker text. A live page carries none of
//  the comments a saved copy has, and a slice taken from a marker that is not
//  there evaluates whatever happens to sit at offset 1 - which fails loudly if
//  you are lucky and quietly if you are not. This reads a minified live response
//  and a pretty-printed saved one identically.
// ============================================================================

const fs = require('fs');
const acorn = require('acorn');

const SCRIPT_RE = /<script[^>]*>([\s\S]*?)<\/script>/g;

/** the loader constants that decide what gets sent and how */
const WANTED = new Set(['eid', 'ce', 'challenge_version', 'cbs', 'ss_cgi', 'r']);

/**
 * `vars` holds whatever parseChallenge lifted from the declarations themselves.
 * That is the authority: `r`, `ce` and `cbs` are one and two characters long,
 * and a page that mentions any of them inside a string would otherwise silently
 * win over its own `var`. The regex is a fallback for a script acorn could not
 * parse at all.
 */
function constants(html, vars) {
  const pick = (n, pattern, cast) => {
    if (vars[n] !== undefined) return vars[n];
    const m = new RegExp('var\\s+' + n + '\\s*=\\s*' + pattern).exec(html);
    return m ? cast(m[1]) : null;
  };
  const str = (n) => { const v = pick(n, "'([^']*)'", String); return v === null ? null : String(v); };
  const num = (n) => { const v = pick(n, '(-?\\d+)', Number); return v === null ? null : Number(v); };
  const bool = (n) => pick(n, '(true|false)', (s) => s === 'true');

  const ce = num('ce');
  const cbs = str('cbs');
  return {
    eid: str('eid'),
    ce: ce === null ? 300 : ce,                 // cookie TTL in seconds
    challengeVersion: num('challenge_version') || 0,
    cbs: cbs === null ? '' : cbs,
    ssCgi: bool('ss_cgi') === true,             // deliver via ?sg_ss= instead of the cookie
    writesCookie: str('r') !== '0',             // `r` gates the cookie write
  };
}

/**
 * The interpreter source and the encrypted program, located by PARSING rather
 * than by matching marker text: a live page carries none of the comments a
 * saved copy has, and a slice taken from a marker that is not there evaluates
 * whatever happens to sit at offset 1.
 */
function parseChallenge(html) {
  const acorn = require('acorn');
  const scripts = [...html.matchAll(SCRIPT_RE)].map((m) => m[1]);
  let vm = null;
  let payload = null;
  const vars = {};   // the loader constants, first declaration wins

  for (const src of scripts) {
    let ast;
    try { ast = acorn.parse(src, { ecmaVersion: 2020, ranges: true }); } catch (e) { continue; }
    (function walk(n) {
      if (!n || typeof n.type !== 'string') return;

      // the interpreter: <something>.join("\n"), where <something> is the source lines
      if (vm === null && n.type === 'CallExpression' && n.callee && n.callee.type === 'MemberExpression' &&
          n.callee.property && n.callee.property.name === 'join' &&
          n.arguments.length === 1 && n.arguments[0].type === 'Literal' && n.arguments[0].value === '\n') {
        // The object is a concatenation like `<lines> + ['//# sourceMappingURL=…']`, which
        // cannot be evaluated whole because it references page variables. Collect the
        // top-level array literals inside it and concatenate them in source order.
        const arrays = [];
        (function collect(x, insideArray) {
          if (!x || typeof x.type !== 'string') return;
          if (x.type === 'ArrayExpression') { if (!insideArray) arrays.push(x); insideArray = true; }
          for (const k of Object.keys(x)) {
            if (k === 'start' || k === 'end' || k === 'range' || k === 'type') continue;
            const v = x[k];
            if (Array.isArray(v)) v.forEach((c) => collect(c, insideArray));
            else if (v && typeof v.type === 'string') collect(v, insideArray);
          }
        })(n.callee.object, false);
        let parts = [];
        for (const a of arrays) {
          try { const got = (0, eval)('(' + src.slice(a.start, a.end) + ')'); if (Array.isArray(got)) parts = parts.concat(got); }
          catch (e) { parts = null; break; }
        }
        if (parts && parts.length) {
          const joined = parts.join('\n');
          if (joined.length > 10000 && joined.indexOf('function') >= 0) vm = joined;  // gate on content, not element count
        }
      }

      if (n.type === 'VariableDeclarator' && n.init && n.init.type === 'Literal') {
        // the bytecode: the longest opaque single-token string literal on the page.
        // Taking the first long one is not safe — a live page carries other big strings.
        if (typeof n.init.value === 'string' && n.init.value.length > 2000 &&
            /^[\x21-\x7e]+$/.test(n.init.value) &&
            (payload === null || n.init.value.length > payload.length)) {
          payload = n.init.value;
        }
        // the loader constants, taken from the declaration itself
        if (n.id && n.id.type === 'Identifier' && WANTED.has(n.id.name) && vars[n.id.name] === undefined) {
          vars[n.id.name] = n.init.value;
        }
      }

      for (const k of Object.keys(n)) {
        if (k === 'start' || k === 'end' || k === 'range' || k === 'type') continue;
        const v = n[k];
        if (Array.isArray(v)) v.forEach(walk);
        else if (v && typeof v.type === 'string') walk(v);
      }
    })(ast);
  }

  if (!vm) throw new Error('this does not look like a SearchGuard interstitial: no <array>.join("\\n") in any script');
  if (!payload) throw new Error('bytecode not found: no string literal over 2000 characters');
  return { vm, payload, ...constants(html, vars) };
}

/** Is this page an interstitial at all? Cheap check, no parsing. */
function isChallenge(html) {
  return /\]\s*\.\s*join\((['"])\\n\1\)/.test(html);
}

const DEGRADED_BY_BUILD = { '885c049eda50': 871, c348580f3670: 893 };

function degradedLength(vmSource) {
  const sha = require('crypto').createHash('sha256').update(vmSource).digest('hex').slice(0, 12);
  return DEGRADED_BY_BUILD[sha] === undefined ? null : DEGRADED_BY_BUILD[sha];
}

function vmGlobalName(w) {
  for (const k of Object.getOwnPropertyNames(w)) {
    let v;
    try { v = w[k]; } catch (e) { continue; }
    if (v && typeof v === 'object' && typeof v.a === 'function' && 'm' in v) return k;
  }
  return null;
}

function envSource(P) {
  const s = P.screen;
  const J = JSON.stringify;
  return `(function(){
  var D = function(o,k,v){ try { Object.defineProperty(o,k,{configurable:true,get:function(){return v;}}); } catch(x){} };
  D(navigator,'platform',${J(P.platform)});
  D(navigator,'vendor',${J(P.vendor)});
  D(navigator,'productSub',${J(P.productSub)});
  D(navigator,'language',${J((P.languages || ['en-US'])[0])});
  D(navigator,'languages',${J(P.languages)});
  D(navigator,'hardwareConcurrency',${P.hardwareConcurrency});
  D(navigator,'deviceMemory',${P.deviceMemory});
  D(navigator,'maxTouchPoints',${P.maxTouchPoints});
  D(navigator,'webdriver',false);
  D(navigator,'pdfViewerEnabled',${!!P.pdfViewerEnabled});
  ${P.connection ? `D(navigator,'connection',${J(P.connection)});` : ''}
  D(screen,'width',${s.width}); D(screen,'height',${s.height});
  D(screen,'availWidth',${s.availWidth}); D(screen,'availHeight',${s.availHeight});
  // availLeft/availTop do not exist in jsdom but do in every real browser, and their
  // presence INSERTS a 5-byte block (tag 0x74) into the record. Omitting them makes
  // the record structurally unlike any browser's.
  D(screen,'availLeft',${s.availLeft}); D(screen,'availTop',${s.availTop});
  D(screen,'colorDepth',${s.colorDepth}); D(screen,'pixelDepth',${s.pixelDepth});
  D(window,'devicePixelRatio',${P.devicePixelRatio});
  D(window,'innerWidth',${P.innerWidth});  D(window,'innerHeight',${P.innerHeight});
  D(window,'outerWidth',${P.outerWidth});  D(window,'outerHeight',${P.outerHeight});
  D(window,'isSecureContext',${!!P.isSecureContext});
  try {
    var C = {};
    ${(P.chromeKeys || []).map((k) =>
      k === 'csi' ? `C.csi = function(){ return {startE: Date.now(), onloadT: Date.now(), pageT: 1000, tran: 15}; };`
      : k === 'loadTimes' ? `C.loadTimes = function(){ return {requestTime: Date.now()/1000}; };`
      : `C[${J(k)}] = {};`).join('\n    ')}
    window.chrome = C;
  } catch(x){}
  ${P.performanceMemory ? `try { Object.defineProperty(performance,'memory',{configurable:true,get:function(){return ${J(P.performanceMemory)};}}); } catch(x){}` : ''}
  ${P.historyLength ? `try { D(window.history,'length',${P.historyLength}); } catch(x){}` : ''}
  ${P.navigationTiming ? `try {
    var NT = ${J(P.navigationTiming)};
    NT.name = String(location.href); NT.entryType = 'navigation';
    NT.toJSON = function(){ var o = {}; for (var k in this) if (typeof this[k] !== 'function') o[k] = this[k]; return o; };
    var _get = performance.getEntriesByType ? performance.getEntriesByType.bind(performance) : function(){ return []; };
    D(performance,'getEntriesByType', function(t){ return t === 'navigation' ? [NT] : _get(t); });
    D(performance,'getEntries', function(){ return [NT]; });
    D(performance,'navigation', { type: 0, redirectCount: 0, TYPE_NAVIGATE: 0, TYPE_RELOAD: 1, TYPE_BACK_FORWARD: 2, TYPE_RESERVED: 255 });
    var T0 = Math.floor((performance.timeOrigin || Date.now()));
    var TM = {}; 
    ['navigationStart','unloadEventStart','unloadEventEnd','redirectStart','redirectEnd','fetchStart',
     'domainLookupStart','domainLookupEnd','connectStart','connectEnd','secureConnectionStart','requestStart',
     'responseStart','responseEnd','domLoading','domInteractive','domContentLoadedEventStart',
     'domContentLoadedEventEnd','domComplete','loadEventStart','loadEventEnd'].forEach(function(k){
      var v = k === 'navigationStart' ? 0
            : (NT[k] !== undefined ? NT[k] : (NT[k.replace(/^dom/, 'dom')] !== undefined ? NT[k] : 0));
      TM[k] = v ? Math.round(T0 + v) : (k === 'navigationStart' ? T0 : 0);
    });
    D(performance,'timing', TM);
  } catch(x){}` : ''}
  if (typeof window.requestIdleCallback !== 'function') try { window.requestIdleCallback = function(fn){ return setTimeout(fn, 0); }; } catch(x){}
  if (!window.trustedTypes) try { window.trustedTypes = { createPolicy: function(n, rules){ return rules; } }; } catch(x){}
  // The challenge stores String(new Date()).slice(25) — "GMT+0200 (<zone>)". Chrome
  // LOCALISES the zone name; Node writes the English one. On one and the same
  // challenge that alone accounted for 32 of 48 differing bytes. Only the name in
  // parentheses is replaced, so nothing contradicts getTimezoneOffset().
  var LOC = ${J((P.languages && P.languages[0]) || 'en-US')};
  var RTS = Date.prototype.toString;
  Date.prototype.toString = function () {
    var s = RTS.call(this);
    var i = s.indexOf(' (');
    if (i < 0) return s;
    try {
      var name = new Intl.DateTimeFormat(LOC, { timeZoneName: 'long' })
        .formatToParts(this).filter(function (x) { return x.type === 'timeZoneName'; })[0].value;
      return s.slice(0, i) + ' (' + name + ')';
    } catch (e) { return s; }
  };
})();`;
}


/** Read a saved page and split it. `interpreter`/`program` are aliases kept for part 1. */
function extract(htmlPath) {
  const parsed = parseChallenge(fs.readFileSync(htmlPath, 'utf8'));
  return { ...parsed, interpreter: parsed.vm, program: parsed.payload };
}

module.exports = { parseChallenge, extract, isChallenge, constants, vmGlobalName, degradedLength, envSource };
