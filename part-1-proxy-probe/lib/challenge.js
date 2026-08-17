'use strict';

/**
 * Loading and running the SearchGuard challenge in an isolated environment.
 *
 * The challenge is the interstitial page Google serves instead of search results.
 * It has two parts: the source of an interpreter (a virtual machine) and an
 * encrypted program for it. The program collects data about the browser and
 * returns a token, which the page stores in the SG_SS cookie.
 *
 * This module exposes two operations: pull both parts out of a saved page
 * (extract) and execute them to obtain the token (run). All instrumentation is
 * supplied through a single `install` option, which keeps the tools themselves
 * short.
 */

const fs = require('fs');
const { JSDOM } = require('jsdom');

/**
 * Host page. Deliberately minimal: the interpreter needs a document, not this
 * particular markup. The `#yvlrue` div mirrors the real interstitial (an inline
 * script there reveals it after two seconds), but it is not required - the token
 * comes out identical without it. It is kept only to stay close to the original.
 */
const PAGE_HTML =
  '<!doctype html><html lang="pl"><head><meta charset="utf-8">' +
  '<title>Google Search</title></head><body>' +
  '<div id="yvlrue" style="display:none">x</div></body></html>';

/** The challenge derives a key from the hostname, so the origin has to be the real one. */
const PAGE_URL = 'https://www.google.com/search?q=hello';
const REFERRER = 'https://www.google.com/';

const DEFAULT_TIMEOUT_MS = 25000;

/** Frozen values: any single fixed number will do, it only has to stay constant. */
const FROZEN_RANDOM = 0.4242424242424242;
const FROZEN_TIME_MS = 17e11;

/**
 * Pulls the interpreter source and the encrypted program out of a saved page.
 *
 * @param {string} htmlPath path to a saved Google response
 * @returns {{ interpreter: string, program: string }}
 */
function extract(htmlPath) {
  // Every tool here starts by reading a capture, so a missing one is the first
  // thing a new reader runs into. Say what is needed and how to get it, rather
  // than letting an ENOENT through.
  if (!fs.existsSync(htmlPath)) {
    throw new Error(
      `no capture at ${htmlPath}\n\n` +
        'These tools read a saved copy of the interstitial page. To fetch one:\n' +
        '  node fetch-challenge.js\n\n' +
        'To use a capture you already have:\n' +
        '  --html=/path/to/challenge.html',
    );
  }

  const html = fs.readFileSync(htmlPath, 'utf8');
  const scripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);

  // The interpreter source ships as an array of strings the page joins itself.
  const bootstrap = scripts.find((s) => s.includes("].join('\\n')"));
  if (!bootstrap) throw new Error(`no interpreter script found in ${htmlPath}`);
  // Anchored on the array literal itself rather than on the concatenation in
  // front of it: responses differ in whether a space follows the `+`.
  const from = bootstrap.indexOf("['//# sourceMappingURL");
  const to = bootstrap.indexOf("].join('\\n')", from);
  if (from < 0 || to < 0) throw new Error('could not isolate the interpreter string array');
  const interpreter = evaluateLiteral(bootstrap.slice(from, to + 1)).join('\n');

  // The program is a string literal, `var p = '...'`, in a separate script.
  // Matched as a literal, quote to quote, because the statement after it is not
  // always on a line of its own: cutting at the next semicolon can overshoot by
  // thousands of characters.
  const loader = scripts.find((s) => /var\s+p\s*=\s*'/.test(s));
  if (!loader) throw new Error('no program script found (var p = ...)');
  const literal = /var\s+p\s*=\s*('(?:[^'\\]|\\.)*')/.exec(loader);
  if (!literal) throw new Error('could not isolate the program string literal');
  const program = evaluateLiteral(`(${literal[1]})`);

  return { interpreter, program };
}

/**
 * Freezes everything non-deterministic. Without this two runs cannot be compared
 * byte for byte, and that comparison is the only way to tell whether a tool
 * changed the behaviour of the challenge.
 */
function freeze(window) {
  window.Math.random = () => FROZEN_RANDOM;

  const RealDate = window.Date;
  function FrozenDate(...args) {
    return args.length ? new RealDate(...args) : new RealDate(FROZEN_TIME_MS);
  }
  FrozenDate.prototype = RealDate.prototype;
  FrozenDate.now = () => FROZEN_TIME_MS;
  FrozenDate.parse = RealDate.parse;
  FrozenDate.UTC = RealDate.UTC;
  window.Date = FrozenDate;

  let ticks = 0;
  window.performance.now = () => ++ticks;
  defineIfPossible(window.performance, 'timeOrigin', { configurable: true, value: FROZEN_TIME_MS });

  // Otherwise jsdom tries to hit the network when the challenge reports telemetry.
  window.navigator.sendBeacon = () => true;
}

/**
 * Runs the challenge and returns the finished token.
 *
 * @param {object} options
 * @param {{ interpreter: string, program: string }} options.challenge
 * @param {(window: object) => (string|void)} [options.install]
 *   Instrumentation. Called before the interpreter starts. May return an
 *   expression to be used as the interpreter's `this` - that is how a Proxy is
 *   substituted for the real window. Return nothing and the interpreter gets `this`.
 * @param {number} [options.timeoutMs]
 * @returns {Promise<string>} the token
 */
function run({ challenge, install, timeoutMs = DEFAULT_TIMEOUT_MS }) {
  return new Promise((resolve, reject) => {
    const { window } = new JSDOM(PAGE_HTML, {
      url: PAGE_URL,
      referrer: REFERRER,
      pretendToBeVisual: true,
      runScripts: 'outside-only',
    });

    freeze(window);
    const host = (install && install(window)) || 'this';

    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      window.close();
      fn(value);
    };
    const timer = setTimeout(
      () => finish(reject, new Error(`the challenge did not finish within ${timeoutMs} ms`)),
      timeoutMs,
    );

    try {
      window.eval(`(function(){\n${challenge.interpreter}\n}).call(${host});`);

      const vm = findInterpreterGlobal(window);
      if (!vm) throw new Error('the interpreter did not register its global object');

      window.__program = challenge.program;
      window.__done = (token) => finish(resolve, token);
      window.eval(
        `(function(){ var bindings = [{}];` +
          ` window.${vm}.a(window.__program,` +
          ` function (invoke) { return void invoke(window.__done, bindings); },` +
          ` false, undefined, undefined, undefined, undefined, true); })();`,
      );
    } catch (error) {
      finish(reject, error);
    }
  });
}

/**
 * The name of the interpreter's global object differs between responses, so it is
 * located by shape: an object with an `a` method and an `m` field.
 */
function findInterpreterGlobal(window) {
  for (const name of Object.getOwnPropertyNames(window)) {
    let value;
    try {
      value = window[name];
    } catch {
      continue;
    }
    if (value && typeof value === 'object' && typeof value.a === 'function' && 'm' in value) {
      return name;
    }
  }
  return null;
}

/** Parses a string literal lifted from the HTML: the escaping there is non-trivial. */
function evaluateLiteral(source) {
  return (0, eval)(source);
}

/** defineProperty on jsdom host objects is sometimes impossible - that is not an error. */
function defineIfPossible(target, key, descriptor) {
  try {
    Object.defineProperty(target, key, descriptor);
  } catch {
    /* the property cannot be redefined, leave it as it is */
  }
}

module.exports = { extract, run, PAGE_URL };
