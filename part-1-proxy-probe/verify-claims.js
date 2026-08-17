'use strict';

/**
 * Verifies the claims made in the article by measurement.
 *
 * Each claim is checked with its own run of the challenge and compared against
 * the expected value. The point is that the article can be re-checked instead of
 * taken on trust: if Google changes the challenge, some of these will go red.
 *
 *   node verify-claims.js [--html=path] [--slow]
 *
 * --slow adds the long self-integrity check: it edits the interpreter source in
 * several places and observes whether the challenge notices the tampering.
 */

const path = require('path');
const { extract, run } = require('./lib/challenge');
const { probe } = require('./probe-proxy');

const EMERGENCY_TOKEN_LENGTH = 871; // the fallback token issued when tampering is detected

async function main() {
  const args = process.argv.slice(2);
  const option = (name, fallback) => {
    const hit = args.find((a) => a.startsWith(`--${name}=`));
    return hit ? hit.slice(name.length + 3) : fallback;
  };

  const htmlPath = path.resolve(option('html', path.join(__dirname, 'challenge.html')));
  const challenge = extract(htmlPath);
  const baseline = await run({ challenge });

  const results = [];
  const check = (claim, expected, actual) =>
    results.push({ claim, expected, actual, ok: expected === actual });

  // --- static facts about the page -------------------------------------------
  check('interpreter source length', 60853, challenge.interpreter.length);
  check(
    'encrypted program size, bytes',
    12307,
    Buffer.from(challenge.program.slice(3), 'base64').length,
  );
  // `screen` does occur in the source, but only as screenX/screenY inside a mouse
  // event helper - nothing to do with fingerprint collection.
  check(
    'readable property names in the interpreter source',
    0,
    (challenge.interpreter.match(/navigator|webdriver|screen(?![XY])/g) || []).length,
  );
  check('token length on a clean run', 1660, baseline.length);

  // --- interception through a Proxy -------------------------------------------
  // probe() discovers the nested surfaces and the functions itself, and drops any
  // that break the run, so this also asserts that none had to be dropped here.
  const { invisible, unsafe, calls, unsafeCalls, rows } = await probe(challenge);
  check('a Proxy in place of window goes unnoticed', true, invisible);
  check('surfaces that had to be excluded', 0, unsafe.size);

  // --- interception of the calls ------------------------------------------------
  check('functions the challenge is handed', 11, calls.size);
  check('functions that had to be excluded', 0, unsafeCalls.size);
  // The reason for watching calls at all: the read of createElement is one line
  // either way, but what it is asked to build is not the same question.
  check('elements the challenge builds', 'a, iframe', argumentsOf(rows, 'document.createElement'));

  // An unchanged token is only evidence if the token can move at all. It does when
  // a single call answers differently - so observing calls without altering them,
  // which is what `invisible` above reports, is a real result and not a tautology.
  const altered = await run({ challenge, install: (window) => void (window.Math.random = () => 0.5) });
  check('a call that answers differently changes the token', true, altered !== baseline);

  // A stand-in does not carry the source text of the function it wraps: toString
  // gives the native-code form instead. Eleven functions go through stand-ins and
  // the token holds, so the challenge does not read the source of what it calls.
  check('a stand-in does not carry the function source', true, standInHidesSource());

  // Self-references: hand back the real window for parent/top and the challenge
  // decides it is running inside a frame, producing a different token.
  const naive = await run({
    challenge,
    install: (window) => {
      window.__probe = new Proxy(window, { get: (o, k) => Reflect.get(o, k) });
      return 'window.__probe';
    },
  });
  check('without rewriting self-references the token changes', true, naive !== baseline);

  // --- Navigator.prototype -----------------------------------------------------
  const onPrototype = await run({
    challenge,
    install: (window) => void wrapNavigatorAccessors(window, { onPrototype: true }),
  });
  check('wrapping Navigator.prototype changes the token', true, onPrototype !== baseline);
  check(
    'and the fallback token is NOT issued',
    true,
    onPrototype.length !== EMERGENCY_TOKEN_LENGTH,
  );

  const onInstance = await run({
    challenge,
    install: (window) => void wrapNavigatorAccessors(window, { onPrototype: false }),
  });
  check('shadowing the navigator instance is unnoticed', true, onInstance === baseline);

  // --- document ----------------------------------------------------------------
  check('window.document cannot be redefined', true, documentIsUnforgeable());

  // --- interpreter self-integrity (slow) ---------------------------------------
  if (args.includes('--slow')) {
    const { detected, total } = await countTamperDetections(challenge);
    check('a source edit is caught by the self-check', true, detected > 0);
    console.log(`      tampering detected in ${detected} of ${total} probes`);
  }

  report(results);
  process.exit(results.every((r) => r.ok) ? 0 : 1);
}

/**
 * Wraps the navigator getters. On the prototype the challenge reads plugins and
 * mimeTypes as a tamper probe, so a wrapper there changes the token; shadowing
 * the navigator object itself leaves those reads untouched.
 */
function wrapNavigatorAccessors(window, { onPrototype }) {
  const prototype = window.Navigator.prototype;
  const target = onPrototype ? prototype : window.navigator;

  for (const key of Object.getOwnPropertyNames(prototype)) {
    if (key === 'constructor') continue;

    const descriptor = Object.getOwnPropertyDescriptor(prototype, key);
    if (!descriptor || !descriptor.get) continue;

    const original = descriptor.get;
    try {
      Object.defineProperty(target, key, {
        configurable: true,
        enumerable: onPrototype ? descriptor.enumerable : false,
        get() {
          return original.call(this);
        },
      });
    } catch {
      /* the property cannot be redefined - skip it */
    }
  }
}

/** The argument lists a given function was called with, deduplicated and sorted. */
function argumentsOf(rows, key) {
  const calls = rows.filter((row) => row.op === 'call' && row.key === key);
  return [...new Set(calls.map((row) => row.args.replace(/"/g, '')))].sort().join(', ');
}

/** `toString` on a stand-in returns the native-code form, not the wrapped source. */
function standInHidesSource() {
  const { JSDOM } = require('jsdom');
  const { window } = new JSDOM('<!doctype html><html><body></body></html>');
  try {
    const fn = window.addEventListener;
    return String(fn) !== String(new Proxy(fn, {}));
  } finally {
    window.close();
  }
}

/** window.document is marked unforgeable: defineProperty on it throws. */
function documentIsUnforgeable() {
  const { JSDOM } = require('jsdom');
  const { window } = new JSDOM('<!doctype html><html><body></body></html>');
  try {
    Object.defineProperty(window, 'document', { configurable: true, get: () => null });
    return false;
  } catch {
    return true;
  } finally {
    window.close();
  }
}

/**
 * Inserts an inert comment at the start of a few interpreter functions and counts
 * how often the challenge notices. The comment changes no behaviour, but it does
 * change the source text - and the functions hash that text themselves.
 */
async function countTamperDetections(challenge, samples = 6) {
  const positions = [...challenge.interpreter.matchAll(/function\s*\([^)]*\)\s*\{/g)]
    .map((m) => m.index + m[0].length)
    .filter((_, i) => i % 40 === 0)
    .slice(0, samples);

  let detected = 0;
  for (const at of positions) {
    const patched = {
      ...challenge,
      interpreter: `${challenge.interpreter.slice(0, at)}/*x*/${challenge.interpreter.slice(at)}`,
    };
    const token = await run({ challenge: patched }).catch(() => '');
    if (token.length === EMERGENCY_TOKEN_LENGTH) detected += 1;
  }
  return { detected, total: positions.length };
}

function report(results) {
  const width = Math.max(...results.map((r) => r.claim.length));
  for (const { claim, expected, actual, ok } of results) {
    const status = ok ? 'OK  ' : 'FAIL';
    const detail = ok ? String(actual) : `expected ${expected}, got ${actual}`;
    console.log(`${status}  ${claim.padEnd(width)}  ${detail}`);
  }
  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n${results.length - failed} of ${results.length} checks passed`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
