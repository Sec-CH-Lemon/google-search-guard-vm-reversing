'use strict';

/**
 * What the challenge reads from the browser and what it calls - observed
 * through a Proxy.
 *
 * The interpreter is installed as `(function(){...}).call(this)` and keeps the
 * object it was handed in an ordinary variable. So we can pass it a stand-in
 * instead of the real window: every property access then goes through a single
 * trap, including accesses to names that do not exist in the browser at all.
 * Those missing names are exactly the automation probes.
 *
 * A stand-in on window alone is not enough: it sees the access to `navigator`,
 * but not the read of `navigator.webdriver` that follows. So nested objects are
 * wrapped too - and which ones is not hardcoded. The tool discovers them:
 *
 *   1. run with a flat stand-in on window and note which objects were read;
 *   2. wrap those and check that the token still matches a clean run;
 *   3. if it does not, find the surfaces that break it, drop them, and report it.
 *
 * Reads alone stop one step short of the answer: they say the challenge took
 * `document.createElement`, not whether it asked for a div or for a canvas. So
 * every function handed out goes back inside a stand-in of its own, whose
 * `apply` and `construct` traps record the arguments and the result. Which
 * functions those are is discovered the same way - they are the reads that
 * returned a function - and cleared through the same three steps.
 *
 * That keeps the tool working when the challenge starts reading or calling
 * something new, instead of silently missing it.
 *
 *   node probe-proxy.js [--html=path] [--json]
 */

const path = require('path');
const { extract, run } = require('./lib/challenge');
const { formatTable } = require('./lib/report');

/** Safety stop for the descent: nothing observed so far nests deeper than this. */
const MAX_DEPTH = 4;

/** Must hand back the stand-in, not the real window: the challenge compares parent to window. */
const SELF_REFERENCES = new Set(['window', 'self', 'globalThis', 'parent', 'top', 'frames']);

/**
 * Wraps window in a stand-in that records every access and every call.
 *
 * @param {object} window
 * @param {Array} log where observations are collected
 * @param {object} watch what to instrument
 * @param {Set<string>} watch.surfaces names of nested objects to descend into
 * @param {Set<string>} watch.calls paths of functions to observe the calls of
 * @returns {Proxy} the object to hand to the interpreter instead of window
 */
function createProbe(window, log, { surfaces, calls = new Set() }) {
  const proxies = new WeakMap(); // object -> its stand-in, to preserve identity
  const bound = new WeakMap(); // method -> the same method bound to its owner
  const callable = new WeakMap(); // function -> its call-recording stand-in
  let root;

  const record = (op, key, exists, value) =>
    log.push({ op, key, exists, args: '', value: op === 'read' ? describe(value) : '' });

  const recordCall = (op, key, args, value) =>
    log.push({ op, key, exists: true, args: args.map(describe).join(', '), value: describe(value) });

  /**
   * Hands a function back inside a stand-in of its own, so that the call is
   * observed and not just the read that fetched it. A stand-in over a callable is
   * itself callable and constructible, so `new` keeps working through it.
   *
   * The WeakMap makes repeated reads of one function yield one stand-in, the way
   * a real property read does. This challenge turns out not to compare function
   * identity - handing out a fresh stand-in every time is equally unnoticed - but
   * there is no reason to give it something a browser never would.
   */
  const wrapCall = (fn, pathname) => {
    if (!calls.has(pathname)) return fn;
    if (callable.has(fn)) return callable.get(fn);

    // Recording happens after the call returns, and outside the catch: a failure
    // to describe a result must surface as itself, not as a call that threw.
    const observe = (op, args, invoke) => {
      let result;
      try {
        result = invoke();
      } catch (error) {
        recordCall('throw', pathname, args, reason(error));
        throw error;
      }
      recordCall(op, pathname, args, result);
      return result;
    };

    const proxy = new Proxy(fn, {
      apply: (target, self, args) => observe('call', args, () => Reflect.apply(target, self, args)),
      construct: (target, args, newTarget) =>
        observe('new', args, () => Reflect.construct(target, args, newTarget)),
    });

    callable.set(fn, proxy);
    return proxy;
  };

  /**
   * `document` is wrapped one level deep only. Its methods are handed back bound
   * to the real document: calling them through the stand-in would throw Illegal
   * invocation. Going deeper is not an option - a stand-in on DOM nodes changes
   * the token, which step 3 above would catch as a broken run.
   */
  const wrapDocument = (document) => {
    if (proxies.has(document)) return proxies.get(document);

    const proxy = new Proxy(document, {
      get(object, key) {
        if (typeof key !== 'string') return Reflect.get(object, key);

        const value = Reflect.get(object, key);
        record('read', `document.${key}`, Reflect.has(object, key), value);

        if (value === window) return root; // document.defaultView
        if (typeof value !== 'function') return value;

        if (!bound.has(value)) bound.set(value, value.bind(object));
        return wrapCall(bound.get(value), `document.${key}`);
      },

      has(object, key) {
        const exists = Reflect.has(object, key);
        if (typeof key === 'string') record('in', `document.${key}`, exists);
        return exists;
      },
    });

    proxies.set(document, proxy);
    return proxy;
  };

  const wrap = (target, prefix, depth = 1) => {
    if (proxies.has(target)) return proxies.get(target);

    const proxy = new Proxy(target, {
      get(object, key) {
        if (typeof key !== 'string') return Reflect.get(object, key);

        const pathname = prefix === 'window' ? `window.${key}` : `${prefix}.${key}`;
        const value = Reflect.get(object, key);
        record('read', pathname, Reflect.has(object, key), value);

        // Self-references have to point at the stand-in, otherwise the challenge
        // concludes it is running inside a frame and takes a different branch.
        if (SELF_REFERENCES.has(key) && value === window) return root;
        if (value === window.document) return wrapDocument(value);
        if (typeof value === 'function') return wrapCall(value, pathname);

        // Descend into a discovered top-level surface, and then into anything
        // object-valued inside it. Discovery only sees what window hands out, so
        // without the second rule a nested object such as `navigator.connection`
        // would be returned raw and the reads from it (effectiveType, rtt,
        // downlink) would never be logged.
        const insideSurface = prefix !== 'window';
        if (isSurface(value) && (surfaces.has(key) || insideSurface) && depth < MAX_DEPTH) {
          return wrap(value, prefix === 'window' ? key : pathname, depth + 1);
        }
        return value;
      },

      has(object, key) {
        const exists = Reflect.has(object, key);
        if (typeof key === 'string') {
          record('in', prefix === 'window' ? `window.${key}` : `${prefix}.${key}`, exists);
        }
        return exists;
      },

      ownKeys(object) {
        record('keys', prefix, true);
        return Reflect.ownKeys(object);
      },
    });

    proxies.set(target, proxy);
    return proxy;
  };

  root = wrap(window, 'window', 0);
  return root;
}

/**
 * Step 1: which nested objects does the challenge actually read off window?
 * A flat stand-in answers that without descending anywhere.
 */
async function discoverSurfaces(challenge) {
  const found = new Set();

  await run({
    challenge,
    install: (window) => {
      const flat = new Proxy(window, {
        get(object, key) {
          const value = Reflect.get(object, key);
          if (typeof key === 'string' && isSurface(value) && value !== window) found.add(key);
          return SELF_REFERENCES.has(key) && value === window ? flat : value;
        },
      });
      window.__probe = flat;
      return 'window.__probe';
    },
  });

  return found;
}

/** Runs the challenge with the given surfaces and calls instrumented. */
async function capture(challenge, watch) {
  const log = [];
  const token = await run({
    challenge,
    install: (window) => {
      window.__probe = createProbe(window, log, watch);
      return 'window.__probe';
    },
  });
  return { token, log };
}

/**
 * Step 3, for surfaces and for calls alike: instrument all the candidates, and if
 * the token moves, find which of them are at fault by trying them one at a time.
 * Naming the culprits and dropping them beats leaving the whole report untrustworthy.
 *
 * @param {object} challenge
 * @param {string} baseline the token from a clean run
 * @param {Set<string>} candidates what to instrument
 * @param {(subset: Set<string>) => object} watch builds the probe config for a subset
 * @returns {{ token, log, kept: Set<string>, rejected: Set<string> }}
 */
async function narrow(challenge, baseline, candidates, watch) {
  let result = await capture(challenge, watch(candidates));
  if (result.token === baseline) return { ...result, kept: candidates, rejected: new Set() };

  const rejected = new Set();
  for (const candidate of candidates) {
    const { token } = await capture(challenge, watch(new Set([candidate])));
    if (token !== baseline) rejected.add(candidate);
  }

  const kept = new Set([...candidates].filter((c) => !rejected.has(c)));
  result = await capture(challenge, watch(kept));
  return { ...result, kept, rejected };
}

/**
 * The functions worth calling through a stand-in are exactly the ones the
 * challenge was handed, so the list comes from the reads of the previous step
 * rather than from a hardcoded set of interesting API names.
 */
const calleesFrom = (log) =>
  new Set(log.filter((e) => e.op === 'read' && e.value === FUNCTION_MARK).map((e) => e.key));

/**
 * A surface worth descending into is an object instance such as navigator or
 * screen. Constructors and plain functions are excluded: the challenge reads
 * properties off instances, and wrapping `Array` or `Function` only adds noise.
 */
const isSurface = (value) => value !== null && typeof value === 'object';

/** How a function is rendered in the report, and how a callee is recognised in the log. */
const FUNCTION_MARK = '[fn]';

/** Short, printable rendering of a value for the report. */
function describe(value) {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'function') return FUNCTION_MARK;
  if (type === 'string') return JSON.stringify(value.length > 40 ? `${value.slice(0, 40)}…` : value);
  if (type !== 'object') return String(value);

  // Arguments come from the challenge, so inspecting them has to be safe: a
  // circular structure or a getter that refuses must not take the run down.
  try {
    if (Array.isArray(value)) return JSON.stringify(value).slice(0, 60);
    return `[${value.constructor?.name || 'object'}]`;
  } catch {
    return '[unreadable]';
  }
}

/** Why a call failed, without assuming that what was thrown is an Error. */
const reason = (error) =>
  error instanceof Error ? `${error.name}: ${error.message}` : `thrown ${describe(error)}`;

/**
 * Collapses repeats: the same access often happens several times per run. Calls
 * are collapsed per argument list, because that is the part worth reading -
 * `createElement('div')` and `createElement('canvas')` are different questions.
 */
function summarise(log) {
  const rows = new Map();
  for (const entry of log) {
    const id = `${entry.op}|${entry.key}|${entry.args}`;
    const row = rows.get(id);
    if (row) row.count += 1;
    else rows.set(id, { ...entry, count: 1 });
  }
  return [...rows.values()];
}

/**
 * Full probe: discover the surfaces, then the functions reached through them,
 * instrument both, and make sure the result is trustworthy.
 *
 * The two passes are ordered, not merged: the list of functions to call through
 * is a product of the reads, so the surfaces have to be settled first.
 *
 * @returns {{ invisible, rows, surfaces, unsafe, calls, unsafeCalls }}
 */
async function probe(challenge) {
  const baseline = await run({ challenge });
  const discovered = await discoverSurfaces(challenge);

  const reads = await narrow(challenge, baseline, discovered, (surfaces) => ({ surfaces }));
  const calls = await narrow(challenge, baseline, calleesFrom(reads.log), (subset) => ({
    surfaces: reads.kept,
    calls: subset,
  }));

  return {
    invisible: calls.token === baseline,
    rows: summarise(calls.log),
    surfaces: reads.kept,
    unsafe: reads.rejected,
    calls: calls.kept,
    unsafeCalls: calls.rejected,
  };
}

async function main() {
  const args = process.argv.slice(2);
  const option = (name, fallback) => {
    const hit = args.find((a) => a.startsWith(`--${name}=`));
    return hit ? hit.slice(name.length + 3) : fallback;
  };

  const htmlPath = path.resolve(option('html', path.join(__dirname, 'challenge.html')));
  const challenge = extract(htmlPath);
  const { invisible, rows, surfaces, unsafe, calls, unsafeCalls } = await probe(challenge);

  if (args.includes('--json')) {
    const asList = (set) => [...set];
    console.log(
      JSON.stringify(
        {
          invisible,
          surfaces: asList(surfaces),
          unsafe: asList(unsafe),
          calls: asList(calls),
          unsafeCalls: asList(unsafeCalls),
          rows,
        },
        null,
        2,
      ),
    );
  } else {
    console.log(formatTable(rows, { invisible }));
    console.log(`\n  nested surfaces descended into: ${[...surfaces].join(', ') || 'none'}`);
    console.log(`  functions called through a stand-in: ${[...calls].join(', ') || 'none'}`);
    for (const [what, excluded] of [
      ['surfaces', unsafe],
      ['functions', unsafeCalls],
    ]) {
      if (!excluded.size) continue;
      console.log(`  excluded as unsafe (${what}): ${[...excluded].join(', ')}`);
      console.log('  (instrumenting these changes the token, so they are missing from the report)');
    }
  }

  if (!invisible) console.error('\nThe token differs from a clean run: this report cannot be trusted.');
  process.exit(invisible ? 0 : 1);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = { calleesFrom, capture, createProbe, discoverSurfaces, probe, summarise };
