'use strict';

/**
 * Saves your own capture of the interstitial.
 *
 * Every other script here reads a file. This is the one that goes to the
 * network, and all it does is the manual step from the README: request the
 * search page with no cookies at all and write the response to disk.
 *
 * The cookieless request is the whole trick. A browser Google already trusts
 * gets results, and a session cookie is exactly what makes it skip the
 * challenge - so nothing resembling a session is sent, and the response is
 * checked rather than assumed. The file is kept only once the interpreter and
 * the encrypted program have actually been found inside it, which is the same
 * test `extract` applies later. If this script says it saved a capture, the
 * other tools will be able to read it.
 *
 *   node fetch-challenge.js [--out=path] [--query=text] [--attempts=n] [--delay=ms] [--force]
 */

const fs = require('fs');
const path = require('path');
const { extract } = require('./lib/challenge');

const DEFAULT_QUERY = 'hello';
const DEFAULT_ATTEMPTS = 3;
const DEFAULT_DELAY_MS = 5000;

/** A retry loop against someone else's search engine should stay small. */
const MAX_ATTEMPTS = 10;

/**
 * Chrome's own headers for a top-level navigation, minus anything that carries
 * a session. `Sec-Fetch-Site: none` is what an address-bar visit looks like.
 */
const HEADERS = {
  'User-Agent':
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) ' +
    'Chrome/140.0.0.0 Safari/537.36',
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
  'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"macOS"',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
  'Sec-Fetch-User': '?1',
  'Upgrade-Insecure-Requests': '1',
};

/** What each verdict means, and what to do about it. */
const EXPLANATIONS = {
  results: 'Google returned search results, so this IP is trusted enough to skip the challenge. Retrying may help, a different IP helps more.',
  captcha: 'Redirected to the /sorry/ page: this IP is rate limited or flagged. A different IP is the only fix.',
  consent: 'Redirected to a consent page, which happens on European exits. Use an exit where consent is not required.',
  redirect: 'Redirected somewhere unexpected. The location header is above.',
  'http-error': 'Google answered with an error rather than a page.',
  partial: 'The page looks like the challenge but one of its two halves is missing. Either the build changed, or the response was truncated.',
};

/**
 * Classifies a response by the two things `extract` needs: the interpreter,
 * shipped as an array of strings the page joins, and the encrypted program in a
 * `var p = '...'` literal. Anything with both is a capture worth keeping.
 *
 * @param {number} status
 * @param {string|null} location value of the Location header, if any
 * @param {string} html
 * @returns {string} one of challenge, results, captcha, consent, redirect, http-error, partial
 */
function classify(status, location, html) {
  if (location) {
    if (location.includes('/sorry/')) return 'captcha';
    if (location.includes('consent.')) return 'consent';
    return 'redirect';
  }
  if (status !== 200) return 'http-error';

  const hasInterpreter = html.includes("].join('\\n')");
  const hasProgram = /var\s+p\s*=\s*'/.test(html);
  if (hasInterpreter && hasProgram) return 'challenge';
  if (hasInterpreter || hasProgram) return 'partial';
  return 'results';
}

/**
 * One request. Redirects are not followed: where Google sends you is itself the
 * answer, and following it would just save the wrong page.
 *
 * @param {string} url
 * @returns {Promise<{status: number, location: string|null, html: string, verdict: string}>}
 */
async function fetchOnce(url) {
  const response = await fetch(url, { headers: HEADERS, redirect: 'manual' });
  const html = await response.text();
  const location = response.headers.get('location');
  return { status: response.status, location, html, verdict: classify(response.status, location, html) };
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  const args = process.argv.slice(2);
  const option = (name, fallback) => {
    const hit = args.find((a) => a.startsWith(`--${name}=`));
    return hit ? hit.slice(name.length + 3) : fallback;
  };

  const out = path.resolve(option('out', path.join(__dirname, 'challenge.html')));
  const query = option('query', DEFAULT_QUERY);
  const delayMs = Number(option('delay', DEFAULT_DELAY_MS));
  const force = args.includes('--force');

  const attempts = Number(option('attempts', DEFAULT_ATTEMPTS));
  if (!Number.isInteger(attempts) || attempts < 1 || attempts > MAX_ATTEMPTS) {
    throw new Error(`--attempts must be between 1 and ${MAX_ATTEMPTS}`);
  }

  // The hostname is part of what the challenge derives its key from, so this
  // stays www.google.com rather than a regional domain.
  const url = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
  console.log(`GET ${url}`);

  let last;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    last = await fetchOnce(url);
    const size = `${last.html.length} bytes`;
    console.log(
      `  attempt ${attempt}/${attempts}: ${last.status} ${last.verdict}, ${size}` +
        (last.location ? `, location ${last.location}` : ''),
    );
    if (last.verdict === 'challenge') break;
    if (attempt < attempts) await wait(delayMs);
  }

  if (last.verdict !== 'challenge' && !force) {
    console.error(`\n${EXPLANATIONS[last.verdict] || 'Unrecognised response.'}`);
    console.error('Nothing was written. Pass --force to save the response anyway.');
    process.exit(1);
  }

  fs.writeFileSync(out, last.html);
  console.log(`\nsaved ${last.html.length} bytes to ${out}`);

  if (last.verdict !== 'challenge') {
    console.error(`Saved on --force, but this is "${last.verdict}" and the tools will not read it.`);
    process.exit(1);
  }

  // Same call the other tools make. Proof the capture is usable, not just present.
  const { interpreter, program } = extract(out);
  console.log(`interpreter ${interpreter.length} chars, encrypted program ${program.length} chars`);
  console.log('\nNext: node probe-proxy.js');
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = { classify, fetchOnce, HEADERS };
