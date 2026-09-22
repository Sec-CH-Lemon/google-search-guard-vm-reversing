'use strict';
// ============================================================================
//  build-compare.cjs — which BUILD is a page on, and what does it carry?
//
//  compare-responses.cjs answers the same question but only for pretty-printed
//  captures: it locates the interpreter by marker text, which a live minified
//  page does not have, so every field comes back <unparsed>. This one parses
//  with the AST extractor and works on either shape.
//
//  It exists because the interpreter turned out NOT to be a constant of the
//  system. Every capture from July 2026 carries 60853 chars / sha 885c049eda50;
//  a page fetched on 2026-08-21 came back with 61857 / c348580f3670. Anything
//  derived from the interpreter — the self-fingerprint constant, the base opcode
//  table — is scoped to one build and has to be re-measured when the sha moves.
//
//     node build-compare.cjs page.html [more.html …]
//     node build-compare.cjs                 (defaults to the captures)
// ============================================================================
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseChallenge } = require('./lib/challenge.js');

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 12);

const files = process.argv.slice(2).filter((a) => !a.startsWith('--'));
if (!files.length) {
  files.push(
    path.join(__dirname, 'captures', 'response.html'),
    path.join(__dirname, 'captures', 'response2.html'),
    path.join(__dirname, 'captures', 'response3.html'),
    path.join(__dirname, 'captures', 'challenge-live.html'),
  );
}

const rows = [];
for (const f of files) {
  const p = path.isAbsolute(f) ? f : path.resolve(f);
  let r;
  try {
    const c = parseChallenge(fs.readFileSync(p, 'utf8'));
    r = {
      file: path.basename(p),
      vmChars: c.vm.length,
      vmSha: sha(c.vm),
      bytecode: c.payload.length,
      eid: c.eid,
      ce: c.ce,
      version: c.challengeVersion,
      cbs: c.cbs,
      ssCgi: c.ssCgi,
      r: c.writesCookie,
    };
  } catch (e) {
    r = { file: path.basename(p), error: e.message };
  }
  rows.push(r);
}

console.log('file                      interpreter  sha           bytecode  ce  ver  ss_cgi  r     eid');
console.log('-'.repeat(112));
for (const r of rows) {
  if (r.error) { console.log(r.file.padEnd(25) + ' ERROR: ' + r.error); continue; }
  console.log(
    r.file.padEnd(25) + ' ' +
    String(r.vmChars).padStart(11) + '  ' + r.vmSha + '  ' +
    String(r.bytecode).padStart(8) + '  ' + String(r.ce).padStart(2) + '  ' +
    String(r.version).padStart(3) + '  ' + String(r.ssCgi).padStart(6) + '  ' +
    String(r.r).padStart(5) + '  ' + (r.eid || '(none)'),
  );
}

// The build is the thing that matters: constants derived from the interpreter are
// only valid within one.
const builds = new Map();
for (const r of rows) {
  if (r.error) continue;
  const k = r.vmSha + '  (' + r.vmChars + ' chars)';
  if (!builds.has(k)) builds.set(k, []);
  builds.get(k).push(r.file);
}
console.log('');
console.log('builds seen: ' + builds.size);
for (const [k, fl] of builds) console.log('  ' + k + '   ' + fl.join(', '));
if (builds.size > 1) {
  console.log('');
  console.log('MORE THAN ONE BUILD. Anything measured from the interpreter — the');
  console.log('self-fingerprint constant, the base opcode table, the fixed/per-response');
  console.log('split — is valid only within a single sha and must be re-measured.');
}
