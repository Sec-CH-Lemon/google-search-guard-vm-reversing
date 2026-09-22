'use strict';
// ============================================================================
//  lib/builds.js - the per-build facts a tool cannot derive on its own.
//
//  Most other facts in this bundle are sought by shape or by observed behaviour.
//  The measured rebuilds changed many internal names and opcode numbers, but that
//  is a corpus observation rather than a promise about every future build. These
//  reviewed values are kept here so a tool can check itself against builds that
//  somebody has already walked.
//
//  `readable` is a fallback name only. build-profile.cjs looks for
//  `vm-readable-<build sha>.js` first, which is what the README tells you to
//  generate, and reaches this field only if that file is not there.
//
//  Adding a build: run opcode-trace.cjs against it for the alphabet loader and
//  the re-key, read the store twins and the register file off build-profile.cjs,
//  then paste the result in.
// ============================================================================

const KNOWN_BUILDS = {
  '885c049eda50': {
    readable: 'vm-readable.js',
    stores: [{ name: 'w', slot: 'e', value: 'X' }, { name: 'C', slot: 'e', value: 'X' }, { name: 'R', slot: 'U', value: 'X' }],
    pc: 202,
    registerFile: 'S',
    // measured by opcode-trace.cjs, and matching what 06-vm-mechanics §6 documents
    alphabet: 262,
    rekeyVia: 501,
  },
  c348580f3670: {
    readable: 'vm-readable-c348580f3670.js',
    stores: [{ name: 'g', slot: 'X', value: 'p' }, { name: 'R', slot: 'X', value: 'p' }, { name: 'N', slot: 'I', value: 'X' }],
    pc: 473,
    registerFile: 'O',
    alphabet: 484,
    rekeyVia: 107,
  },
  // 2026-08-27. Third build. The three store twins disagree on argument order on
  // every build, and this one introduces an ordering neither predecessor used:
  //   m(state, slot, value)   w(slot, state, value)   A(state, value, slot)
  // `A` is the odd one out here, as `R` was on 885c049eda50 and `N` on c348580f3670.
  // pc/keyCtl and the register-file property are read straight out of the store
  // body: it branches on `J == 302 || J == 452` to extend rather than replace,
  // and re-keys on `J == 376`.
  // 2026-09-11. Fourth build. First one whose three store twins all take the same
  // argument order — on the three before it, one was always the odd one out, which
  // shows that permutation is a per-build coin flip rather than a rule.
  '80056f9da7b2': {
    readable: 'vm-readable-80056f9da7b2.js',
    stores: [{ name: 'H', slot: 'b', value: 'I' }, { name: 'X', slot: 'b', value: 'I' },
      { name: 'Jy', slot: 'b', value: 'I' }],
    pc: 6,
    registerFile: 'N',
    alphabet: 345,
    rekeyVia: 216,
  },
  d4a6b4f0a2a5: {
    readable: 'vm-readable-d4a6b4f0a2a5.js',
    stores: [{ name: 'm', slot: 'J', value: 'L' }, { name: 'w', slot: 'e', value: 'L' }, { name: 'A', slot: 'L', value: 'J' }],
    pc: 302,
    registerFile: 'D',
    alphabet: 498,
    rekeyVia: 86,
  },
  // Current publication capture. The iframe self-fingerprint tap was
  // byte-identical to the untapped run (69 calls, 66 distinct texts).
  // build-primitives.cjs found all three stores by shape; opcode-trace.cjs
  // supplied the first-executed alphabet candidate and first key transition.
  // The resulting cipher oracle matched the first plaintext opcode (38).
  f6ad334abefc: {
    readable: 'vm-readable-f6ad334abefc.js',
    stores: [{ name: 'k', slot: 'e', value: 'u' }, { name: 'I', slot: 'e', value: 'u' },
      { name: 'w', slot: 'e', value: 'u' }],
    pc: 389,
    instructionStart: 52,
    outputKeySlot: 251,
    outputKeyWords: [1, 2],
    registerFile: 'u',
    alphabet: 38,
    rekeyVia: 276,
  },
};

module.exports = { KNOWN_BUILDS };
