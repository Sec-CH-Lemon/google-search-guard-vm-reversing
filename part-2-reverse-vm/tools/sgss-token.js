'use strict';

// Minimal ARX block helper used by static-disasm.cjs.
//
// The defaults describe the current publication interpreter (build
// f6ad334abefc): 15 rounds, round constant 1819, rotation 3. A generated
// capture profile replaces them before decoding, because these parameters
// belong to the supplied interpreter rather than to the SG_SS protocol.

let rounds = 15;
let roundConst = 1819;
let rotation = 3;

function cipherParams(next) {
  if (next !== undefined) {
    if (!next || ![next.rounds, next.roundConst, next.rot].every(Number.isFinite)) {
      throw new Error('cipher parameters must contain numeric rounds, roundConst and rot');
    }
    rounds = Number(next.rounds);
    roundConst = Number(next.roundConst);
    rotation = Number(next.rot);
  }
  return { rounds, roundConst, rot: rotation };
}

function keystreamBlock(k1, k2, dataHi, dataLo) {
  let f = k1 | 0;
  let v = k2 | 0;
  let y = dataHi | 0;
  let d = dataLo | 0;

  for (let i = 0; i < rounds; i++) {
    y = (y >>> 8) | (y << 24);
    y = (y + d) | 0;
    v = (v >>> 8) | (v << 24);
    d = (d << rotation) | (d >>> (32 - rotation));
    y ^= (f + roundConst) | 0;
    v = (v + f) | 0;
    f = (f << rotation) | (f >>> (32 - rotation));
    v ^= (i + roundConst) | 0;
    d ^= y;
    f ^= v;
  }

  return [
    (d >>> 24) & 255,
    (d >>> 16) & 255,
    (d >>> 8) & 255,
    d & 255,
    (y >>> 24) & 255,
    (y >>> 16) & 255,
    (y >>> 8) & 255,
    y & 255,
  ];
}

module.exports = { cipherParams, keystreamBlock };
