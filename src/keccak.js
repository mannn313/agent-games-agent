// Vendored Keccak-256 (NOT SHA3-256: Keccak padding 0x01, no 0x06 domain
// byte). Pure JS, no dependencies. Verified against NIST/Keccak test vectors
// in test/test-keccak.js. Used for taskId/salt field encodings (see
// encodings.js) — the platform's own docs use keccak256 (viem) for hashes.
'use strict';

// Round constants (64-bit), split into hi/lo 32-bit words.
const RC = [
  [0x00000000, 0x00000001], [0x00000000, 0x00008082],
  [0x80000000, 0x0000808a], [0x80000000, 0x80008000],
  [0x00000000, 0x0000808b], [0x00000000, 0x80000001],
  [0x80000000, 0x80008081], [0x80000000, 0x00008009],
  [0x00000000, 0x0000008a], [0x00000000, 0x00000088],
  [0x00000000, 0x80008009], [0x00000000, 0x8000000a],
  [0x00000000, 0x8000808b], [0x80000000, 0x0000008b],
  [0x80000000, 0x00008089], [0x80000000, 0x00008003],
  [0x80000000, 0x00008002], [0x80000000, 0x00000080],
  [0x00000000, 0x0000800a], [0x80000000, 0x8000000a],
  [0x80000000, 0x80008081], [0x80000000, 0x00008080],
  [0x00000000, 0x80000001], [0x80000000, 0x80008008],
];

// Rotation offsets, indexed by lane i = x + 5*y.
const ROT = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

// Pi permutation: lane (x,y) moves to (y, (2x+3y) mod 5).
const PI = (() => {
  const p = new Array(25);
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      p[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5);
    }
  }
  return p;
})();

function rotl64(hi, lo, n) {
  if (n === 0) return [hi, lo];
  if (n < 32) return [((hi << n) | (lo >>> (32 - n))) >>> 0, ((lo << n) | (hi >>> (32 - n))) >>> 0];
  const m = n - 32;
  return [((lo << m) | (hi >>> (32 - m))) >>> 0, ((hi << m) | (lo >>> (32 - m))) >>> 0];
}

function keccakF(h, l) {
  const Ch = new Array(5), Cl = new Array(5);
  const Bh = new Array(25), Bl = new Array(25);
  for (let round = 0; round < 24; round++) {
    // Theta
    for (let x = 0; x < 5; x++) {
      Ch[x] = h[x] ^ h[x + 5] ^ h[x + 10] ^ h[x + 15] ^ h[x + 20];
      Cl[x] = l[x] ^ l[x + 5] ^ l[x + 10] ^ l[x + 15] ^ l[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      const [dh, dl] = rotl64(Ch[(x + 1) % 5], Cl[(x + 1) % 5], 1);
      const dhi = dh ^ Ch[(x + 4) % 5], dlo = dl ^ Cl[(x + 4) % 5];
      for (let y = 0; y < 5; y++) {
        h[x + 5 * y] = (h[x + 5 * y] ^ dhi) >>> 0;
        l[x + 5 * y] = (l[x + 5 * y] ^ dlo) >>> 0;
      }
    }
    // Rho + Pi
    for (let i = 0; i < 25; i++) {
      const [rh, rl] = rotl64(h[i], l[i], ROT[i]);
      Bh[PI[i]] = rh; Bl[PI[i]] = rl;
    }
    // Chi
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        const i = x + 5 * y;
        const i1 = ((x + 1) % 5) + 5 * y, i2 = ((x + 2) % 5) + 5 * y;
        h[i] = (Bh[i] ^ (~Bh[i1] & Bh[i2])) >>> 0;
        l[i] = (Bl[i] ^ (~Bl[i1] & Bl[i2])) >>> 0;
      }
    }
    // Iota
    h[0] = (h[0] ^ RC[round][0]) >>> 0;
    l[0] = (l[0] ^ RC[round][1]) >>> 0;
  }
}

// Absorb + squeeze. Rate = 136 bytes (1088-bit), output 32 bytes.
function keccak256(data) {
  const msg = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const h = new Array(25).fill(0), l = new Array(25).fill(0);
  const RATE = 136;
  let off = 0;
  // Full blocks
  while (off + RATE <= msg.length) {
    absorbBlock(h, l, msg, off, RATE);
    keccakF(h, l);
    off += RATE;
  }
  // Final block with pad10*1 (Keccak domain 0x01)
  const rem = msg.length - off;
  const block = Buffer.alloc(RATE);
  msg.copy(block, 0, off);
  block[rem] ^= 0x01;
  block[RATE - 1] ^= 0x80;
  absorbBlock(h, l, block, 0, RATE);
  keccakF(h, l);
  // Squeeze 32 bytes, little-endian lanes
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    out.writeUInt32LE(l[i] >>> 0, i * 8);
    out.writeUInt32LE(h[i] >>> 0, i * 8 + 4);
  }
  return out;
}

function absorbBlock(h, l, buf, off, len) {
  for (let i = 0; i < len / 8; i++) {
    l[i] = (l[i] ^ buf.readUInt32LE(off + i * 8)) >>> 0;
    h[i] = (h[i] ^ buf.readUInt32LE(off + i * 8 + 4)) >>> 0;
  }
}

module.exports = { keccak256 };
