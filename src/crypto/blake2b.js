/**
 * @fileoverview Pure-JavaScript BLAKE2b Cryptographic Hash Function (RFC 7693).
 *
 * Implements 64-bit word operations, 12 rounds of the mixing function G,
 * parameter blocks, unkeyed and keyed hashing, and streaming context updates.
 */

import { normalizeBuffer } from '../utils/validation.js';

/**
 * 64-bit bitmask (2^64 - 1) for modular arithmetic.
 */
const MASK64 = 0xffffffffffffffffn;

/**
 * BLAKE2b Initialization Vectors (RFC 7693 Section 2.6).
 * Same constants as SHA-512 initial hash values.
 */
export const BLAKE2B_IV = Object.freeze([
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n
]);

/**
 * SIGMA message word permutation schedule (RFC 7693 Section 2.1).
 * 10 permutations of indices 0 through 15, repeated cyclically for 12 rounds.
 */
export const BLAKE2B_SIGMA = Object.freeze([
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
]);

/**
 * Circular right rotation of a 64-bit unsigned integer.
 *
 * @param {bigint} x - 64-bit integer
 * @param {bigint} c - Shift amount (1 to 63)
 * @returns {bigint} Rotated 64-bit integer
 */
export function rotr64(x, c) {
  return ((x >> c) | (x << (64n - c))) & MASK64;
}

/**
 * BLAKE2b Mixing Function G (RFC 7693 Section 3.1).
 *
 * Modifies four 64-bit state words using modular addition, bitwise XOR,
 * and 64-bit rotations (32, 24, 16, 63).
 *
 * @param {BigUint64Array} v - Working vector (16 elements)
 * @param {number} a - Index a
 * @param {number} b - Index b
 * @param {number} c - Index c
 * @param {number} d - Index d
 * @param {bigint} x - First message word
 * @param {bigint} y - Second message word
 */
export function blake2bG(v, a, b, c, d, x, y) {
  v[a] = (v[a] + v[b] + x) & MASK64;
  v[d] = rotr64(v[d] ^ v[a], 32n);
  v[c] = (v[c] + v[d]) & MASK64;
  v[b] = rotr64(v[b] ^ v[c], 24n);
  v[a] = (v[a] + v[b] + y) & MASK64;
  v[d] = rotr64(v[d] ^ v[a], 16n);
  v[c] = (v[c] + v[d]) & MASK64;
  v[b] = rotr64(v[b] ^ v[c], 63n);
}

/**
 * Core BLAKE2b compression function F (RFC 7693 Section 3.2).
 * Compresses one 128-byte block into state vector h.
 *
 * @param {BigUint64Array} h - Current 8-word state vector (in/out)
 * @param {BigUint64Array} m - 16-word message block
 * @param {bigint} t0 - Low 64 bits of byte offset
 * @param {bigint} t1 - High 64 bits of byte offset
 * @param {boolean} isFinal - True if this is the final block (sets f0 = 0xffffffffffffffffn)
 * @param {BigUint64Array} [vWork] - Optional reusable 16-word working array
 */
export function blake2bCompress(h, m, t0, t1, isFinal, vWork) {
  const v = vWork || new BigUint64Array(16);

  // Initialize working vector v[0..15]
  v[0] = h[0];
  v[1] = h[1];
  v[2] = h[2];
  v[3] = h[3];
  v[4] = h[4];
  v[5] = h[5];
  v[6] = h[6];
  v[7] = h[7];

  v[8] = BLAKE2B_IV[0];
  v[9] = BLAKE2B_IV[1];
  v[10] = BLAKE2B_IV[2];
  v[11] = BLAKE2B_IV[3];
  v[12] = BLAKE2B_IV[4] ^ t0;
  v[13] = BLAKE2B_IV[5] ^ t1;
  v[14] = isFinal ? BLAKE2B_IV[6] ^ MASK64 : BLAKE2B_IV[6];
  v[15] = BLAKE2B_IV[7];

  // 12 rounds of column and diagonal mixing
  for (let r = 0; r < 12; r++) {
    const s = BLAKE2B_SIGMA[r % 10];
    // Column step
    blake2bG(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    blake2bG(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    blake2bG(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    blake2bG(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

    // Diagonal step
    blake2bG(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    blake2bG(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    blake2bG(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    blake2bG(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }

  // Update chain value h[i] = h[i] ^ v[i] ^ v[i + 8]
  for (let i = 0; i < 8; i++) {
    h[i] = (h[i] ^ v[i] ^ v[i + 8]) & MASK64;
  }
}

/**
 * Streaming BLAKE2b Context.
 */
export class Blake2bContext {
  /**
   * @param {number} [outlen=64] - Output digest length in bytes (1 to 64)
   * @param {Uint8Array|Buffer|null} [key=null] - Optional secret key (up to 64 bytes)
   * @param {Object} [params] - Optional tree hashing or salt/personal parameters
   * @param {Uint8Array|null} [params.salt] - 16-byte salt
   * @param {Uint8Array|null} [params.personal] - 16-byte personalization string
   */
  constructor(outlen = 64, key = null, params = {}) {
    if (typeof outlen !== 'number' || !Number.isInteger(outlen) || outlen < 1 || outlen > 64) {
      throw new RangeError('BLAKE2b outlen must be an integer between 1 and 64');
    }

    const keyBytes = key ? normalizeBuffer(key, 'Key') : null;
    const keylen = keyBytes ? keyBytes.length : 0;
    if (keylen > 64) {
      throw new RangeError('BLAKE2b key length cannot exceed 64 bytes');
    }

    this.outlen = outlen;
    this.h = new BigUint64Array(8);

    // Initialize state with IV
    for (let i = 0; i < 8; i++) {
      this.h[i] = BLAKE2B_IV[i];
    }

    // Parameter block: word 0 = outlen | (keylen << 8) | (fanout << 16) | (depth << 24)
    // For sequential hashing, fanout = 1, depth = 1 -> 0x01010000n
    this.h[0] ^= 0x01010000n ^ (BigInt(keylen) << 8n) ^ BigInt(outlen);

    // Optional salt (words 4 and 5) and personalization (words 6 and 7)
    if (params.salt) {
      const saltBuf = normalizeBuffer(params.salt, 'Salt');
      if (saltBuf.length !== 16) throw new RangeError('BLAKE2b salt must be exactly 16 bytes');
      const view = new DataView(saltBuf.buffer, saltBuf.byteOffset, 16);
      this.h[4] ^= view.getBigUint64(0, true);
      this.h[5] ^= view.getBigUint64(8, true);
    }

    if (params.personal) {
      const personalBuf = normalizeBuffer(params.personal, 'Personal');
      if (personalBuf.length !== 16) throw new RangeError('BLAKE2b personal must be exactly 16 bytes');
      const view = new DataView(personalBuf.buffer, personalBuf.byteOffset, 16);
      this.h[6] ^= view.getBigUint64(0, true);
      this.h[7] ^= view.getBigUint64(8, true);
    }

    this.buf = new Uint8Array(128);
    this.bufLen = 0;
    this.t0 = 0n;
    this.t1 = 0n;

    // Pre-allocated reusable arrays for compression
    this.mWork = new BigUint64Array(16);
    this.vWork = new BigUint64Array(16);

    // Keyed hashing: pad key to 1 full block (128 bytes)
    if (keylen > 0) {
      this.buf.set(keyBytes);
      this.bufLen = 128;
    }
  }

  /**
   * Internal routine to compress current buffer block.
   *
   * @private
   * @param {Uint8Array} blockBytes - 128-byte block
   * @param {boolean} isFinal - True if final block
   */
  _compressBuffer(blockBytes, isFinal) {
    // Increment 128-bit counter t by bufLen
    const inc = BigInt(this.bufLen);
    this.t0 = (this.t0 + inc) & MASK64;
    if (this.t0 < inc) {
      this.t1 = (this.t1 + 1n) & MASK64;
    }

    // Convert 128 bytes to 16 little-endian 64-bit words
    const view = new DataView(blockBytes.buffer, blockBytes.byteOffset, 128);
    for (let i = 0; i < 16; i++) {
      this.mWork[i] = view.getBigUint64(i * 8, true);
    }

    blake2bCompress(this.h, this.mWork, this.t0, this.t1, isFinal, this.vWork);
  }

  /**
   * Updates the hash stream with additional message bytes.
   *
   * @param {string|Uint8Array|Buffer} data - Incoming message chunk
   * @returns {this}
   */
  update(data) {
    const bytes = normalizeBuffer(data, 'Message data');
    let offset = 0;
    let len = bytes.length;

    while (len > 0) {
      if (this.bufLen === 128) {
        this._compressBuffer(this.buf, false);
        this.bufLen = 0;
      }
      const want = 128 - this.bufLen;
      const take = Math.min(len, want);
      this.buf.set(bytes.subarray(offset, offset + take), this.bufLen);
      this.bufLen += take;
      offset += take;
      len -= take;
    }

    return this;
  }

  /**
   * Finalizes the hash and produces the digest.
   *
   * @returns {Uint8Array} Digest of length outlen
   */
  digest() {
    // Pad remaining buffer bytes with zero
    this.buf.fill(0, this.bufLen);
    this._compressBuffer(this.buf, true);

    const out = new Uint8Array(this.outlen);
    const view = new DataView(out.buffer, out.byteOffset, this.outlen);

    for (let i = 0; i < 8; i++) {
      const start = i * 8;
      if (start >= this.outlen) break;
      const remaining = this.outlen - start;
      if (remaining >= 8) {
        view.setBigUint64(start, this.h[i], true);
      } else {
        const temp = new Uint8Array(8);
        new DataView(temp.buffer).setBigUint64(0, this.h[i], true);
        out.set(temp.subarray(0, remaining), start);
      }
    }

    return out;
  }
}

/**
 * Computes BLAKE2b hash of an input message in a single call.
 *
 * @param {string|Uint8Array|Buffer} message - Input data to hash
 * @param {Uint8Array|Buffer|null} [key=null] - Optional secret key (up to 64 bytes)
 * @param {number} [outlen=64] - Output digest length in bytes (1 to 64)
 * @returns {Uint8Array} Hash digest
 */
export function blake2b(message, key = null, outlen = 64) {
  return new Blake2bContext(outlen, key).update(message).digest();
}
