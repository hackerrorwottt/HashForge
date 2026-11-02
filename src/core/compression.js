/**
 * @fileoverview Argon2 Core Compression Function G and BlaMka Permutation (RFC 9106 §3.5 & §3.6).
 *
 * Implements:
 * - fBlaMka: 64-bit non-linear integer arithmetic (multiplication + addition modulo 2^64)
 * - GB: Quarter-round mixing function using fBlaMka and 64-bit rotations (32, 24, 16, 63)
 * - roundP: 16-word permutation P applied column-wise and diagonal-wise
 * - compressBlock: 1024-byte compression function G(X, Y) transforming 8 rows and 8 columns
 */

import { BLOCK_BYTES, QWORDS_PER_BLOCK } from '../constants/index.js';
import { rotr64 } from '../crypto/blake2b.js';

/**
 * 64-bit unsigned bitmask (2^64 - 1).
 */
const MASK64 = 0xffffffffffffffffn;

/**
 * 32-bit unsigned bitmask (2^32 - 1).
 */
const MASK32 = 0xffffffffn;

/**
 * BlaMka 64-bit non-linear modular arithmetic (RFC 9106 Section 3.6).
 *
 * Computes:
 *   fBlaMka(x, y) = (x + y + 2 * trunc32(x) * trunc32(y)) mod 2^64
 *
 * @param {bigint} x - First 64-bit unsigned integer
 * @param {bigint} y - Second 64-bit unsigned integer
 * @returns {bigint} 64-bit result modulo 2^64
 */
export function fBlaMka(x, y) {
  const m = 2n * (x & MASK32) * (y & MASK32);
  return (x + y + m) & MASK64;
}

/**
 * Argon2 Quarter-Round Function GB (RFC 9106 Section 3.6).
 *
 * Modifies four 64-bit words in-place within vector v at indices a, b, c, d
 * using fBlaMka arithmetic, bitwise XOR, and 64-bit rotations (32, 24, 16, 63).
 *
 * @param {BigUint64Array} v - State vector containing 64-bit words
 * @param {number} a - First index
 * @param {number} b - Second index
 * @param {number} c - Third index
 * @param {number} d - Fourth index
 */
export function GB(v, a, b, c, d) {
  v[a] = fBlaMka(v[a], v[b]);
  v[d] = rotr64(v[d] ^ v[a], 32n);
  v[c] = fBlaMka(v[c], v[d]);
  v[b] = rotr64(v[b] ^ v[c], 24n);
  v[a] = fBlaMka(v[a], v[b]);
  v[d] = rotr64(v[d] ^ v[a], 16n);
  v[c] = fBlaMka(v[c], v[d]);
  v[b] = rotr64(v[b] ^ v[c], 63n);
}

/**
 * Permutation P on 16 64-bit words (RFC 9106 Section 3.6).
 *
 * Executes 4 column-wise GB rounds followed by 4 diagonal GB rounds.
 *
 * @param {BigUint64Array} v - State vector
 * @param {number} i0 .. i15 - Word indices
 */
export function roundP(v, i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15) {
  // Column-wise step
  GB(v, i0, i4, i8, i12);
  GB(v, i1, i5, i9, i13);
  GB(v, i2, i6, i10, i14);
  GB(v, i3, i7, i11, i15);

  // Diagonal-wise step
  GB(v, i0, i5, i10, i15);
  GB(v, i1, i6, i11, i12);
  GB(v, i2, i7, i8, i13);
  GB(v, i3, i4, i9, i14);
}

/**
 * Converts a Uint8Array or BigUint64Array block into a BigUint64Array view.
 *
 * @private
 * @param {Uint8Array|BigUint64Array} block
 * @returns {BigUint64Array}
 */
function toQwords(block) {
  if (block instanceof BigUint64Array) {
    if (block.length !== QWORDS_PER_BLOCK) {
      throw new RangeError(`BigUint64Array must have length ${QWORDS_PER_BLOCK}`);
    }
    return block;
  }
  if (block instanceof Uint8Array) {
    if (block.length !== BLOCK_BYTES) {
      throw new RangeError(`Uint8Array must have length ${BLOCK_BYTES}`);
    }
    return new BigUint64Array(block.buffer, block.byteOffset, QWORDS_PER_BLOCK);
  }
  throw new TypeError('Block must be an instance of BigUint64Array or Uint8Array');
}

/**
 * Argon2 1024-byte Block Compression Function G (RFC 9106 Section 3.5).
 *
 * Compresses two 1024-byte input blocks X and Y into output block Z.
 * - In pass 0: Z = G(X, Y) = (X ^ Y) ^ P(X ^ Y)
 * - In pass > 0: Z = Z_prev ^ G(X, Y)
 *
 * @param {Uint8Array|BigUint64Array} blockX - Previous block
 * @param {Uint8Array|BigUint64Array} blockY - Reference block
 * @param {Uint8Array|BigUint64Array} destination - Destination block
 * @param {boolean} [xorWithDest=false] - True if result should be XORed with destination (passes > 0)
 * @param {BigUint64Array} [scratchR=null] - Optional pre-allocated 128-word scratch buffer
 */
export function compressBlock(blockX, blockY, destination, xorWithDest = false, scratchR = null) {
  const X = toQwords(blockX);
  const Y = toQwords(blockY);
  const dest = toQwords(destination);

  const R = scratchR || new BigUint64Array(QWORDS_PER_BLOCK);

  // Initial XOR: R = X ^ Y
  for (let i = 0; i < QWORDS_PER_BLOCK; i++) {
    R[i] = X[i] ^ Y[i];
  }

  // Row-wise permutations across eight 128-byte rows
  for (let i = 0; i < 8; i++) {
    const row = i * 16;
    roundP(
      R,
      row, row + 1, row + 2, row + 3,
      row + 4, row + 5, row + 6, row + 7,
      row + 8, row + 9, row + 10, row + 11,
      row + 12, row + 13, row + 14, row + 15
    );
  }

  // Column-wise permutations across eight 128-byte columns
  for (let i = 0; i < 8; i++) {
    const col = 2 * i;
    roundP(
      R,
      col, col + 1,
      col + 16, col + 17,
      col + 32, col + 33,
      col + 48, col + 49,
      col + 64, col + 65,
      col + 80, col + 81,
      col + 96, col + 97,
      col + 112, col + 113
    );
  }

  // Final XOR mixing: destination = (X ^ Y) ^ R_permuted (or XORed into destination)
  if (xorWithDest) {
    for (let i = 0; i < QWORDS_PER_BLOCK; i++) {
      dest[i] ^= X[i] ^ Y[i] ^ R[i];
    }
  } else {
    for (let i = 0; i < QWORDS_PER_BLOCK; i++) {
      dest[i] = X[i] ^ Y[i] ^ R[i];
    }
  }
}
