/**
 * @fileoverview Argon2 Finalization and Digest Extraction (RFC 9106 Section 3.5).
 *
 * Implements:
 * - Lane XOR folding across all lanes for the final column:
 *   C = B[0][q-1] ⊕ B[1][q-1] ⊕ ... ⊕ B[p-1][q-1]
 * - Final tag derivation using variable-length hash H'(C, tau):
 *   T = H'(C, tau)
 * - Safe memory zeroization of intermediate block C.
 */

import { BLOCK_BYTES, QWORDS_PER_BLOCK } from '../constants/index.js';
import { variableLengthHash } from '../crypto/variableHash.js';

/**
 * Extracts the final cryptographic tag from the filled memory matrix.
 *
 * RFC 9106 Section 3.5:
 * After t passes have completed, the last block of each lane is XORed:
 *   C = B[0][q-1] ⊕ B[1][q-1] ⊕ ... ⊕ B[p-1][q-1]
 * The requested tag T of length tau is derived by variable-length hashing H':
 *   T = H'(C, tau)
 *
 * @param {import('./memory.js').MemoryMatrix} matrix - Filled Argon2 memory matrix
 * @param {number} outlen - Requested tag length tau in bytes
 * @returns {Uint8Array} Derived cryptographic tag T of length outlen
 */
export function finalizeMemory(matrix, outlen) {
  if (typeof outlen !== 'number' || !Number.isInteger(outlen) || outlen < 1) {
    throw new RangeError('outlen must be a positive integer >= 1');
  }

  const p = matrix.lanes;
  const q = matrix.columnCount;
  const lastCol = q - 1;

  // Allocate 1024-byte buffer for block C
  const finalBlockBytes = new Uint8Array(BLOCK_BYTES);
  const finalBlockQwords = new BigUint64Array(finalBlockBytes.buffer);

  try {
    // Copy the last block of lane 0 into block C
    const lane0Last = matrix.getBlockQwords(0, lastCol);
    for (let w = 0; w < QWORDS_PER_BLOCK; w++) {
      finalBlockQwords[w] = lane0Last[w];
    }

    // XOR the last block of all remaining lanes 1..p-1
    for (let lane = 1; lane < p; lane++) {
      const laneLast = matrix.getBlockQwords(lane, lastCol);
      for (let w = 0; w < QWORDS_PER_BLOCK; w++) {
        finalBlockQwords[w] ^= laneLast[w];
      }
    }

    // Derive tag T = H'(C, tau)
    const tag = variableLengthHash(finalBlockBytes, outlen);
    return tag;
  } finally {
    // Zeroize intermediate block C from memory
    finalBlockBytes.fill(0);
  }
}
