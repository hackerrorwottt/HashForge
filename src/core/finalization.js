/**
 * @fileoverview Argon2 Finalization and Digest Extraction (RFC 9106 Section 3.6).
 *
 * XORs the last block of each lane together to produce a single 1024-byte block C,
 * then computes the final tag T = H'(outlen, C).
 *
 * (To be implemented in Phase 7)
 */

/**
 * Extracts the final digest from the filled memory matrix.
 *
 * @param {MemoryMatrix} matrix
 * @param {number} outlen - Requested tag length
 * @returns {Uint8Array} Final tag T
 */
export function finalizeMemory(matrix, outlen) {
  throw new Error('finalizeMemory will be implemented in Phase 7');
}

