/**
 * @fileoverview Variable-Length Hash Function H' based on BLAKE2b (RFC 9106 Section 3.2).
 *
 * Argon2 uses H' to compute the initial 64-byte digest H0, to initialize memory blocks,
 * and to produce arbitrary-length output tags (T).
 *
 * (To be implemented in Phase 3)
 */

/**
 * Computes variable-length hash H'(T, message) according to RFC 9106 Section 3.2.
 *
 * @param {Uint8Array} message - Input bytes
 * @param {number} outlen - Desired output length in bytes (tau)
 * @returns {Uint8Array} Output tag of length `outlen`
 */
export function variableLengthHash(message, outlen) {
  throw new Error('Variable-length hash H\' will be completed in Phase 3');
}
