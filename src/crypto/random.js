/**
 * @fileoverview Cryptographically secure random byte generator.
 */

import crypto from 'node:crypto';

/**
 * Generates cryptographically secure random bytes using Node.js crypto subsystem.
 *
 * @param {number} length - Number of bytes to generate
 * @returns {Uint8Array} Secure random bytes
 */
export function generateRandomBytes(length) {
  if (typeof length !== 'number' || length <= 0 || !Number.isInteger(length)) {
    throw new RangeError('Byte length must be a positive integer');
  }
  return new Uint8Array(crypto.randomBytes(length));
}

