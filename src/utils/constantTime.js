/**
 * @fileoverview Constant-time comparison utilities to mitigate timing attacks.
 */

import crypto from 'node:crypto';

/**
 * Compares two buffers or Uint8Arrays in constant time.
 *
 * @param {Uint8Array|Buffer} a - First byte buffer
 * @param {Uint8Array|Buffer} b - Second byte buffer
 * @returns {boolean} True if both buffers have identical length and byte content
 */
export function timingSafeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
    throw new TypeError('Both arguments must be Uint8Array or Buffer instances');
  }

  // If lengths differ, we must still perform a constant-time operation to avoid leaking
  // length-equality timing prematurely, but timingSafeEqual requires equal length buffers.
  if (a.length !== b.length) {
    // Run a dummy comparison on equal slices to normalize timing characteristics
    const dummy = new Uint8Array(a.length);
    crypto.timingSafeEqual(a, dummy);
    return false;
  }

  return crypto.timingSafeEqual(a, b);
}
