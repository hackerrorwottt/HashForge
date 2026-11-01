/**
 * @fileoverview Variable-Length Hash Function H' based on BLAKE2b (RFC 9106 Section 3.2).
 *
 * Implements the extendable output function (XOF) used by Argon2:
 * - If outlen <= 64: H'^T(A) = H^T(LE32(T) || A)
 * - If outlen > 64:  Iterative cascading expansion where:
 *     r = ceil(T / 32) - 2
 *     V_1 = H^(64)(LE32(T) || A)
 *     V_2 = H^(64)(V_1)
 *     ...
 *     V_r = H^(64)(V_{r-1})
 *     V_{r+1} = H^(T - 32 * r)(V_r)
 *     Output = W_1 || W_2 || ... || W_r || V_{r+1} (where W_i = first 32 bytes of V_i)
 */

import { Blake2bContext, blake2b } from './blake2b.js';
import { normalizeBuffer } from '../utils/validation.js';

/**
 * Computes variable-length hash H'(outlen, message) according to RFC 9106 Section 3.2.
 *
 * @param {string|Uint8Array|Buffer|Array<string|Uint8Array|Buffer>} message - Input message or array of chunks
 * @param {number} outlen - Desired output length in bytes (tau)
 * @param {Uint8Array} [destination=null] - Optional destination buffer to write into directly
 * @returns {Uint8Array} Output hash of length outlen
 */
export function variableLengthHash(message, outlen, destination = null) {
  if (typeof outlen !== 'number' || !Number.isInteger(outlen) || outlen < 1) {
    throw new RangeError('outlen must be a positive integer >= 1');
  }

  const out = destination || new Uint8Array(outlen);
  if (out.length < outlen) {
    throw new RangeError(`Destination buffer length (${out.length}) is smaller than requested outlen (${outlen})`);
  }

  // 4-byte little-endian prefix encoding the output length: LE32(outlen)
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, outlen, true);

  // Helper to feed message input (handling arrays of chunks or single values) into a context
  const feedInput = (ctx) => {
    ctx.update(prefix);
    if (Array.isArray(message)) {
      for (const part of message) {
        ctx.update(normalizeBuffer(part, 'Message chunk'));
      }
    } else {
      ctx.update(normalizeBuffer(message, 'Message'));
    }
  };

  // Case 1: outlen <= 64 bytes (Single direct BLAKE2b call)
  if (outlen <= 64) {
    const ctx = new Blake2bContext(outlen);
    feedInput(ctx);
    const digest = ctx.digest();
    out.set(digest, 0);
    return out;
  }

  // Case 2: outlen > 64 bytes (Cascading iterative expansion)
  const r = Math.ceil(outlen / 32) - 2;

  // Compute V_1 = H^(64)(LE32(T) || A)
  const ctx = new Blake2bContext(64);
  feedInput(ctx);
  let v = ctx.digest();

  // W_1 is the first 32 bytes of V_1
  out.set(v.subarray(0, 32), 0);

  // Compute subsequent 64-byte blocks: V_2 ... V_r
  for (let i = 2; i <= r; i++) {
    v = blake2b(v, null, 64);
    out.set(v.subarray(0, 32), (i - 1) * 32);
  }

  // Compute final block V_{r+1} with remaining length (T - 32 * r)
  const remaining = outlen - 32 * r;
  const vFinal = blake2b(v, null, remaining);
  out.set(vFinal, r * 32);

  return out;
}
