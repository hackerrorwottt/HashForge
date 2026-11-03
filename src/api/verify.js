/**
 * @fileoverview High-Level verify() API for Password Verification.
 */

import { ARGON2_TYPES } from '../constants/index.js';
import { argon2Core } from '../core/argon2.js';
import { parseEncodedHash } from '../utils/encoding.js';
import { timingSafeEqual } from '../utils/constantTime.js';

const TYPE_NAME_TO_CODE = Object.freeze({
  argon2d: ARGON2_TYPES.ARGON2D,
  argon2i: ARGON2_TYPES.ARGON2I,
  argon2id: ARGON2_TYPES.ARGON2ID
});

/**
 * Verifies a candidate password against an Argon2 encoded hash in constant time.
 *
 * @param {string} encodedHash - Encoded Argon2 MCF hash string
 * @param {string|Uint8Array|Buffer} candidatePassword - Plaintext password to verify
 * @param {Object} [options={}] - Verification options (e.g. secret, associatedData)
 * @returns {Promise<boolean>} True if password matches, false otherwise
 */
export async function verify(encodedHash, candidatePassword, options = {}) {
  if (typeof encodedHash !== 'string') {
    throw new TypeError('Encoded hash must be a string');
  }

  if (candidatePassword === undefined || candidatePassword === null) {
    throw new TypeError('Candidate password is required');
  }

  let parsed;
  try {
    parsed = parseEncodedHash(encodedHash);
  } catch {
    return false;
  }

  const typeCode = TYPE_NAME_TO_CODE[parsed.type];
  if (typeCode === undefined) {
    return false;
  }

  try {
    const candidateTag = argon2Core({
      password: candidatePassword,
      salt: parsed.salt,
      memoryCost: parsed.memoryCost,
      timeCost: parsed.timeCost,
      parallelism: parsed.parallelism,
      hashLength: parsed.hash.length,
      type: typeCode,
      version: parsed.version,
      secret: options.secret,
      associatedData: options.associatedData
    });

    return timingSafeEqual(candidateTag, parsed.hash);
  } catch {
    return false;
  }
}
