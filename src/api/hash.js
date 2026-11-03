/**
 * @fileoverview High-Level hash() API for Password Hashing.
 *
 * Produces an interoperable Modular Crypt Format (MCF) encoded string.
 */

import { DEFAULTS, ARGON2_TYPE_NAMES } from '../constants/index.js';
import { generateRandomBytes } from '../crypto/random.js';
import { argon2Core } from '../core/argon2.js';
import { formatEncodedHash } from '../utils/encoding.js';
import { normalizeBuffer } from '../utils/validation.js';

/**
 * Hashes a plaintext password using Argon2id (or specified variant).
 *
 * @param {string|Uint8Array|Buffer} password - Plaintext password
 * @param {Object} [options={}] - Custom parameters
 * @param {number} [options.timeCost=3] - Number of iterations (t)
 * @param {number} [options.memoryCost=65536] - Memory cost in KiB (m)
 * @param {number} [options.parallelism=4] - Degree of parallelism (p)
 * @param {number} [options.hashLength=32] - Tag length in bytes (tau)
 * @param {number} [options.saltLength=16] - Length of salt to generate in bytes
 * @param {Uint8Array|Buffer} [options.salt] - Custom salt (if provided, saltLength is ignored)
 * @param {number} [options.type=2] - Algorithm variant (0: d, 1: i, 2: id)
 * @param {number} [options.version=0x13] - Specification version (0x10 or 0x13)
 * @param {string|Uint8Array|Buffer} [options.secret] - Optional secret key K
 * @param {string|Uint8Array|Buffer} [options.associatedData] - Optional associated data X
 * @param {boolean} [options.raw=false] - If true, returns raw Uint8Array tag instead of MCF string
 * @returns {Promise<string|Uint8Array>} Encoded MCF string or raw tag bytes
 */
export async function hash(password, options = {}) {
  if (password === undefined || password === null) {
    throw new TypeError('Password is required');
  }

  const saltLength = options.saltLength ?? DEFAULTS.saltLength;
  const salt = options.salt ? normalizeBuffer(options.salt, 'salt') : generateRandomBytes(saltLength);

  const mergedOptions = {
    ...DEFAULTS,
    ...options,
    password,
    salt
  };

  const tag = argon2Core(mergedOptions);

  if (options.raw === true) {
    return tag;
  }

  const typeName = ARGON2_TYPE_NAMES[mergedOptions.type] || 'argon2id';

  return formatEncodedHash({
    type: typeName,
    version: mergedOptions.version,
    memoryCost: mergedOptions.memoryCost,
    timeCost: mergedOptions.timeCost,
    parallelism: mergedOptions.parallelism,
    salt,
    hash: tag
  });
}
