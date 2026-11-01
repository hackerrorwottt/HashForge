/**
 * @fileoverview Parameter validation and sanity checks for Argon2 operations.
 *
 * Enforces RFC 9106 parameter bounds and protects the runtime environment
 * from memory exhaustion attacks or invalid cryptographic configurations.
 */

import { LIMITS, DEFAULTS, ARGON2_TYPES } from '../constants/index.js';

/**
 * Validates and normalizes user-supplied Argon2 options.
 *
 * @param {Object} options - Hash options
 * @param {number} [options.timeCost] - Number of iterations (t)
 * @param {number} [options.memoryCost] - Memory size in KiB (m)
 * @param {number} [options.parallelism] - Number of parallel threads/lanes (p)
 * @param {number} [options.hashLength] - Output tag length in bytes (T)
 * @param {number} [options.saltLength] - Length of salt to generate in bytes (S)
 * @param {number} [options.type] - Argon2 type (0: d, 1: i, 2: id)
 * @param {number} [options.version] - Argon2 version (0x10 or 0x13)
 * @returns {Required<Object>} Normalized options
 */
export function validateOptions(options = {}) {
  const opts = { ...DEFAULTS, ...options };

  if (typeof opts.timeCost !== 'number' || !Number.isInteger(opts.timeCost) || opts.timeCost < LIMITS.MIN_TIME || opts.timeCost > LIMITS.MAX_TIME) {
    throw new RangeError(`timeCost must be an integer between ${LIMITS.MIN_TIME} and ${LIMITS.MAX_TIME}`);
  }

  if (typeof opts.parallelism !== 'number' || !Number.isInteger(opts.parallelism) || opts.parallelism < LIMITS.MIN_LANES || opts.parallelism > LIMITS.MAX_LANES) {
    throw new RangeError(`parallelism must be an integer between ${LIMITS.MIN_LANES} and ${LIMITS.MAX_LANES}`);
  }

  // RFC 9106 Section 3.1: m MUST be at least 8 * p
  const minMemory = 8 * opts.parallelism;
  if (typeof opts.memoryCost !== 'number' || !Number.isInteger(opts.memoryCost) || opts.memoryCost < minMemory) {
    throw new RangeError(`memoryCost must be an integer >= ${minMemory} KiB (8 * parallelism)`);
  }

  // Protect against allocating beyond safe Node.js buffer limits (e.g. max 2GB by default in V8)
  const MAX_SAFE_MEMORY_KIB = 2 * 1024 * 1024; // 2 GiB
  if (opts.memoryCost > MAX_SAFE_MEMORY_KIB) {
    throw new RangeError(`memoryCost exceeds maximum safe allocation limit of ${MAX_SAFE_MEMORY_KIB} KiB (2 GiB)`);
  }

  if (typeof opts.hashLength !== 'number' || !Number.isInteger(opts.hashLength) || opts.hashLength < LIMITS.MIN_HASH_LENGTH || opts.hashLength > LIMITS.MAX_HASH_LENGTH) {
    throw new RangeError(`hashLength must be an integer between ${LIMITS.MIN_HASH_LENGTH} and ${LIMITS.MAX_HASH_LENGTH}`);
  }

  if (typeof opts.saltLength !== 'number' || !Number.isInteger(opts.saltLength) || opts.saltLength < LIMITS.MIN_SALT_LENGTH || opts.saltLength > LIMITS.MAX_SALT_LENGTH) {
    throw new RangeError(`saltLength must be an integer between ${LIMITS.MIN_SALT_LENGTH} and ${LIMITS.MAX_SALT_LENGTH}`);
  }

  if (opts.type !== ARGON2_TYPES.ARGON2ID && opts.type !== ARGON2_TYPES.ARGON2I && opts.type !== ARGON2_TYPES.ARGON2D) {
    throw new TypeError(`Invalid Argon2 type: ${opts.type}. Expected ARGON2ID (2), ARGON2I (1), or ARGON2D (0)`);
  }

  return opts;
}

/**
 * Validates and converts input password/salt data into Uint8Array buffers.
 *
 * @param {string|Uint8Array|Buffer} input - Input value
 * @param {string} paramName - Parameter name for error messages
 * @returns {Uint8Array} Byte representation
 */
export function normalizeBuffer(input, paramName = 'Input') {
  if (typeof input === 'string') {
    return new TextEncoder().encode(input);
  }
  if (input instanceof Uint8Array) {
    return input;
  }
  if (Buffer.isBuffer(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new TypeError(`${paramName} must be a string, Buffer, or Uint8Array`);
}

