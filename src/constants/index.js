/**
 * @fileoverview Argon2id and Cryptographic Constants according to RFC 9106 & RFC 7693.
 *
 * Defines algorithm identifiers, version codes, block dimensions, default parameters,
 * and structural constraints for HashForge.
 */

/**
 * Argon2 Algorithm Identifiers (RFC 9106 Section 3.1)
 */
export const ARGON2_TYPES = Object.freeze({
  ARGON2D: 0,
  ARGON2I: 1,
  ARGON2ID: 2
});

/**
 * Algorithm Type Names as string identifiers (used in MCF / modular crypt format)
 */
export const ARGON2_TYPE_NAMES = Object.freeze({
  [ARGON2_TYPES.ARGON2D]: 'argon2d',
  [ARGON2_TYPES.ARGON2I]: 'argon2i',
  [ARGON2_TYPES.ARGON2ID]: 'argon2id'
});

/**
 * Argon2 Specification Versions (RFC 9106 Section 3.1)
 * Version 0x13 (19 decimal) is the standard defined in RFC 9106.
 */
export const ARGON2_VERSIONS = Object.freeze({
  V10: 0x10, // 16 decimal - legacy
  V13: 0x13  // 19 decimal - RFC 9106 standard
});

/**
 * Argon2 Memory Block Specifications (RFC 9106 Section 3.1)
 * Each memory block Q is 1024 bytes, organized as 128 64-bit words (little-endian).
 */
export const BLOCK_BYTES = 1024;
export const QWORDS_PER_BLOCK = 128; // 1024 / 8 bytes = 128 64-bit words
export const DWORDS_PER_BLOCK = 256; // 1024 / 4 bytes = 256 32-bit words

/**
 * Number of synchronization slices per pass (RFC 9106 Section 3.4)
 */
export const ARGON2_SYNC_POINTS = 4;

/**
 * RFC 9106 Parameter Constraints & Recommended Defaults
 */
export const LIMITS = Object.freeze({
  // Memory cost (m) in KiB: minimum is 8 * parallelism
  MIN_LANES: 1,
  MAX_LANES: 0x00ffffff, // 2^24 - 1
  MIN_TIME: 1,
  MAX_TIME: 0xffffffff, // 2^32 - 1
  MIN_HASH_LENGTH: 4,
  MAX_HASH_LENGTH: 0xffffffff, // 2^32 - 1
  MIN_SALT_LENGTH: 8,
  MAX_SALT_LENGTH: 0xffffffff, // 2^32 - 1
  MAX_PASSWORD_LENGTH: 0xffffffff, // 2^32 - 1
  MAX_SECRET_LENGTH: 0xffffffff,
  MAX_ASSOCIATED_DATA_LENGTH: 0xffffffff
});

/**
 * Recommended Default Parameters (RFC 9106 Section 7.4)
 * RFC 9106 recommends:
 * - FIRST RECOMMENDED option: m=21 (2 GiB), t=1, p=4
 * - SECOND RECOMMENDED option (memory-constrained): m=64 MiB (65536 KiB), t=3, p=4
 * For general Node.js backend password hashing defaults:
 * - memoryCost: 65536 KiB (64 MiB)
 * - timeCost: 3 iterations
 * - parallelism: 4 lanes
 * - hashLength: 32 bytes (256-bit tag)
 * - saltLength: 16 bytes (128 bits secure random)
 */
export const DEFAULTS = Object.freeze({
  type: ARGON2_TYPES.ARGON2ID,
  version: ARGON2_VERSIONS.V13,
  timeCost: 3,
  memoryCost: 65536, // 64 MiB
  parallelism: 4,
  hashLength: 32,
  saltLength: 16
});

/**
 * BLAKE2b Constants (RFC 7693)
 */
export const BLAKE2B = Object.freeze({
  BLOCK_BYTES: 128,
  MAX_DIGEST_BYTES: 64,
  MAX_KEY_BYTES: 64,
  ROUNDS: 12
});
