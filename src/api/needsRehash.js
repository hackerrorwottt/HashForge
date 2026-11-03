/**
 * @fileoverview High-Level needsRehash() API.
 *
 * Checks if an existing encoded hash was generated with parameters weaker than
 * current security policies or target configurations.
 */

import { DEFAULTS, ARGON2_TYPE_NAMES } from '../constants/index.js';
import { parseEncodedHash } from '../utils/encoding.js';

/**
 * Determines whether an existing hash needs to be recomputed due to policy upgrades.
 *
 * @param {string} encodedHash - Encoded MCF hash to inspect
 * @param {Object} [desiredOptions={}] - Target security parameters
 * @param {number} [desiredOptions.memoryCost=65536] - Desired memory cost in KiB
 * @param {number} [desiredOptions.timeCost=3] - Desired iterations
 * @param {number} [desiredOptions.parallelism=4] - Desired parallelism
 * @param {number} [desiredOptions.version=0x13] - Desired version
 * @param {number|string} [desiredOptions.type] - Desired algorithm type (e.g. ARGON2_TYPES.ARGON2ID or 'argon2id')
 * @returns {boolean} True if parameters differ or are weaker than target
 */
export function needsRehash(encodedHash, desiredOptions = {}) {
  let parsed;
  try {
    parsed = parseEncodedHash(encodedHash);
  } catch {
    return true; // Malformed hashes should be considered needing rehash
  }

  const targetMemory = desiredOptions.memoryCost ?? DEFAULTS.memoryCost;
  const targetTime = desiredOptions.timeCost ?? DEFAULTS.timeCost;
  const targetParallelism = desiredOptions.parallelism ?? DEFAULTS.parallelism;
  const targetVersion = desiredOptions.version ?? DEFAULTS.version;

  if (parsed.memoryCost < targetMemory) return true;
  if (parsed.timeCost < targetTime) return true;
  if (parsed.parallelism < targetParallelism) return true;
  if (parsed.version < targetVersion) return true;

  if (desiredOptions.type !== undefined) {
    let desiredTypeName = desiredOptions.type;
    if (typeof desiredOptions.type === 'number') {
      desiredTypeName = ARGON2_TYPE_NAMES[desiredOptions.type];
    }
    if (parsed.type !== desiredTypeName) return true;
  }

  return false;
}
