/**
 * @fileoverview Main Argon2 Core Execution Engine (RFC 9106).
 *
 * Coordinates:
 * - Parameter normalization and input validation.
 * - Initial 64-byte digest derivation (H0).
 * - Allocation of contiguous 2D memory block matrix.
 * - Multi-pass multi-slice block processing using hybrid addressing and function G.
 * - Final tag extraction with lane XOR folding (C = ⊕ B[i][q-1]) and H'.
 * - Guaranteed memory matrix zeroization on completion or error.
 */

import { ARGON2_SYNC_POINTS, LIMITS } from '../constants/index.js';
import { validateOptions, normalizeBuffer } from '../utils/validation.js';
import { MemoryMatrix } from './memory.js';
import { computeH0, initializeFirstBlocks } from './initialization.js';
import { compressBlock } from './compression.js';
import {
  isDataIndependent,
  initAddressGenerator,
  nextAddresses,
  getReferenceCoordinates
} from './indexing.js';
import { finalizeMemory } from './finalization.js';

const MASK32 = 0xffffffffn;

/**
 * Executes the full Argon2 memory-hard hashing algorithm.
 *
 * @param {Object} options - Configuration and input parameters
 * @param {string|Uint8Array|Buffer} options.password - Password to hash
 * @param {string|Uint8Array|Buffer} options.salt - Salt bytes (min 8 bytes)
 * @param {number} [options.timeCost=3] - Number of passes t
 * @param {number} [options.memoryCost=65536] - Memory size in KiB m
 * @param {number} [options.parallelism=4] - Degree of parallelism p
 * @param {number} [options.hashLength=32] - Desired tag length in bytes tau
 * @param {number} [options.type=2] - Algorithm type (0: d, 1: i, 2: id)
 * @param {number} [options.version=0x13] - Specification version (0x10 or 0x13)
 * @param {string|Uint8Array|Buffer} [options.secret] - Optional secret key K
 * @param {string|Uint8Array|Buffer} [options.associatedData] - Optional associated data X
 * @returns {Uint8Array} Derived cryptographic tag of length hashLength
 */
export function argon2Core(options) {
  if (!options || typeof options !== 'object') {
    throw new TypeError('Argon2 options must be an object');
  }

  if (options.password === undefined || options.password === null) {
    throw new TypeError('Password is required');
  }

  if (options.salt === undefined || options.salt === null) {
    throw new TypeError('Salt is required');
  }

  const opts = validateOptions(options);
  const password = normalizeBuffer(options.password, 'password');
  const salt = normalizeBuffer(options.salt, 'salt');

  if (salt.length < LIMITS.MIN_SALT_LENGTH) {
    throw new RangeError(`Salt must be at least ${LIMITS.MIN_SALT_LENGTH} bytes long (received ${salt.length})`);
  }

  const secret = options.secret ? normalizeBuffer(options.secret, 'secret') : new Uint8Array(0);
  const associatedData = options.associatedData ? normalizeBuffer(options.associatedData, 'associatedData') : new Uint8Array(0);

  // RFC 9106 Section 3.1: Compute 64-byte initial digest H0
  const h0 = computeH0({
    parallelism: opts.parallelism,
    hashLength: opts.hashLength,
    memoryCost: opts.memoryCost,
    timeCost: opts.timeCost,
    version: opts.version,
    type: opts.type,
    password,
    salt,
    secret,
    associatedData
  });

  // RFC 9106 Section 3.1: Allocate memory matrix of m' blocks
  const matrix = new MemoryMatrix(opts.parallelism, opts.memoryCost);

  try {
    // RFC 9106 Section 3.3: Initialize first two blocks for each lane B[i][0] and B[i][1]
    initializeFirstBlocks(matrix, h0);

    // Pre-allocate working blocks to eliminate allocations inside the core loop
    const zeroBlock = new BigUint64Array(128);
    const inputBlock = new BigUint64Array(128);
    const addressBlock = new BigUint64Array(128);
    const scratch = new BigUint64Array(128);

    const q = matrix.columnCount;
    const sL = matrix.sliceLength;

    // RFC 9106 Section 3.4: Outer loop over t passes
    for (let pass = 0; pass < opts.timeCost; pass++) {
      // 4 synchronization slices per pass
      for (let slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
        // Parallel lanes
        for (let lane = 0; lane < opts.parallelism; lane++) {
          const dataIndep = isDataIndependent(opts.type, pass, slice);
          if (dataIndep) {
            initAddressGenerator(inputBlock, pass, lane, slice, matrix.blockCount, opts.timeCost, opts.type);
          }

          let addrIndex = 0;
          // In pass 0 slice 0, first two blocks (0 and 1) are pre-initialized
          const startIndex = (pass === 0 && slice === 0) ? 2 : 0;

          for (let index = startIndex; index < sL; index++) {
            const col = slice * sL + index;
            const prevCol = (col === 0) ? q - 1 : col - 1;
            const prevBlock = matrix.getBlockQwords(lane, prevCol);

            let J1, J2;
            if (dataIndep) {
              if (addrIndex % 128 === 0) {
                nextAddresses(addressBlock, inputBlock, zeroBlock, scratch);
              }
              const addrWord = addressBlock[addrIndex % 128];
              J1 = Number(addrWord & MASK32);
              J2 = Number((addrWord >> 32n) & MASK32);
              addrIndex++;
            } else {
              J1 = Number(prevBlock[0] & MASK32);
              J2 = Number((prevBlock[0] >> 32n) & MASK32);
            }

            // Compute reference coordinates (refLane, refCol)
            const { refLane, refCol } = getReferenceCoordinates(matrix, pass, lane, slice, index, J1, J2);
            const refBlock = matrix.getBlockQwords(refLane, refCol);
            const destBlock = matrix.getBlockQwords(lane, col);

            // Compress block: overwrite on pass 0, XOR on passes > 0
            compressBlock(prevBlock, refBlock, destBlock, pass > 0, scratch);
          }
        }
      }
    }

    // RFC 9106 Section 3.5: Finalization
    return finalizeMemory(matrix, opts.hashLength);
  } finally {
    // RFC 9106 & Defensive Cryptography: Zeroize memory matrix
    matrix.clear();
  }
}
