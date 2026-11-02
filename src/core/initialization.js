/**
 * @fileoverview Argon2 Initial Hash H0 and First Blocks Initialization (RFC 9106 §3.3).
 *
 * Computes initial 64-byte digest H0 from protocol parameters, password, salt,
 * secret key, and associated data, then derives the first two blocks of each lane
 * (B[i][0] and B[i][1]) using variable-length hash function H'.
 */

import { Blake2bContext } from '../crypto/blake2b.js';
import { variableLengthHash } from '../crypto/variableHash.js';
import { normalizeBuffer, validateOptions } from '../utils/validation.js';
import { BLOCK_BYTES } from '../constants/index.js';

/**
 * Computes the initial 64-byte hash H0 according to RFC 9106 Section 3.3.
 *
 * H0 = BLAKE2b_64(
 *   LE32(p) || LE32(T) || LE32(m) || LE32(t) || LE32(v) || LE32(y) ||
 *   LE32(len(P)) || P ||
 *   LE32(len(S)) || S ||
 *   LE32(len(K)) || K ||
 *   LE32(len(X)) || X
 * )
 *
 * @param {Object} options
 * @param {number} options.parallelism - Lanes p
 * @param {number} options.hashLength - Output tag length T
 * @param {number} options.memoryCost - Memory cost m in KiB
 * @param {number} options.timeCost - Iterations t
 * @param {number} options.version - Algorithm version v (0x13)
 * @param {number} options.type - Algorithm type y (0: d, 1: i, 2: id)
 * @param {string|Uint8Array|Buffer} options.password - Plaintext password
 * @param {string|Uint8Array|Buffer} options.salt - Salt bytes
 * @param {string|Uint8Array|Buffer} [options.secret] - Optional secret key K
 * @param {string|Uint8Array|Buffer} [options.associatedData] - Optional associated data X
 * @returns {Uint8Array} 64-byte initial digest H0
 */
export function computeH0(options) {
  const opts = validateOptions(options);

  const pwdBytes = normalizeBuffer(options.password, 'password');
  const saltBytes = normalizeBuffer(options.salt, 'salt');
  const secretBytes = options.secret ? normalizeBuffer(options.secret, 'secret') : new Uint8Array(0);
  const adBytes = options.associatedData ? normalizeBuffer(options.associatedData, 'associatedData') : new Uint8Array(0);

  const ctx = new Blake2bContext(64);
  const u32Buf = new Uint8Array(4);
  const view = new DataView(u32Buf.buffer);

  const writeU32 = (val) => {
    view.setUint32(0, val, true);
    ctx.update(u32Buf);
  };

  // 1. Parameters
  writeU32(opts.parallelism);
  writeU32(opts.hashLength);
  writeU32(opts.memoryCost);
  writeU32(opts.timeCost);
  writeU32(opts.version);
  writeU32(opts.type);

  // 2. Password: LE32(len(P)) || P
  writeU32(pwdBytes.length);
  ctx.update(pwdBytes);

  // 3. Salt: LE32(len(S)) || S
  writeU32(saltBytes.length);
  ctx.update(saltBytes);

  // 4. Secret: LE32(len(K)) || K
  writeU32(secretBytes.length);
  if (secretBytes.length > 0) {
    ctx.update(secretBytes);
  }

  // 5. Associated Data: LE32(len(X)) || X
  writeU32(adBytes.length);
  if (adBytes.length > 0) {
    ctx.update(adBytes);
  }

  return ctx.digest();
}

/**
 * Initializes the first two columns of memory blocks for each lane using H0.
 *
 * For each lane i from 0 to p - 1:
 *   B[i][0] = H'(1024, H0 || LE32(0) || LE32(i))
 *   B[i][1] = H'(1024, H0 || LE32(1) || LE32(i))
 *
 * @param {import('./memory.js').MemoryMatrix} matrix - Allocated memory grid
 * @param {Uint8Array} h0 - 64-byte pre-hashing digest
 */
export function initializeFirstBlocks(matrix, h0) {
  if (!(h0 instanceof Uint8Array) || h0.length !== 64) {
    throw new TypeError('h0 must be a 64-byte Uint8Array');
  }

  const u32Col = new Uint8Array(4);
  const u32Lane = new Uint8Array(4);
  const viewCol = new DataView(u32Col.buffer);
  const viewLane = new DataView(u32Lane.buffer);

  for (let lane = 0; lane < matrix.lanes; lane++) {
    viewLane.setUint32(0, lane, true);

    // B[lane][0]
    viewCol.setUint32(0, 0, true);
    variableLengthHash([h0, u32Col, u32Lane], BLOCK_BYTES, matrix.getBlock(lane, 0));

    // B[lane][1]
    viewCol.setUint32(0, 1, true);
    variableLengthHash([h0, u32Col, u32Lane], BLOCK_BYTES, matrix.getBlock(lane, 1));
  }
}
