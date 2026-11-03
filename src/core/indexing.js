/**
 * @fileoverview Argon2 2D Indexing and Reference Block Selection (RFC 9106 Section 3.4).
 *
 * Implements:
 * - Data-independent (Argon2i) address block generation via double-compression.
 * - Data-dependent (Argon2d) and hybrid (Argon2id) addressing modes.
 * - Reference lane selection.
 * - Non-uniform reference column mapping (indexAlpha / phi function).
 */

import { ARGON2_TYPES } from '../constants/index.js';
import { compressBlock } from './compression.js';

const MASK64 = 0xffffffffffffffffn;
const MASK32 = 0xffffffffn;

/**
 * Determines whether the current slice and pass should use data-independent addressing.
 *
 * RFC 9106 Section 3.4:
 * - Argon2d (0): data-dependent across all passes and slices.
 * - Argon2i (1): data-independent across all passes and slices.
 * - Argon2id (2): data-independent during pass 0, slices 0 & 1;
 *                 data-dependent for the remainder of pass 0 and all subsequent passes.
 *
 * @param {number} type - Algorithm type (0 = Argon2d, 1 = Argon2i, 2 = Argon2id)
 * @param {number} pass - Current iteration pass index (0-based)
 * @param {number} slice - Current synchronization slice index (0..3)
 * @returns {boolean} True if data-independent addressing should be used
 */
export function isDataIndependent(type, pass, slice) {
  if (type === ARGON2_TYPES.ARGON2I) {
    return true;
  }
  if (type === ARGON2_TYPES.ARGON2D) {
    return false;
  }
  // Argon2id hybrid mode
  return pass === 0 && slice < 2;
}

/**
 * Initializes the input block for data-independent address generation (Argon2i mode).
 *
 * RFC 9106 Section 3.4.1.1:
 * An input block of 128 64-bit words is constructed:
 * - r: pass number (v[0])
 * - l: lane number (v[1])
 * - s: slice number (v[2])
 * - m': total number of memory blocks (v[3])
 * - t: total number of passes (v[4])
 * - y: algorithm type (v[5])
 * - i: iteration counter within the slice (v[6], starts at 0, incremented before compression)
 * - Remaining words v[7..127] are zeroed.
 *
 * @param {BigUint64Array} inputBlock - 128-element 64-bit word array
 * @param {number} pass - Pass index
 * @param {number} lane - Lane index
 * @param {number} slice - Slice index
 * @param {number} blockCount - Total block count m'
 * @param {number} timeCost - Total passes t
 * @param {number} type - Algorithm type (0, 1, or 2)
 */
export function initAddressGenerator(inputBlock, pass, lane, slice, blockCount, timeCost, type) {
  inputBlock.fill(0n);
  inputBlock[0] = BigInt(pass);
  inputBlock[1] = BigInt(lane);
  inputBlock[2] = BigInt(slice);
  inputBlock[3] = BigInt(blockCount);
  inputBlock[4] = BigInt(timeCost);
  inputBlock[5] = BigInt(type);
  inputBlock[6] = 0n;
}

/**
 * Generates the next batch of 128 pseudo-random address words for Argon2i addressing.
 *
 * RFC 9106 Section 3.4.1.1:
 * Increments the counter at inputBlock[6] and performs double compression:
 * addressBlock = G(zeroBlock, G(zeroBlock, inputBlock))
 *
 * @param {BigUint64Array} addressBlock - 128-element destination word array
 * @param {BigUint64Array} inputBlock - 128-element input word array (counter incremented in-place)
 * @param {BigUint64Array} zeroBlock - 128-element all-zero block
 * @param {BigUint64Array} scratch - 128-element scratch buffer for round permutations
 */
export function nextAddresses(addressBlock, inputBlock, zeroBlock, scratch) {
  inputBlock[6] = (inputBlock[6] + 1n) & MASK64;
  compressBlock(zeroBlock, inputBlock, addressBlock, false, scratch);
  compressBlock(zeroBlock, addressBlock, addressBlock, false, scratch);
}

/**
 * Computes the size of the reference area W for block B[i][j].
 *
 * RFC 9106 Section 3.4.2:
 * Defines the set of blocks available for referencing without race conditions
 * during multi-lane parallel processing:
 * - If pass == 0:
 *   - If slice == 0: index - 1 (in the same lane)
 *   - If slice > 0:
 *     - Same lane: slice * sL + index - 1
 *     - Different lane: slice * sL - (index == 0 ? 1 : 0)
 * - If pass > 0:
 *   - Same lane: q - sL + index - 1
 *   - Different lane: q - sL - (index == 0 ? 1 : 0)
 *
 * @param {import('./memory.js').MemoryMatrix} matrix - Memory matrix instance
 * @param {number} pass - Pass index
 * @param {number} slice - Slice index (0..3)
 * @param {number} index - Index within current slice (0..sliceLength - 1)
 * @param {boolean} sameLane - Whether reference lane equals current lane
 * @returns {number} Reference area size W
 */
export function computeReferenceAreaSize(matrix, pass, slice, index, sameLane) {
  const q = matrix.columnCount;
  const sL = matrix.sliceLength;

  if (pass === 0) {
    if (slice === 0) {
      return index - 1;
    }
    if (sameLane) {
      return slice * sL + index - 1;
    }
    return slice * sL - (index === 0 ? 1 : 0);
  }

  // pass > 0
  if (sameLane) {
    return q - sL + index - 1;
  }
  return q - sL - (index === 0 ? 1 : 0);
}

/**
 * Maps pseudo-random value J1 to a column index in the memory matrix (phi / indexAlpha function).
 *
 * RFC 9106 Section 3.4.2:
 * To optimize cache-miss hardness and prevent side-channel leakage, Argon2 uses a
 * non-uniform mapping that places higher probability on recently computed blocks:
 *   x = (J1^2) / 2^32
 *   y = (W * x) / 2^32
 *   z_rel = W - 1 - y
 *
 * The absolute column index is then calculated relative to the start of the reference window:
 *   startCol = 0 (pass == 0) or ((slice + 1) % 4) * sL (pass > 0)
 *   refCol = (startCol + z_rel) % q
 *
 * @param {import('./memory.js').MemoryMatrix} matrix - Memory matrix instance
 * @param {number} pass - Pass index
 * @param {number} lane - Lane index
 * @param {number} slice - Slice index (0..3)
 * @param {number} index - Index within slice
 * @param {bigint|number} pseudoRand - 32-bit pseudo-random value J1
 * @param {boolean} sameLane - Whether reference lane equals current lane
 * @returns {number} Reference column index z
 */
export function indexAlpha(matrix, pass, lane, slice, index, pseudoRand, sameLane) {
  const q = matrix.columnCount;
  const sL = matrix.sliceLength;

  const refAreaSize = computeReferenceAreaSize(matrix, pass, slice, index, sameLane);

  const j1 = BigInt(pseudoRand) & MASK32;
  const x = (j1 * j1) >> 32n;
  const y = (BigInt(refAreaSize) * x) >> 32n;
  const zRel = BigInt(refAreaSize) - 1n - y;

  const startCol = (pass === 0) ? 0 : (((slice + 1) % 4) * sL);
  return (startCol + Number(zRel)) % q;
}

/**
 * Computes the 2D reference coordinates (refLane, refCol) for block B[lane][col].
 *
 * RFC 9106 Section 3.4.2:
 * - refLane:
 *   - In pass 0, slice 0: must reference current lane to avoid uninitialized memory.
 *   - Otherwise: J2 % parallelism.
 * - refCol:
 *   - Computed via non-uniform distribution indexAlpha based on J1 and sameLane.
 *
 * @param {import('./memory.js').MemoryMatrix} matrix - Memory matrix instance
 * @param {number} pass - Pass index
 * @param {number} lane - Current lane index
 * @param {number} slice - Current slice index (0..3)
 * @param {number} index - Index within current slice
 * @param {bigint|number} J1 - Lower 32 bits of pseudo-random qword
 * @param {bigint|number} J2 - Upper 32 bits of pseudo-random qword
 * @returns {{ refLane: number, refCol: number }} Reference coordinates
 */
export function getReferenceCoordinates(matrix, pass, lane, slice, index, J1, J2) {
  const p = matrix.lanes ?? matrix.laneCount;

  let refLane = lane;
  if (pass !== 0 || slice !== 0) {
    refLane = Number(BigInt(J2) & MASK32) % p;
  }

  const sameLane = (refLane === lane);
  const refCol = indexAlpha(matrix, pass, lane, slice, index, J1, sameLane);

  return { refLane, refCol };
}
