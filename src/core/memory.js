/**
 * @fileoverview Argon2 Memory Block and Matrix Representation (RFC 9106 §3.1 & §3.4).
 *
 * Implements a contiguous 2D memory grid of 1024-byte blocks organized across
 * p lanes and q columns, partitioned into 4 synchronization slices. Exposes
 * both byte-level (Uint8Array) and 64-bit word (BigUint64Array) views.
 */

import { BLOCK_BYTES, QWORDS_PER_BLOCK, ARGON2_SYNC_POINTS } from '../constants/index.js';

/**
 * 2D Memory Matrix representing the Argon2 memory grid.
 */
export class MemoryMatrix {
  /**
   * @param {number} lanes - Degree of parallelism p (number of lanes)
   * @param {number} memoryCost - Memory cost m in KiB
   */
  constructor(lanes, memoryCost) {
    if (typeof lanes !== 'number' || !Number.isInteger(lanes) || lanes < 1) {
      throw new RangeError('lanes must be a positive integer >= 1');
    }
    if (typeof memoryCost !== 'number' || !Number.isInteger(memoryCost) || memoryCost < 8 * lanes) {
      throw new RangeError(`memoryCost must be an integer >= 8 * lanes (${8 * lanes} KiB)`);
    }

    this.lanes = lanes;
    this.memoryCost = memoryCost;

    // RFC 9106 Section 3.1: m' = 4 * p * floor(m / (4 * p))
    // Number of columns per lane: q = 4 * floor(m / (4 * p))
    this.columnCount = Math.floor(memoryCost / (ARGON2_SYNC_POINTS * lanes)) * ARGON2_SYNC_POINTS;
    this.blockCount = this.lanes * this.columnCount;
    this.totalBytes = this.blockCount * BLOCK_BYTES;

    // Each lane is partitioned into 4 slices
    this.sliceLength = this.columnCount / ARGON2_SYNC_POINTS;

    // Allocate single contiguous memory buffer for maximum cache locality
    this.buffer = new ArrayBuffer(this.totalBytes);
  }

  /**
   * Calculates the byte offset for block B[lane][column].
   *
   * @param {number} lane - Lane index [0, p - 1]
   * @param {number} column - Column index [0, q - 1]
   * @returns {number} Byte offset in buffer
   */
  getBlockOffset(lane, column) {
    if (lane < 0 || lane >= this.lanes) {
      throw new RangeError(`Invalid lane index ${lane}. Must be between 0 and ${this.lanes - 1}`);
    }
    if (column < 0 || column >= this.columnCount) {
      throw new RangeError(`Invalid column index ${column}. Must be between 0 and ${this.columnCount - 1}`);
    }
    return (lane * this.columnCount + column) * BLOCK_BYTES;
  }

  /**
   * Returns a 1024-byte Uint8Array view of block B[lane][column].
   *
   * @param {number} lane - Lane index
   * @param {number} column - Column index
   * @returns {Uint8Array} 1024-byte subarray
   */
  getBlock(lane, column) {
    const offset = this.getBlockOffset(lane, column);
    return new Uint8Array(this.buffer, offset, BLOCK_BYTES);
  }

  /**
   * Returns a 128-element BigUint64Array view of block B[lane][column].
   *
   * @param {number} lane - Lane index
   * @param {number} column - Column index
   * @returns {BigUint64Array} 128 64-bit words view
   */
  getBlockQwords(lane, column) {
    const offset = this.getBlockOffset(lane, column);
    return new BigUint64Array(this.buffer, offset, QWORDS_PER_BLOCK);
  }

  /**
   * Returns a 1024-byte view of a block by its absolute linear index.
   *
   * @param {number} index - Linear block index [0, blockCount - 1]
   * @returns {Uint8Array}
   */
  getBlockByIndex(index) {
    if (index < 0 || index >= this.blockCount) {
      throw new RangeError(`Invalid block index ${index}. Max: ${this.blockCount - 1}`);
    }
    return new Uint8Array(this.buffer, index * BLOCK_BYTES, BLOCK_BYTES);
  }

  /**
   * Returns a 128-element BigUint64Array view of a block by its absolute linear index.
   *
   * @param {number} index - Linear block index [0, blockCount - 1]
   * @returns {BigUint64Array}
   */
  getBlockQwordsByIndex(index) {
    if (index < 0 || index >= this.blockCount) {
      throw new RangeError(`Invalid block index ${index}. Max: ${this.blockCount - 1}`);
    }
    return new BigUint64Array(this.buffer, index * BLOCK_BYTES, QWORDS_PER_BLOCK);
  }

  /**
   * Securely zeroes the entire memory grid.
   */
  clear() {
    new Uint8Array(this.buffer).fill(0);
  }
}
