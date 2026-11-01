/**
 * @fileoverview Argon2 Memory Block and Matrix Representation (RFC 9106 Section 3.1 & 3.4).
 *
 * Each block is 1024 bytes (128 64-bit words). The memory matrix consists of p lanes,
 * each containing q = m' / p blocks, partitioned into 4 synchronization slices.
 *
 * (To be implemented in Phase 4)
 */

import { BLOCK_BYTES } from '../constants/index.js';

/**
 * Represents the 2D memory matrix of 1024-byte blocks for Argon2.
 */
export class MemoryMatrix {
  /**
   * @param {number} lanes - Parallelism p (number of lanes)
   * @param {number} memoryCost - Memory cost m in KiB
   */
  constructor(lanes, memoryCost) {
    this.lanes = lanes;
    // RFC 9106 Section 3.1: m' = 4 * p * floor(m / (4 * p))
    this.columnCount = Math.floor(memoryCost / (4 * lanes)) * 4;
    this.blockCount = this.lanes * this.columnCount;
    this.totalBytes = this.blockCount * BLOCK_BYTES;
  }
}

