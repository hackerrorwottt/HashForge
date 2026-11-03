/**
 * @fileoverview Test suite for Argon2 2D Indexing and Reference Selection (RFC 9106 Section 3.4).
 */

import { describe, it, expect } from 'vitest';
import {
  isDataIndependent,
  initAddressGenerator,
  nextAddresses,
  computeReferenceAreaSize,
  indexAlpha,
  getReferenceCoordinates
} from '../src/core/indexing.js';
import { MemoryMatrix } from '../src/core/memory.js';
import { computeH0, initializeFirstBlocks } from '../src/core/initialization.js';
import { compressBlock } from '../src/core/compression.js';
import { ARGON2_TYPES, ARGON2_VERSIONS } from '../src/constants/index.js';

describe('Argon2 Indexing and Reference Selection', () => {
  describe('isDataIndependent', () => {
    it('always returns false for Argon2d across all passes and slices', () => {
      for (let pass = 0; pass < 3; pass++) {
        for (let slice = 0; slice < 4; slice++) {
          expect(isDataIndependent(ARGON2_TYPES.ARGON2D, pass, slice)).toBe(false);
        }
      }
    });

    it('always returns true for Argon2i across all passes and slices', () => {
      for (let pass = 0; pass < 3; pass++) {
        for (let slice = 0; slice < 4; slice++) {
          expect(isDataIndependent(ARGON2_TYPES.ARGON2I, pass, slice)).toBe(true);
        }
      }
    });

    it('returns true only for pass 0 slices 0 and 1 for Argon2id', () => {
      expect(isDataIndependent(ARGON2_TYPES.ARGON2ID, 0, 0)).toBe(true);
      expect(isDataIndependent(ARGON2_TYPES.ARGON2ID, 0, 1)).toBe(true);
      expect(isDataIndependent(ARGON2_TYPES.ARGON2ID, 0, 2)).toBe(false);
      expect(isDataIndependent(ARGON2_TYPES.ARGON2ID, 0, 3)).toBe(false);

      for (let pass = 1; pass < 3; pass++) {
        for (let slice = 0; slice < 4; slice++) {
          expect(isDataIndependent(ARGON2_TYPES.ARGON2ID, pass, slice)).toBe(false);
        }
      }
    });
  });

  describe('computeReferenceAreaSize', () => {
    const matrix = new MemoryMatrix(4, 32); // q = 8 columns, sL = 2

    it('computes correct reference area in pass 0, slice 0', () => {
      // In slice 0, blocks 0 and 1 are pre-initialized, index starts at 2
      expect(computeReferenceAreaSize(matrix, 0, 0, 2, true)).toBe(1);
      expect(computeReferenceAreaSize(matrix, 0, 0, 3, true)).toBe(2);
    });

    it('computes correct reference area in pass 0, slice > 0', () => {
      // slice 1: slice * sL = 2
      // index 0: sameLane -> 2 + 0 - 1 = 1; differentLane -> 2 - 1 = 1
      expect(computeReferenceAreaSize(matrix, 0, 1, 0, true)).toBe(1);
      expect(computeReferenceAreaSize(matrix, 0, 1, 0, false)).toBe(1);

      // index 1: sameLane -> 2 + 1 - 1 = 2; differentLane -> 2 - 0 = 2
      expect(computeReferenceAreaSize(matrix, 0, 1, 1, true)).toBe(2);
      expect(computeReferenceAreaSize(matrix, 0, 1, 1, false)).toBe(2);
    });

    it('computes correct reference area in pass > 0', () => {
      // q - sL = 8 - 2 = 6
      expect(computeReferenceAreaSize(matrix, 1, 0, 0, true)).toBe(5);
      expect(computeReferenceAreaSize(matrix, 1, 0, 0, false)).toBe(5);
      expect(computeReferenceAreaSize(matrix, 1, 0, 1, true)).toBe(6);
      expect(computeReferenceAreaSize(matrix, 1, 0, 1, false)).toBe(6);
    });
  });

  describe('Address Generator (Argon2i mode)', () => {
    it('initializes and produces 128 pseudo-random address words per batch', () => {
      const inputBlock = new BigUint64Array(128);
      const addressBlock = new BigUint64Array(128);
      const zeroBlock = new BigUint64Array(128);
      const scratch = new BigUint64Array(128);

      initAddressGenerator(inputBlock, 0, 1, 2, 32, 3, ARGON2_TYPES.ARGON2ID);
      expect(inputBlock[0]).toBe(0n);
      expect(inputBlock[1]).toBe(1n);
      expect(inputBlock[2]).toBe(2n);
      expect(inputBlock[3]).toBe(32n);
      expect(inputBlock[4]).toBe(3n);
      expect(inputBlock[5]).toBe(2n);
      expect(inputBlock[6]).toBe(0n);

      nextAddresses(addressBlock, inputBlock, zeroBlock, scratch);
      expect(inputBlock[6]).toBe(1n);

      // Verify that addressBlock is populated with non-zero entropy
      const nonZeroWords = Array.from(addressBlock).filter(w => w !== 0n);
      expect(nonZeroWords.length).toBe(128);

      // Next batch increments counter and produces different addresses
      const prevFirstWord = addressBlock[0];
      nextAddresses(addressBlock, inputBlock, zeroBlock, scratch);
      expect(inputBlock[6]).toBe(2n);
      expect(addressBlock[0]).not.toBe(prevFirstWord);
    });
  });

  describe('indexAlpha & getReferenceCoordinates', () => {
    const matrix = new MemoryMatrix(4, 32); // 4 lanes, 8 columns

    it('always selects the same lane during pass 0 slice 0', () => {
      for (let lane = 0; lane < 4; lane++) {
        const { refLane, refCol } = getReferenceCoordinates(matrix, 0, lane, 0, 2, 12345n, 99999n);
        expect(refLane).toBe(lane);
        expect(refCol).toBeGreaterThanOrEqual(0);
        expect(refCol).toBeLessThan(matrix.columnCount);
      }
    });

    it('can select different lanes when pass > 0 or slice > 0', () => {
      const { refLane } = getReferenceCoordinates(matrix, 0, 0, 1, 0, 100n, 3n);
      expect(refLane).toBe(3); // 3 % 4 = 3
    });

    it('always keeps column index within matrix bounds across random pseudo-random inputs', () => {
      for (let pass = 0; pass < 2; pass++) {
        for (let slice = 0; slice < 4; slice++) {
          for (let index = 0; index < matrix.sliceLength; index++) {
            if (pass === 0 && slice === 0 && index < 2) continue;

            const J1 = Math.floor(Math.random() * 0xffffffff);
            const J2 = Math.floor(Math.random() * 0xffffffff);
            const { refLane, refCol } = getReferenceCoordinates(matrix, pass, 1, slice, index, J1, J2);

            expect(refLane).toBeGreaterThanOrEqual(0);
            expect(refLane).toBeLessThan(matrix.laneCount);
            expect(refCol).toBeGreaterThanOrEqual(0);
            expect(refCol).toBeLessThan(matrix.columnCount);
          }
        }
      }
    });
  });

  describe('RFC 9106 Section 5.3 Multi-Pass Intermediate Vectors', () => {
    it('matches exact intermediate Block 0000 qwords across passes 0, 1, and 2', () => {
      const MASK32 = 0xffffffffn;

      const params = {
        parallelism: 4,
        hashLength: 32,
        memoryCost: 32,
        timeCost: 3,
        version: ARGON2_VERSIONS.V13,
        type: ARGON2_TYPES.ARGON2ID,
        password: new Uint8Array(32).fill(1),
        salt: new Uint8Array(16).fill(2),
        secret: new Uint8Array(8).fill(3),
        associatedData: new Uint8Array(12).fill(4)
      };

      const h0 = computeH0(params);
      const matrix = new MemoryMatrix(params.parallelism, params.memoryCost);
      initializeFirstBlocks(matrix, h0);

      const zeroBlock = new BigUint64Array(128);
      const inputBlock = new BigUint64Array(128);
      const addressBlock = new BigUint64Array(128);
      const scratch = new BigUint64Array(128);

      const q = matrix.columnCount;
      const sL = matrix.sliceLength;

      const intermediateB0_0 = [];

      for (let pass = 0; pass < params.timeCost; pass++) {
        for (let slice = 0; slice < 4; slice++) {
          for (let lane = 0; lane < params.parallelism; lane++) {
            const dataIndep = isDataIndependent(params.type, pass, slice);
            if (dataIndep) {
              initAddressGenerator(inputBlock, pass, lane, slice, matrix.blockCount, params.timeCost, params.type);
            }

            let addrIndex = 0;
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

              const { refLane, refCol } = getReferenceCoordinates(matrix, pass, lane, slice, index, J1, J2);
              const refBlock = matrix.getBlockQwords(refLane, refCol);
              const destBlock = matrix.getBlockQwords(lane, col);

              compressBlock(prevBlock, refBlock, destBlock, pass > 0, scratch);
            }
          }
        }

        const b0_0 = matrix.getBlockQwords(0, 0);
        intermediateB0_0.push([b0_0[0], b0_0[1]]);
      }

      // Expected values from RFC 9106 Section 5.3:
      // After pass 0: Block 0000 [ 0]: 6b2e09f10671bd43, [ 1]: f69f5c27918a21be
      expect(intermediateB0_0[0][0]).toBe(0x6b2e09f10671bd43n);
      expect(intermediateB0_0[0][1]).toBe(0xf69f5c27918a21ben);

      // After pass 1: Block 0000 [ 0]: 3653ec9d01583df9, [ 1]: 69ef53a72d1e1fd3
      expect(intermediateB0_0[1][0]).toBe(0x3653ec9d01583df9n);
      expect(intermediateB0_0[1][1]).toBe(0x69ef53a72d1e1fd3n);

      // After pass 2: Block 0000 [ 0]: 942363968ce597a4, [ 1]: a22448c0bdad5760
      expect(intermediateB0_0[2][0]).toBe(0x942363968ce597a4n);
      expect(intermediateB0_0[2][1]).toBe(0xa22448c0bdad5760n);
    });
  });
});

