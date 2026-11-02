import { describe, it, expect } from 'vitest';
import { MemoryMatrix } from '../src/core/memory.js';
import { computeH0, initializeFirstBlocks } from '../src/core/initialization.js';
import { ARGON2_TYPES, ARGON2_VERSIONS } from '../src/constants/index.js';

describe('Phase 4: Memory Block Matrix & H0 Initialization', () => {
  describe('MemoryMatrix Geometry & Zero-Copy Views', () => {
    it('computes correct column and block dimensions according to RFC 9106', () => {
      // p = 4, m = 32 KiB -> q = 4 * floor(32 / 16) = 8 columns per lane
      const matrix = new MemoryMatrix(4, 32);
      expect(matrix.lanes).toBe(4);
      expect(matrix.columnCount).toBe(8);
      expect(matrix.blockCount).toBe(32);
      expect(matrix.sliceLength).toBe(2);
      expect(matrix.totalBytes).toBe(32 * 1024);
    });

    it('rounds down memoryCost to nearest multiple of 4 * parallelism', () => {
      // p = 4: 4 * p = 16. If m = 35 KiB -> q = 4 * floor(35 / 16) = 8
      const matrix = new MemoryMatrix(4, 35);
      expect(matrix.columnCount).toBe(8);
      expect(matrix.blockCount).toBe(32);
    });

    it('provides zero-copy BigUint64Array and Uint8Array views over the same block', () => {
      const matrix = new MemoryMatrix(2, 16);
      const qwords = matrix.getBlockQwords(1, 1);
      const bytes = matrix.getBlock(1, 1);

      // Write a known 64-bit word
      qwords[0] = 0x0123456789abcdefn;

      // In little-endian, byte[0] is 0xef, byte[7] is 0x01
      expect(bytes[0]).toBe(0xef);
      expect(bytes[1]).toBe(0xcd);
      expect(bytes[2]).toBe(0xab);
      expect(bytes[3]).toBe(0x89);
      expect(bytes[4]).toBe(0x67);
      expect(bytes[5]).toBe(0x45);
      expect(bytes[6]).toBe(0x23);
      expect(bytes[7]).toBe(0x01);
    });

    it('clears memory buffer completely on clear()', () => {
      const matrix = new MemoryMatrix(2, 16);
      const qwords = matrix.getBlockQwords(0, 0);
      qwords[0] = 0xffffffffffffffffn;

      matrix.clear();
      expect(qwords[0]).toBe(0n);
      const bytes = matrix.getBlock(0, 0);
      expect(bytes.every((b) => b === 0)).toBe(true);
    });

    it('rejects out-of-bounds lane and column indices', () => {
      const matrix = new MemoryMatrix(2, 16);
      expect(() => matrix.getBlock(2, 0)).toThrow(RangeError);
      expect(() => matrix.getBlock(0, 8)).toThrow(RangeError);
      expect(() => matrix.getBlock(-1, 0)).toThrow(RangeError);
    });
  });

  describe('RFC 9106 Section 5 Official Test Vectors for H0', () => {
    const commonParams = {
      parallelism: 4,
      hashLength: 32,
      memoryCost: 32,
      timeCost: 3,
      version: ARGON2_VERSIONS.V13,
      password: new Uint8Array(32).fill(1),
      salt: new Uint8Array(16).fill(2),
      secret: new Uint8Array(8).fill(3),
      associatedData: new Uint8Array(12).fill(4)
    };

    it('matches official RFC 9106 Section 5.1 H0 vector for Argon2d', () => {
      const h0 = computeH0({ ...commonParams, type: ARGON2_TYPES.ARGON2D });
      const expected = 'b8819791a0359660bb7709c85fa48f04d5d82c05c5f215ccdb885491717cf757082c28b951be381410b5fc2eb7274033b9fdc7ae672bcaac5d179097a4af3109';
      expect(Buffer.from(h0).toString('hex')).toBe(expected);
    });

    it('matches official RFC 9106 Section 5.2 H0 vector for Argon2i', () => {
      const h0 = computeH0({ ...commonParams, type: ARGON2_TYPES.ARGON2I });
      const expected = 'c46065815276a0b3e731731c902f1fd80cf776907fbb7b6a5ca72e7b56011feeca446c86dd75b9469a5e6879dec4b72d0863fb939b982e5f397cc7d164fddaa9';
      expect(Buffer.from(h0).toString('hex')).toBe(expected);
    });

    it('matches official RFC 9106 Section 5.3 H0 vector for Argon2id', () => {
      const h0 = computeH0({ ...commonParams, type: ARGON2_TYPES.ARGON2ID });
      const expected = '2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b8546a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997';
      expect(Buffer.from(h0).toString('hex')).toBe(expected);
    });
  });

  describe('First Blocks B[i][0] and B[i][1] Initialization', () => {
    it('matches official RFC 9106 Section 5.3 Argon2id Block 0000 qwords', () => {
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

      // Verify B[0][0] qwords match RFC 9106 Section 5.3
      const b0_0_qwords = matrix.getBlockQwords(0, 0);
      expect(b0_0_qwords[0]).toBe(0x6b2e09f10671bd43n);
      expect(b0_0_qwords[1]).toBe(0xf69f5c27918a21ben);
      expect(b0_0_qwords[2]).toBe(0xdea7810ea41290e1n);
      expect(b0_0_qwords[3]).toBe(0x6787f7171870f893n);
    });

    it('matches official RFC 9106 Section 5.1 Argon2d Block 0000 qwords', () => {
      const params = {
        parallelism: 4,
        hashLength: 32,
        memoryCost: 32,
        timeCost: 3,
        version: ARGON2_VERSIONS.V13,
        type: ARGON2_TYPES.ARGON2D,
        password: new Uint8Array(32).fill(1),
        salt: new Uint8Array(16).fill(2),
        secret: new Uint8Array(8).fill(3),
        associatedData: new Uint8Array(12).fill(4)
      };

      const h0 = computeH0(params);
      const matrix = new MemoryMatrix(params.parallelism, params.memoryCost);
      initializeFirstBlocks(matrix, h0);

      // Verify B[0][0] qwords match RFC 9106 Section 5.1
      const b0_0_qwords = matrix.getBlockQwords(0, 0);
      expect(b0_0_qwords[0]).toBe(0xdb2fea6b2c6f5c8an);
      expect(b0_0_qwords[1]).toBe(0x719413be00f82634n);
      expect(b0_0_qwords[2]).toBe(0xa1e3f6dd42aa25ccn);
      expect(b0_0_qwords[3]).toBe(0x3ea8efd4d55ac0d1n);
    });

    it('initializes non-zero, distinct blocks across all lanes', () => {
      const params = {
        parallelism: 4,
        hashLength: 32,
        memoryCost: 32,
        timeCost: 3,
        version: ARGON2_VERSIONS.V13,
        type: ARGON2_TYPES.ARGON2ID,
        password: 'securePassword',
        salt: new Uint8Array(16).fill(9)
      };

      const h0 = computeH0(params);
      const matrix = new MemoryMatrix(params.parallelism, params.memoryCost);
      initializeFirstBlocks(matrix, h0);

      const seen = new Set();
      for (let lane = 0; lane < matrix.lanes; lane++) {
        for (const col of [0, 1]) {
          const hex = Buffer.from(matrix.getBlock(lane, col)).toString('hex');
          expect(hex).not.toBe('00'.repeat(1024));
          expect(seen.has(hex)).toBe(false);
          seen.add(hex);
        }
      }
      expect(seen.size).toBe(8); // 4 lanes * 2 blocks = 8 distinct blocks
    });
  });
});
