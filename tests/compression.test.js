import { describe, it, expect } from 'vitest';
import {
  fBlaMka,
  GB,
  roundP,
  compressBlock
} from '../src/core/compression.js';
import { BLOCK_BYTES, QWORDS_PER_BLOCK } from '../src/constants/index.js';

describe('Phase 5: Compression Function G & BlaMka Arithmetic', () => {
  describe('fBlaMka 64-Bit Non-Linear Arithmetic', () => {
    it('is strictly commutative: fBlaMka(x, y) == fBlaMka(y, x)', () => {
      const pairs = [
        [0n, 0n],
        [1n, 2n],
        [0x12345678n, 0x87654321n],
        [0xffffffffn, 0x12345678n],
        [0x100000000n, 0x200000000n],
        [0xffffffffffffffffn, 1n],
        [0xdeadbeefcafebaben, 0x0123456789abcdefn]
      ];

      for (const [x, y] of pairs) {
        expect(fBlaMka(x, y)).toBe(fBlaMka(y, x));
      }
    });

    it('has additive identity with 0n: fBlaMka(x, 0) == x', () => {
      const values = [0n, 1n, 0x12345678n, 0xffffffffn, 0xffffffffffffffffn];
      for (const x of values) {
        expect(fBlaMka(x, 0n)).toBe(x);
        expect(fBlaMka(0n, x)).toBe(x);
      }
    });

    it('computes known mathematical manual cases correctly', () => {
      // 1 + 2 + 2 * (1 * 2) = 7
      expect(fBlaMka(1n, 2n)).toBe(7n);

      // When lower 32 bits are zero, 2 * 0 * 0 = 0, so result is simply (x + y) mod 2^64
      const x = 0x100000000n;
      const y = 0x200000000n;
      expect(fBlaMka(x, y)).toBe(0x300000000n);

      // 0xffffffffn has lower 32 bits all 1s (2^32 - 1)
      const u32max = 0xffffffffn;
      // x + y + 2 * u32max * u32max
      const expected = (u32max + u32max + 2n * u32max * u32max) & 0xffffffffffffffffn;
      expect(fBlaMka(u32max, u32max)).toBe(expected);
    });

    it('handles 64-bit unsigned integer overflow modulo 2^64 correctly', () => {
      // 2^64 - 1 + 1 = 0 mod 2^64. Plus 2 * (2^32 - 1) * 1 = 2 * (2^32 - 1) = 0x1fffffffe
      const max64 = 0xffffffffffffffffn;
      expect(fBlaMka(max64, 1n)).toBe(0x1fffffffen);
    });
  });

  describe('GB Quarter-Round Function', () => {
    it('modifies only indices a, b, c, d and leaves all other vector elements untouched', () => {
      const v = new BigUint64Array(16);
      for (let i = 0; i < 16; i++) v[i] = BigInt(i + 1);

      const copyBefore = new BigUint64Array(v);
      GB(v, 0, 4, 8, 12);

      // 0, 4, 8, 12 should be modified
      expect(v[0]).not.toBe(copyBefore[0]);
      expect(v[4]).not.toBe(copyBefore[4]);
      expect(v[8]).not.toBe(copyBefore[8]);
      expect(v[12]).not.toBe(copyBefore[12]);

      // All others must be completely unchanged
      for (let i = 0; i < 16; i++) {
        if (i !== 0 && i !== 4 && i !== 8 && i !== 12) {
          expect(v[i]).toBe(copyBefore[i]);
        }
      }
    });
  });

  describe('Permutation roundP', () => {
    it('thoroughly diffuses all 16 state words', () => {
      const v = new BigUint64Array(16);
      v[0] = 0x0123456789abcdefn;

      const indices = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
      roundP(v, ...indices);

      // After 4 column and 4 diagonal rounds, every word must be non-zero
      for (let i = 0; i < 16; i++) {
        expect(v[i]).not.toBe(0n);
      }
    });
  });

  describe('1024-Byte Block Compression Function G', () => {
    it('compresses two 1024-byte blocks deterministically', () => {
      const X = new BigUint64Array(QWORDS_PER_BLOCK);
      const Y = new BigUint64Array(QWORDS_PER_BLOCK);
      for (let i = 0; i < QWORDS_PER_BLOCK; i++) {
        X[i] = BigInt(i * 3 + 1);
        Y[i] = BigInt(i * 7 + 2);
      }

      const dest1 = new BigUint64Array(QWORDS_PER_BLOCK);
      const dest2 = new BigUint64Array(QWORDS_PER_BLOCK);

      compressBlock(X, Y, dest1, false);
      compressBlock(X, Y, dest2, false);

      expect(Array.from(dest1)).toEqual(Array.from(dest2));
      expect(dest1.some((w) => w !== 0n)).toBe(true);
    });

    it('works seamlessly with Uint8Array views (1024 bytes)', () => {
      const u8X = new Uint8Array(BLOCK_BYTES).fill(0xaa);
      const u8Y = new Uint8Array(BLOCK_BYTES).fill(0x55);
      const u8Dest = new Uint8Array(BLOCK_BYTES);

      compressBlock(u8X, u8Y, u8Dest, false);
      expect(u8Dest.some((b) => b !== 0)).toBe(true);
    });

    it('correctly XORs into destination when xorWithDest is true (pass > 0)', () => {
      const X = new BigUint64Array(QWORDS_PER_BLOCK).fill(1n);
      const Y = new BigUint64Array(QWORDS_PER_BLOCK).fill(2n);

      const destPass0 = new BigUint64Array(QWORDS_PER_BLOCK);
      compressBlock(X, Y, destPass0, false);

      // destination pre-filled with an existing state
      const existing = new BigUint64Array(QWORDS_PER_BLOCK).fill(0x42n);
      const destPass1 = new BigUint64Array(existing);

      compressBlock(X, Y, destPass1, true);

      // destPass1 must equal existing ^ destPass0
      for (let i = 0; i < QWORDS_PER_BLOCK; i++) {
        expect(destPass1[i]).toBe(existing[i] ^ destPass0[i]);
      }
    });

    it('produces identical output when using a pre-allocated scratch buffer', () => {
      const X = new BigUint64Array(QWORDS_PER_BLOCK).fill(0x12345678n);
      const Y = new BigUint64Array(QWORDS_PER_BLOCK).fill(0x87654321n);

      const dest1 = new BigUint64Array(QWORDS_PER_BLOCK);
      const dest2 = new BigUint64Array(QWORDS_PER_BLOCK);

      const scratch = new BigUint64Array(QWORDS_PER_BLOCK);

      compressBlock(X, Y, dest1, false, null);
      compressBlock(X, Y, dest2, false, scratch);

      expect(Array.from(dest1)).toEqual(Array.from(dest2));
    });

    it('rejects blocks with invalid sizes', () => {
      const invalidU8 = new Uint8Array(500);
      const validU8 = new Uint8Array(1024);

      expect(() => compressBlock(invalidU8, validU8, validU8)).toThrow(RangeError);
      expect(() => compressBlock(validU8, invalidU8, validU8)).toThrow(RangeError);
      expect(() => compressBlock(validU8, validU8, invalidU8)).toThrow(RangeError);
    });
  });
});
