import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  blake2b,
  Blake2bContext,
  BLAKE2B_IV,
  BLAKE2B_SIGMA,
  rotr64
} from '../src/crypto/blake2b.js';

describe('Phase 2: RFC 7693 BLAKE2b Implementation', () => {
  describe('Mathematical Primitives & Constants', () => {
    it('defines 8 64-bit IV constants', () => {
      expect(BLAKE2B_IV.length).toBe(8);
      expect(BLAKE2B_IV[0]).toBe(0x6a09e667f3bcc908n);
      expect(BLAKE2B_IV[7]).toBe(0x5be0cd19137e2179n);
    });

    it('defines 10 SIGMA permutation schedules of length 16', () => {
      expect(BLAKE2B_SIGMA.length).toBe(10);
      for (const row of BLAKE2B_SIGMA) {
        expect(row.length).toBe(16);
        expect(new Set(row).size).toBe(16); // all indices 0..15 present
      }
    });

    it('performs 64-bit right rotations correctly', () => {
      expect(rotr64(1n, 1n)).toBe(0x8000000000000000n);
      expect(rotr64(0x8000000000000000n, 1n)).toBe(0x4000000000000000n);
      expect(rotr64(0x123456789abcdef0n, 32n)).toBe(0x9abcdef012345678n);
    });
  });

  describe('RFC 7693 Appendix E Official Self-Test', () => {
    /**
     * Deterministic Fibonacci-like sequence generator from RFC 7693 Appendix E.
     */
    function selftestSeq(out, len, seed) {
      let a = Math.imul(0xdead4bad, seed) >>> 0;
      let b = 1;
      for (let i = 0; i < len; i++) {
        const t = (a + b) >>> 0;
        a = b;
        b = t;
        out[i] = (t >>> 24) & 0xff;
      }
    }

    it('passes the official RFC 7693 grand-hash self-test vector', () => {
      const b2bMdLen = [20, 32, 48, 64];
      const b2bInLen = [0, 3, 128, 129, 255, 1024];

      const masterCtx = new Blake2bContext(32);
      const inBuf = new Uint8Array(1024);
      const keyBuf = new Uint8Array(64);

      for (let i = 0; i < 4; i++) {
        const outlen = b2bMdLen[i];
        for (let j = 0; j < 6; j++) {
          const inlen = b2bInLen[j];

          // 1. Unkeyed hash
          selftestSeq(inBuf, inlen, inlen);
          const md1 = new Blake2bContext(outlen)
            .update(inBuf.subarray(0, inlen))
            .digest();
          masterCtx.update(md1);

          // 2. Keyed hash
          selftestSeq(keyBuf, outlen, outlen);
          const md2 = new Blake2bContext(outlen, keyBuf.subarray(0, outlen))
            .update(inBuf.subarray(0, inlen))
            .digest();
          masterCtx.update(md2);
        }
      }

      const grandHash = masterCtx.digest();
      const grandHashHex = Buffer.from(grandHash).toString('hex');

      // Hardcoded expected 32-byte grand hash from RFC 7693 Appendix E (blake2b_res)
      const expectedGrandHashHex = 'c23a7800d98123bd10f506c61e29da5603d763b8bbad2e737f5e765a7bccd475';
      expect(grandHashHex).toBe(expectedGrandHashHex);
    });
  });

  describe('Standard Test Vectors', () => {
    it('computes 512-bit digest for empty string correctly', () => {
      const digest = blake2b('', null, 64);
      expect(Buffer.from(digest).toString('hex')).toBe(
        '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce'
      );
    });

    it('computes 512-bit digest for "abc" correctly', () => {
      const digest = blake2b('abc', null, 64);
      expect(Buffer.from(digest).toString('hex')).toBe(
        'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923'
      );
    });

    it('computes 512-bit digest for the quick brown fox correctly', () => {
      const message = 'The quick brown fox jumps over the lazy dog';
      const digest = blake2b(message, null, 64);
      expect(Buffer.from(digest).toString('hex')).toBe(
        'a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918'
      );
    });
  });

  describe('Differential Verification against Node.js OpenSSL (blake2b512)', () => {
    const testCases = [
      '',
      'a',
      'hello world',
      'password123',
      'A'.repeat(64),
      'B'.repeat(127),
      'C'.repeat(128),
      'D'.repeat(129),
      'E'.repeat(256),
      'F'.repeat(1024),
      'G'.repeat(5000)
    ];

    for (const testCase of testCases) {
      it(`matches OpenSSL for message length ${testCase.length}`, () => {
        const expected = crypto.createHash('blake2b512').update(testCase).digest('hex');
        const actual = Buffer.from(blake2b(testCase, null, 64)).toString('hex');
        expect(actual).toBe(expected);
      });
    }
  });

  describe('Streaming & Chunk Invariance', () => {
    it('produces identical digest regardless of chunk sizes', () => {
      const longMessage = new Uint8Array(2000);
      for (let i = 0; i < longMessage.length; i++) longMessage[i] = (i * 17) & 0xff;

      const oneShot = blake2b(longMessage, null, 64);

      // Byte-by-byte update
      const stream1 = new Blake2bContext(64);
      for (let i = 0; i < longMessage.length; i++) {
        stream1.update(longMessage.subarray(i, i + 1));
      }
      expect(Array.from(stream1.digest())).toEqual(Array.from(oneShot));

      // Irregular chunk sizes
      const stream2 = new Blake2bContext(64);
      stream2.update(longMessage.subarray(0, 13));
      stream2.update(longMessage.subarray(13, 140));
      stream2.update(longMessage.subarray(140, 512));
      stream2.update(longMessage.subarray(512, 1999));
      stream2.update(longMessage.subarray(1999, 2000));
      expect(Array.from(stream2.digest())).toEqual(Array.from(oneShot));
    });
  });

  describe('Variable Output Lengths', () => {
    it('supports arbitrary outlen between 1 and 64 bytes', () => {
      for (const len of [1, 16, 20, 32, 48, 64]) {
        const digest = blake2b('test payload', null, len);
        expect(digest.length).toBe(len);
      }
    });
  });

  describe('Parameter Bounds & Error Handling', () => {
    it('rejects outlen outside 1..64 range', () => {
      expect(() => new Blake2bContext(0)).toThrow(RangeError);
      expect(() => new Blake2bContext(65)).toThrow(RangeError);
      expect(() => new Blake2bContext(-1)).toThrow(RangeError);
    });

    it('rejects key length exceeding 64 bytes', () => {
      const bigKey = new Uint8Array(65);
      expect(() => new Blake2bContext(64, bigKey)).toThrow(RangeError);
    });

    it('rejects invalid salt or personal lengths', () => {
      expect(() => new Blake2bContext(64, null, { salt: new Uint8Array(15) })).toThrow(RangeError);
      expect(() => new Blake2bContext(64, null, { personal: new Uint8Array(17) })).toThrow(RangeError);
    });
  });
});
