import { describe, it, expect } from 'vitest';
import { variableLengthHash } from '../src/crypto/variableHash.js';
import { blake2b } from '../src/crypto/blake2b.js';

describe('Phase 3: RFC 9106 Section 3.2 Variable-Length Hash Function H\'', () => {
  describe('Short Output Lengths (T <= 64 bytes)', () => {
    it('matches direct BLAKE2b prefixed with LE32(T)', () => {
      const message = new TextEncoder().encode('HashForge password hashing');

      for (const outlen of [1, 16, 20, 32, 48, 64]) {
        const prefix = new Uint8Array(4);
        new DataView(prefix.buffer).setUint32(0, outlen, true);

        const combined = new Uint8Array(4 + message.length);
        combined.set(prefix, 0);
        combined.set(message, 4);

        const expected = blake2b(combined, null, outlen);
        const actual = variableLengthHash(message, outlen);

        expect(actual.length).toBe(outlen);
        expect(Array.from(actual)).toEqual(Array.from(expected));
      }
    });
  });

  describe('Boundary Conditions Around 64 Bytes', () => {
    it('transitions smoothly across 64-byte boundary', () => {
      const message = 'Boundary test message';

      const h63 = variableLengthHash(message, 63);
      const h64 = variableLengthHash(message, 64);
      const h65 = variableLengthHash(message, 65);
      const h66 = variableLengthHash(message, 66);

      expect(h63.length).toBe(63);
      expect(h64.length).toBe(64);
      expect(h65.length).toBe(65);
      expect(h66.length).toBe(66);

      // Verify that for T=65, the first 32 bytes match W_1 (first 32 bytes of V_1)
      const prefix65 = new Uint8Array(4);
      new DataView(prefix65.buffer).setUint32(0, 65, true);
      const v1Expected = blake2b(Buffer.concat([prefix65, Buffer.from(message)]), null, 64);

      expect(Array.from(h65.subarray(0, 32))).toEqual(Array.from(v1Expected.subarray(0, 32)));

      // And bytes 32..64 (33 bytes) match V_2 = blake2b(V_1, null, 33)
      const v2Expected = blake2b(v1Expected, null, 33);
      expect(Array.from(h65.subarray(32, 65))).toEqual(Array.from(v2Expected));
    });
  });

  describe('Argon2 Standard 1024-Byte Memory Block Generation', () => {
    it('generates an exact 1024-byte block according to RFC 9106 chaining rules', () => {
      const message = new Uint8Array(64).fill(0x5a); // Simulate H0

      const block = variableLengthHash(message, 1024);
      expect(block.length).toBe(1024);

      // Verify mathematical derivation step-by-step
      const prefix = new Uint8Array(4);
      new DataView(prefix.buffer).setUint32(0, 1024, true);

      // Step 1: V_1 = H^(64)(LE32(1024) || message)
      let v = blake2b(Buffer.concat([prefix, message]), null, 64);
      expect(Array.from(block.subarray(0, 32))).toEqual(Array.from(v.subarray(0, 32)));

      // Step 2: V_2 ... V_30 (r = 30)
      for (let i = 2; i <= 30; i++) {
        v = blake2b(v, null, 64);
        const offset = (i - 1) * 32;
        expect(Array.from(block.subarray(offset, offset + 32))).toEqual(Array.from(v.subarray(0, 32)));
      }

      // Step 3: Final block V_31 = H^(64)(V_30) (rem = 1024 - 32 * 30 = 64)
      const v31 = blake2b(v, null, 64);
      expect(Array.from(block.subarray(960, 1024))).toEqual(Array.from(v31));
    });
  });

  describe('Destination Buffer & Memory Re-use', () => {
    it('writes directly into a pre-allocated destination buffer', () => {
      const message = 'test buffer reuse';
      const dest = new Uint8Array(1024);

      const returned = variableLengthHash(message, 1024, dest);
      expect(returned).toBe(dest); // Exact same buffer instance
      expect(returned.some((byte) => byte !== 0)).toBe(true);
    });

    it('rejects destination buffer if smaller than requested outlen', () => {
      const smallDest = new Uint8Array(100);
      expect(() => {
        variableLengthHash('msg', 1024, smallDest);
      }).toThrow(/Destination buffer length/);
    });
  });

  describe('Array of Message Chunks', () => {
    it('produces identical output for chunked arrays vs concatenated strings', () => {
      const chunk1 = new TextEncoder().encode('first-part-');
      const chunk2 = new TextEncoder().encode('second-part-');
      const chunk3 = new TextEncoder().encode('third-part');

      const fullString = 'first-part-second-part-third-part';

      for (const len of [32, 64, 128, 1024]) {
        const hashFromChunks = variableLengthHash([chunk1, chunk2, chunk3], len);
        const hashFromString = variableLengthHash(fullString, len);
        expect(Array.from(hashFromChunks)).toEqual(Array.from(hashFromString));
      }
    });
  });

  describe('Input Validation & Constraints', () => {
    it('rejects invalid outlen bounds', () => {
      expect(() => variableLengthHash('msg', 0)).toThrow(RangeError);
      expect(() => variableLengthHash('msg', -10)).toThrow(RangeError);
      expect(() => variableLengthHash('msg', 32.5)).toThrow(RangeError);
      expect(() => variableLengthHash('msg', '64')).toThrow(RangeError);
    });
  });
});

