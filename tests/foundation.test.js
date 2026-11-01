import { describe, it, expect } from 'vitest';
import {
  ARGON2_TYPES,
  ARGON2_VERSIONS,
  BLOCK_BYTES,
  QWORDS_PER_BLOCK,
  DEFAULTS,
  LIMITS
} from '../src/constants/index.js';
import { validateOptions, normalizeBuffer } from '../src/utils/validation.js';
import { timingSafeEqual } from '../src/utils/constantTime.js';
import { toUnpaddedBase64, fromUnpaddedBase64, formatEncodedHash, parseEncodedHash } from '../src/utils/encoding.js';
import { generateRandomBytes } from '../src/crypto/random.js';

describe('Phase 1: Architecture & Cryptographic Foundations', () => {
  describe('Constants & RFC 9106 Specifications', () => {
    it('defines correct Argon2 types', () => {
      expect(ARGON2_TYPES.ARGON2D).toBe(0);
      expect(ARGON2_TYPES.ARGON2I).toBe(1);
      expect(ARGON2_TYPES.ARGON2ID).toBe(2);
    });

    it('defines RFC 9106 version 0x13', () => {
      expect(ARGON2_VERSIONS.V13).toBe(0x13);
      expect(ARGON2_VERSIONS.V10).toBe(0x10);
    });

    it('defines standard 1024-byte block dimensions', () => {
      expect(BLOCK_BYTES).toBe(1024);
      expect(QWORDS_PER_BLOCK).toBe(128); // 128 * 8 bytes = 1024 bytes
    });

    it('provides secure RFC recommended defaults', () => {
      expect(DEFAULTS.type).toBe(ARGON2_TYPES.ARGON2ID);
      expect(DEFAULTS.version).toBe(ARGON2_VERSIONS.V13);
      expect(DEFAULTS.timeCost).toBeGreaterThanOrEqual(1);
      expect(DEFAULTS.memoryCost).toBeGreaterThanOrEqual(8 * DEFAULTS.parallelism);
      expect(DEFAULTS.parallelism).toBeGreaterThanOrEqual(1);
      expect(DEFAULTS.saltLength).toBeGreaterThanOrEqual(16);
      expect(DEFAULTS.hashLength).toBe(32);
    });
  });

  describe('Parameter Validation & Safety Bounds', () => {
    it('validates default options successfully', () => {
      const opts = validateOptions();
      expect(opts.timeCost).toBe(DEFAULTS.timeCost);
      expect(opts.memoryCost).toBe(DEFAULTS.memoryCost);
      expect(opts.parallelism).toBe(DEFAULTS.parallelism);
    });

    it('rejects memoryCost lower than 8 * parallelism', () => {
      expect(() => {
        validateOptions({ parallelism: 4, memoryCost: 31 });
      }).toThrow(/memoryCost must be an integer >= 32/);
    });

    it('rejects invalid timeCost bounds', () => {
      expect(() => validateOptions({ timeCost: 0 })).toThrow(RangeError);
      expect(() => validateOptions({ timeCost: -5 })).toThrow(RangeError);
    });

    it('rejects memoryCost exceeding safe limits', () => {
      expect(() => validateOptions({ memoryCost: 3 * 1024 * 1024 })).toThrow(/safe allocation limit/);
    });

    it('normalizes string, Buffer, and Uint8Array inputs into Uint8Array', () => {
      const strBuf = normalizeBuffer('test-password');
      expect(strBuf).toBeInstanceOf(Uint8Array);
      expect(new TextDecoder().decode(strBuf)).toBe('test-password');

      const u8 = new Uint8Array([1, 2, 3]);
      expect(normalizeBuffer(u8)).toBe(u8);

      const nodeBuf = Buffer.from([4, 5, 6]);
      const normalizedNodeBuf = normalizeBuffer(nodeBuf);
      expect(normalizedNodeBuf).toBeInstanceOf(Uint8Array);
      expect(Array.from(normalizedNodeBuf)).toEqual([4, 5, 6]);
    });
  });

  describe('Constant-Time Comparison (timingSafeEqual)', () => {
    it('returns true for identical byte sequences', () => {
      const a = new Uint8Array([1, 2, 3, 4, 5]);
      const b = new Uint8Array([1, 2, 3, 4, 5]);
      expect(timingSafeEqual(a, b)).toBe(true);
    });

    it('returns false for mismatched byte contents', () => {
      const a = new Uint8Array([1, 2, 3, 4, 5]);
      const b = new Uint8Array([1, 2, 3, 4, 6]);
      expect(timingSafeEqual(a, b)).toBe(false);
    });

    it('returns false safely when lengths differ without throwing', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3, 4]);
      expect(timingSafeEqual(a, b)).toBe(false);
    });
  });

  describe('Unpadded Base64 & Modular Crypt Format (MCF)', () => {
    it('encodes and decodes unpadded base64 correctly', () => {
      const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const encoded = toUnpaddedBase64(data);
      expect(encoded).not.toContain('=');
      const decoded = fromUnpaddedBase64(encoded);
      expect(Array.from(decoded)).toEqual(Array.from(data));
    });

    it('formats and parses standard Argon2 MCF string', () => {
      const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
      const hash = new Uint8Array(32).fill(42);

      const mcf = formatEncodedHash({
        type: 'argon2id',
        version: 19,
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 4,
        salt,
        hash
      });

      expect(mcf).toMatch(/^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/);

      const parsed = parseEncodedHash(mcf);
      expect(parsed.type).toBe('argon2id');
      expect(parsed.version).toBe(19);
      expect(parsed.memoryCost).toBe(65536);
      expect(parsed.timeCost).toBe(3);
      expect(parsed.parallelism).toBe(4);
      expect(Array.from(parsed.salt)).toEqual(Array.from(salt));
      expect(Array.from(parsed.hash)).toEqual(Array.from(hash));
    });
  });

  describe('Secure Random Generation', () => {
    it('generates non-zero cryptographically random bytes of requested length', () => {
      const salt1 = generateRandomBytes(16);
      const salt2 = generateRandomBytes(16);
      expect(salt1.length).toBe(16);
      expect(salt2.length).toBe(16);
      expect(Array.from(salt1)).not.toEqual(Array.from(salt2));
    });

    it('rejects non-positive lengths', () => {
      expect(() => generateRandomBytes(0)).toThrow(RangeError);
      expect(() => generateRandomBytes(-1)).toThrow(RangeError);
    });
  });
});
