/**
 * @fileoverview Test suite for Argon2 Core Execution Engine (RFC 9106).
 */

import { describe, it, expect } from 'vitest';
import { argon2Core } from '../src/core/argon2.js';
import { ARGON2_TYPES, ARGON2_VERSIONS } from '../src/constants/index.js';

describe('Argon2 Core Engine', () => {
  describe('Official RFC 9106 Section 5 Golden Test Vectors', () => {
    // Common parameters across RFC 9106 Section 5 test vectors:
    // Memory: 32 KiB, Passes: 3, Parallelism: 4, Tag Length: 32
    // Password: 32 bytes of 0x01
    // Salt: 16 bytes of 0x02
    // Secret: 8 bytes of 0x03
    // Associated Data: 12 bytes of 0x04
    const baseParams = {
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

    it('matches official RFC 9106 Section 5.1 Argon2d Golden Vector', () => {
      const tag = argon2Core({
        ...baseParams,
        type: ARGON2_TYPES.ARGON2D
      });

      const expectedHex = '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb';
      expect(Buffer.from(tag).toString('hex')).toBe(expectedHex);
    });

    it('matches official RFC 9106 Section 5.2 Argon2i Golden Vector', () => {
      const tag = argon2Core({
        ...baseParams,
        type: ARGON2_TYPES.ARGON2I
      });

      const expectedHex = 'c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8';
      expect(Buffer.from(tag).toString('hex')).toBe(expectedHex);
    });

    it('matches official RFC 9106 Section 5.3 Argon2id Golden Vector', () => {
      const tag = argon2Core({
        ...baseParams,
        type: ARGON2_TYPES.ARGON2ID
      });

      const expectedHex = '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659';
      expect(Buffer.from(tag).toString('hex')).toBe(expectedHex);
    });
  });

  describe('Variable Configuration and Output Sizes', () => {
    it('produces variable tag lengths (e.g. 16, 24, 64 bytes)', () => {
      for (const length of [16, 24, 64]) {
        const tag = argon2Core({
          password: 'my-secure-password',
          salt: 'salt-must-be-at-least-8',
          parallelism: 1,
          memoryCost: 16,
          timeCost: 1,
          hashLength: length
        });

        expect(tag).toBeInstanceOf(Uint8Array);
        expect(tag.length).toBe(length);
      }
    });

    it('handles string, Buffer, and Uint8Array password/salt inputs identically', () => {
      const strPass = 'correct-horse-battery-staple';
      const strSalt = 'salt-string-0123';

      const tagFromStr = argon2Core({
        password: strPass,
        salt: strSalt,
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      const tagFromBuf = argon2Core({
        password: Buffer.from(strPass),
        salt: Buffer.from(strSalt),
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      const tagFromU8 = argon2Core({
        password: new TextEncoder().encode(strPass),
        salt: new TextEncoder().encode(strSalt),
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      expect(Buffer.from(tagFromStr).toString('hex')).toBe(Buffer.from(tagFromBuf).toString('hex'));
      expect(Buffer.from(tagFromStr).toString('hex')).toBe(Buffer.from(tagFromU8).toString('hex'));
    });

    it('produces completely different hashes for single-bit password or salt changes', () => {
      const tag1 = argon2Core({
        password: 'password1',
        salt: 'secure-salt-1234',
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      const tag2 = argon2Core({
        password: 'password2',
        salt: 'secure-salt-1234',
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      const tag3 = argon2Core({
        password: 'password1',
        salt: 'secure-salt-1235',
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      expect(Buffer.from(tag1).toString('hex')).not.toBe(Buffer.from(tag2).toString('hex'));
      expect(Buffer.from(tag1).toString('hex')).not.toBe(Buffer.from(tag3).toString('hex'));
    });
  });

  describe('Defensive Input Validation', () => {
    it('throws when password or salt is missing', () => {
      expect(() => argon2Core({})).toThrow(TypeError);
      expect(() => argon2Core({ password: 'pw' })).toThrow(TypeError);
      expect(() => argon2Core({ salt: 'salt12345' })).toThrow(TypeError);
    });

    it('throws when salt is less than 8 bytes', () => {
      expect(() => argon2Core({
        password: 'pw',
        salt: 'short'
      })).toThrow(RangeError);
    });

    it('throws when memoryCost is less than 8 * parallelism', () => {
      expect(() => argon2Core({
        password: 'pw',
        salt: 'salt12345',
        parallelism: 4,
        memoryCost: 24 // < 32 (8 * 4)
      })).toThrow(RangeError);
    });

    it('throws when memoryCost exceeds safe ceiling (2 GiB)', () => {
      expect(() => argon2Core({
        password: 'pw',
        salt: 'salt12345',
        parallelism: 1,
        memoryCost: 3 * 1024 * 1024 // 3 GiB
      })).toThrow(RangeError);
    });
  });
});
