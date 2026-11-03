/**
 * @fileoverview Test suite for HashForge High-Level Public API (hash, verify, needsRehash).
 */

import { describe, it, expect } from 'vitest';
import { hash, verify, needsRehash, ARGON2_TYPES, ARGON2_VERSIONS } from '../src/index.js';

describe('HashForge High-Level Public API', () => {
  const testFastOptions = {
    parallelism: 1,
    memoryCost: 16,
    timeCost: 1
  };

  describe('hash()', () => {
    it('produces a standard Modular Crypt Format (MCF) string with defaults', async () => {
      const password = 'CorrectHorseBatteryStaple123!';
      const encoded = await hash(password, testFastOptions);

      expect(typeof encoded).toBe('string');
      expect(encoded.startsWith('$argon2id$v=19$m=16,t=1,p=1$')).toBe(true);

      const parts = encoded.split('$');
      expect(parts.length).toBe(6);
      expect(parts[1]).toBe('argon2id');
      expect(parts[2]).toBe('v=19');
      expect(parts[3]).toBe('m=16,t=1,p=1');
      expect(parts[4].length).toBeGreaterThan(0); // salt
      expect(parts[5].length).toBeGreaterThan(0); // hash
    });

    it('generates distinct salts and distinct hashes across repeated calls', async () => {
      const password = 'SuperSecretPassword!';
      const hash1 = await hash(password, testFastOptions);
      const hash2 = await hash(password, testFastOptions);

      expect(hash1).not.toBe(hash2);
      const salt1 = hash1.split('$')[4];
      const salt2 = hash2.split('$')[4];
      expect(salt1).not.toBe(salt2);
    });

    it('supports raw output mode returning Uint8Array', async () => {
      const rawTag = await hash('myPassword', {
        ...testFastOptions,
        raw: true,
        hashLength: 32
      });

      expect(rawTag).toBeInstanceOf(Uint8Array);
      expect(rawTag.length).toBe(32);
    });

    it('supports custom salt buffers', async () => {
      const customSalt = new Uint8Array(16).fill(0xaa);
      const encoded = await hash('myPassword', {
        ...testFastOptions,
        salt: customSalt
      });

      const b64Salt = Buffer.from(customSalt).toString('base64').replace(/=+$/, '');
      expect(encoded).toContain(`$${b64Salt}$`);
    });

    it('throws when password is null or undefined', async () => {
      await expect(hash(null)).rejects.toThrow(TypeError);
      await expect(hash(undefined)).rejects.toThrow(TypeError);
    });
  });

  describe('verify()', () => {
    it('returns true for correct password and false for wrong password', async () => {
      const password = 'Passw0rd-Strong-Auth!';
      const encoded = await hash(password, testFastOptions);

      const isValid = await verify(encoded, password);
      expect(isValid).toBe(true);

      const isInvalid = await verify(encoded, 'Wrong-Password-Attempt!');
      expect(isInvalid).toBe(false);
    });

    it('verifies passwords provided as Buffer or Uint8Array', async () => {
      const password = 'MultiFormatPassword123';
      const encoded = await hash(password, testFastOptions);

      expect(await verify(encoded, Buffer.from(password))).toBe(true);
      expect(await verify(encoded, new TextEncoder().encode(password))).toBe(true);
    });

    it('returns false for corrupted or altered encoded hash strings', async () => {
      const password = 'TestingCorruptHash';
      const encoded = await hash(password, testFastOptions);

      // Corrupt the hash part (flip the leading base64 character to alter payload bits)
      const parts = encoded.split('$');
      parts[5] = (parts[5][0] === 'A' ? 'B' : 'A') + parts[5].slice(1);
      const corruptedHash = parts.join('$');

      expect(await verify(corruptedHash, password)).toBe(false);
    });

    it('returns false for malformed or non-MCF strings without throwing', async () => {
      expect(await verify('not-a-hash', 'password')).toBe(false);
      expect(await verify('$bcrypt$something', 'password')).toBe(false);
      expect(await verify('$argon2id$v=99$bad$params', 'password')).toBe(false);
    });

    it('throws TypeError if candidate password or encodedHash is invalid type', async () => {
      await expect(verify(12345, 'password')).rejects.toThrow(TypeError);
      await expect(verify('$argon2id$v=19$...', null)).rejects.toThrow(TypeError);
    });
  });

  describe('needsRehash()', () => {
    it('returns false when hash matches target security policy', async () => {
      const encoded = await hash('pw', {
        parallelism: 2,
        memoryCost: 32,
        timeCost: 2
      });

      const shouldRehash = needsRehash(encoded, {
        parallelism: 2,
        memoryCost: 32,
        timeCost: 2
      });

      expect(shouldRehash).toBe(false);
    });

    it('returns true when target memory cost is upgraded', async () => {
      const encoded = await hash('pw', { memoryCost: 32, parallelism: 1, timeCost: 1 });
      expect(needsRehash(encoded, { memoryCost: 64, parallelism: 1, timeCost: 1 })).toBe(true);
    });

    it('returns true when target time cost is upgraded', async () => {
      const encoded = await hash('pw', { timeCost: 1, memoryCost: 16, parallelism: 1 });
      expect(needsRehash(encoded, { timeCost: 2, memoryCost: 16, parallelism: 1 })).toBe(true);
    });

    it('returns true when target parallelism is upgraded', async () => {
      const encoded = await hash('pw', { parallelism: 1, memoryCost: 16, timeCost: 1 });
      expect(needsRehash(encoded, { parallelism: 2, memoryCost: 16, timeCost: 1 })).toBe(true);
    });

    it('returns true when target algorithm type is changed', async () => {
      const encodedI = await hash('pw', {
        type: ARGON2_TYPES.ARGON2I,
        memoryCost: 16,
        parallelism: 1,
        timeCost: 1
      });

      expect(needsRehash(encodedI, { type: ARGON2_TYPES.ARGON2ID, memoryCost: 16, parallelism: 1, timeCost: 1 })).toBe(true);
      expect(needsRehash(encodedI, { type: 'argon2id', memoryCost: 16, parallelism: 1, timeCost: 1 })).toBe(true);
    });

    it('returns true for malformed hash strings', () => {
      expect(needsRehash('invalid-string')).toBe(true);
    });
  });
});

