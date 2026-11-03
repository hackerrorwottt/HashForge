/**
 * @fileoverview Phase 9: Comprehensive Testing & Differential Verification Suite.
 *
 * Verifies RFC 9106 compliance across varying parameters, edge cases,
 * boundary conditions, and end-to-end authentication lifecycles.
 */

import { describe, it, expect } from 'vitest';
import { hash, verify, needsRehash, argon2Core, ARGON2_TYPES, ARGON2_VERSIONS } from '../src/index.js';
import { parseEncodedHash } from '../src/utils/encoding.js';

describe('Phase 9: Comprehensive & Differential Verification', () => {
  describe('RFC 9106 Boundary & Matrix Scaling', () => {
    it('executes correctly on minimum boundary memory (m = 8 * p)', () => {
      const configs = [
        { parallelism: 1, memoryCost: 8 },
        { parallelism: 2, memoryCost: 16 },
        { parallelism: 4, memoryCost: 32 }
      ];

      for (const cfg of configs) {
        const tag = argon2Core({
          password: 'boundary-password',
          salt: 'salt-boundary-1234',
          timeCost: 1,
          parallelism: cfg.parallelism,
          memoryCost: cfg.memoryCost,
          hashLength: 32
        });

        expect(tag).toBeInstanceOf(Uint8Array);
        expect(tag.length).toBe(32);
      }
    });

    it('executes correctly across varying iteration passes (t = 1, 2, 4)', () => {
      const pass1 = argon2Core({
        password: 'scaling-password',
        salt: 'salt-12345678',
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      const pass2 = argon2Core({
        password: 'scaling-password',
        salt: 'salt-12345678',
        parallelism: 1,
        memoryCost: 16,
        timeCost: 2
      });

      const pass4 = argon2Core({
        password: 'scaling-password',
        salt: 'salt-12345678',
        parallelism: 1,
        memoryCost: 16,
        timeCost: 4
      });

      const h1 = Buffer.from(pass1).toString('hex');
      const h2 = Buffer.from(pass2).toString('hex');
      const h4 = Buffer.from(pass4).toString('hex');

      expect(h1).not.toBe(h2);
      expect(h2).not.toBe(h4);
      expect(h1).not.toBe(h4);
    });

    it('correctly produces non-standard tag lengths (16, 20, 48, 64 bytes)', () => {
      for (const hashLength of [16, 20, 48, 64]) {
        const tag = argon2Core({
          password: 'length-test-password',
          salt: 'salt-12345678',
          parallelism: 1,
          memoryCost: 16,
          timeCost: 1,
          hashLength
        });

        expect(tag.length).toBe(hashLength);
      }
    });
  });

  describe('Password & Salt Edge Cases', () => {
    it('hashes and verifies an empty password', async () => {
      const emptyPw = '';
      const encoded = await hash(emptyPw, {
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      expect(await verify(encoded, emptyPw)).toBe(true);
      expect(await verify(encoded, 'not-empty')).toBe(false);
    });

    it('hashes and verifies a long password (5,000 characters)', async () => {
      const longPw = 'a'.repeat(5000);
      const encoded = await hash(longPw, {
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      expect(await verify(encoded, longPw)).toBe(true);
      expect(await verify(encoded, longPw + 'b')).toBe(false);
    });

    it('hashes and verifies passwords containing binary null bytes and high Unicode', async () => {
      const binaryPw = 'pass\0word\u0000with\uFFFFunicode\uD83D\uDD25';
      const encoded = await hash(binaryPw, {
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      expect(await verify(encoded, binaryPw)).toBe(true);
      expect(await verify(encoded, 'passwordwithunicode')).toBe(false);
    });

    it('handles exact minimum 8-byte salt and oversized 64-byte salt', async () => {
      const minSalt = new Uint8Array(8).fill(0x77);
      const maxSalt = new Uint8Array(64).fill(0x88);

      const encodedMin = await hash('test-pw', {
        salt: minSalt,
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });
      expect(await verify(encodedMin, 'test-pw')).toBe(true);

      const encodedMax = await hash('test-pw', {
        salt: maxSalt,
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });
      expect(await verify(encodedMax, 'test-pw')).toBe(true);
    });
  });

  describe('Secret Key and Associated Data Options', () => {
    it('produces distinct digests with and without secret key (pepper)', () => {
      const withoutSecret = argon2Core({
        password: 'password',
        salt: 'salt-12345678',
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      const withSecret = argon2Core({
        password: 'password',
        salt: 'salt-12345678',
        secret: 'server-side-pepper-key',
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      expect(Buffer.from(withoutSecret).toString('hex')).not.toBe(
        Buffer.from(withSecret).toString('hex')
      );
    });

    it('verifies successfully when secret key is provided to verify()', async () => {
      const secret = 'super-secret-pepper';
      const encoded = await hash('my-account-password', {
        secret,
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      // Verification without secret fails
      expect(await verify(encoded, 'my-account-password')).toBe(false);

      // Verification with secret succeeds
      expect(await verify(encoded, 'my-account-password', { secret })).toBe(true);
    });

    it('produces distinct digests with and without associated data', () => {
      const withoutAD = argon2Core({
        password: 'password',
        salt: 'salt-12345678',
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      const withAD = argon2Core({
        password: 'password',
        salt: 'salt-12345678',
        associatedData: 'user-id-123456',
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      expect(Buffer.from(withoutAD).toString('hex')).not.toBe(
        Buffer.from(withAD).toString('hex')
      );
    });
  });

  describe('End-to-End Authentication Lifecycle', () => {
    it('simulates user registration, login success, wrong password, and rehash flow', async () => {
      const originalPassword = 'InitialUserPassword2026!';

      // 1. User signs up: generate initial hash
      const oldPolicyHash = await hash(originalPassword, {
        parallelism: 1,
        memoryCost: 16,
        timeCost: 1
      });

      // 2. User logs in with correct password
      const loginSuccess = await verify(oldPolicyHash, originalPassword);
      expect(loginSuccess).toBe(true);

      // 3. Attacker attempts login with wrong password
      const loginFail = await verify(oldPolicyHash, 'WrongGuess!');
      expect(loginFail).toBe(false);

      // 4. Security team upgrades system policy: check if rehash is needed
      const upgradedPolicy = {
        parallelism: 2,
        memoryCost: 32,
        timeCost: 2
      };
      expect(needsRehash(oldPolicyHash, upgradedPolicy)).toBe(true);

      // 5. System transparently upgrades password hash upon successful login
      const newPolicyHash = await hash(originalPassword, upgradedPolicy);
      expect(needsRehash(newPolicyHash, upgradedPolicy)).toBe(false);

      // 6. Future login succeeds against upgraded hash
      expect(await verify(newPolicyHash, originalPassword)).toBe(true);
    });

    it('round-trips MCF encoding and parsing with full parameter fidelity', async () => {
      const encoded = await hash('fidelityTest', {
        parallelism: 4,
        memoryCost: 64,
        timeCost: 2
      });

      const parsed = parseEncodedHash(encoded);
      expect(parsed.type).toBe('argon2id');
      expect(parsed.version).toBe(19);
      expect(parsed.parallelism).toBe(4);
      expect(parsed.memoryCost).toBe(64);
      expect(parsed.timeCost).toBe(2);
      expect(parsed.salt.length).toBe(16);
      expect(parsed.hash.length).toBe(32);
    });
  });
});

