/**
 * TypeScript Type Definitions for HashForge.
 * Independent Argon2id Password Hashing Engine (RFC 9106).
 */

export type BinaryData = string | Uint8Array | Buffer;

export type Argon2Type = 0 | 1 | 2;
export type Argon2TypeName = 'argon2d' | 'argon2i' | 'argon2id';
export type Argon2Version = 0x10 | 0x13;

export interface Argon2Options {
  /**
   * Number of passes/iterations t (default: 3).
   * Range: 1 to 2^32 - 1.
   */
  timeCost?: number;

  /**
   * Memory size in KiB m (default: 65536 KiB = 64 MiB).
   * Minimum: 8 * parallelism KiB. Maximum: 2 GiB (2097152 KiB).
   */
  memoryCost?: number;

  /**
   * Degree of parallelism p / number of lanes (default: 4).
   * Range: 1 to 2^24 - 1.
   */
  parallelism?: number;

  /**
   * Output tag length in bytes tau (default: 32).
   * Minimum: 4 bytes.
   */
  hashLength?: number;

  /**
   * Salt length in bytes to generate automatically (default: 16).
   * Minimum: 8 bytes. Ignored if custom salt is provided.
   */
  saltLength?: number;

  /**
   * Custom cryptographic salt buffer.
   * If provided, must be at least 8 bytes.
   */
  salt?: BinaryData;

  /**
   * Argon2 variant type (default: 2 / ARGON2_TYPES.ARGON2ID).
   * 0 = Argon2d, 1 = Argon2i, 2 = Argon2id.
   */
  type?: Argon2Type;

  /**
   * Argon2 specification version (default: 0x13 / 19).
   */
  version?: Argon2Version;

  /**
   * Optional secret cryptographic key K (pepper).
   */
  secret?: BinaryData;

  /**
   * Optional associated data X.
   */
  associatedData?: BinaryData;
}

export interface HashOptions extends Argon2Options {
  /**
   * If true, returns raw tag bytes (Uint8Array) instead of formatted MCF string.
   */
  raw?: boolean;
}

export interface VerifyOptions {
  /**
   * Optional secret cryptographic key K (pepper) matching original hash.
   */
  secret?: BinaryData;

  /**
   * Optional associated data X matching original hash.
   */
  associatedData?: BinaryData;
}

export interface RehashOptions {
  /** Target memory cost in KiB */
  memoryCost?: number;
  /** Target iteration count */
  timeCost?: number;
  /** Target degree of parallelism */
  parallelism?: number;
  /** Target algorithm version */
  version?: Argon2Version;
  /** Target algorithm type code or name */
  type?: Argon2Type | Argon2TypeName;
}

export interface ParsedHash {
  type: Argon2TypeName;
  version: number;
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  salt: Uint8Array;
  hash: Uint8Array;
}

/**
 * Hashes a plaintext password using Argon2id.
 *
 * @param password - Plaintext password
 * @param options - Hashing configuration options
 * @returns Standard Modular Crypt Format (MCF) string (or Uint8Array if raw: true)
 */
export function hash(password: BinaryData, options?: HashOptions & { raw?: false }): Promise<string>;
export function hash(password: BinaryData, options: HashOptions & { raw: true }): Promise<Uint8Array>;
export function hash(password: BinaryData, options?: HashOptions): Promise<string | Uint8Array>;

/**
 * Verifies a candidate password against an Argon2 encoded hash in constant time.
 *
 * @param encodedHash - Encoded Modular Crypt Format (MCF) string
 * @param candidatePassword - Plaintext password to verify
 * @param options - Verification options (secret, associatedData)
 * @returns True if password matches, false otherwise
 */
export function verify(encodedHash: string, candidatePassword: BinaryData, options?: VerifyOptions): Promise<boolean>;

/**
 * Determines whether an existing hash needs to be recomputed due to policy upgrades.
 *
 * @param encodedHash - Encoded MCF hash to inspect
 * @param desiredOptions - Target security configuration
 * @returns True if hash parameters are weaker than desired target
 */
export function needsRehash(encodedHash: string, desiredOptions?: RehashOptions): boolean;

/**
 * Executes low-level core Argon2 pipeline directly.
 *
 * @param options - Argon2 parameters and buffers
 * @returns Derived cryptographic tag
 */
export function argon2Core(options: Argon2Options & { password: BinaryData; salt: BinaryData }): Uint8Array;

export const ARGON2_TYPES: {
  readonly ARGON2D: 0;
  readonly ARGON2I: 1;
  readonly ARGON2ID: 2;
};

export const ARGON2_VERSIONS: {
  readonly V10: 0x10;
  readonly V13: 0x13;
};

export const DEFAULTS: {
  readonly type: 2;
  readonly version: 0x13;
  readonly timeCost: 3;
  readonly memoryCost: 65536;
  readonly parallelism: 4;
  readonly hashLength: 32;
  readonly saltLength: 16;
};

export const LIMITS: {
  readonly MIN_LANES: 1;
  readonly MAX_LANES: 16777215;
  readonly MIN_TIME: 1;
  readonly MAX_TIME: 4294967295;
  readonly MIN_HASH_LENGTH: 4;
  readonly MAX_HASH_LENGTH: 4294967295;
  readonly MIN_SALT_LENGTH: 8;
  readonly MAX_SALT_LENGTH: 4294967295;
};

