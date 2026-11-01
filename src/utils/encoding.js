/**
 * @fileoverview Encoding utilities for Argon2 Modular Crypt Format (MCF) and unpadded Base64.
 */

/**
 * Encodes a Uint8Array into unpadded Base64 string (RFC 4648 without '=' padding).
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toUnpaddedBase64(bytes) {
  const base64 = Buffer.from(bytes).toString('base64');
  return base64.replace(/=+$/, '');
}

/**
 * Decodes an unpadded Base64 string into a Uint8Array.
 *
 * @param {string} str
 * @returns {Uint8Array}
 */
export function fromUnpaddedBase64(str) {
  return new Uint8Array(Buffer.from(str, 'base64'));
}

/**
 * Formats Argon2 parameters, salt, and digest into standard Modular Crypt Format (MCF).
 * Format: $argon2id$v=19$m=<m>,t=<t>,p=<p>$<base64salt>$<base64hash>
 *
 * @param {Object} params
 * @param {string} params.type - Algorithm type (e.g. 'argon2id')
 * @param {number} params.version - Argon2 version (e.g. 19)
 * @param {number} params.memoryCost - Memory cost in KiB
 * @param {number} params.timeCost - Number of iterations
 * @param {number} params.parallelism - Number of lanes
 * @param {Uint8Array} params.salt - Salt bytes
 * @param {Uint8Array} params.hash - Derived hash bytes
 * @returns {string} Encoded MCF string
 */
export function formatEncodedHash({ type, version, memoryCost, timeCost, parallelism, salt, hash }) {
  const b64Salt = toUnpaddedBase64(salt);
  const b64Hash = toUnpaddedBase64(hash);
  return `$${type}$v=${version}$m=${memoryCost},t=${timeCost},p=${parallelism}$${b64Salt}$${b64Hash}`;
}

/**
 * Parses an Argon2 Modular Crypt Format (MCF) string into its constituent parameters.
 *
 * @param {string} encodedString
 * @returns {Object} Parsed parameters
 */
export function parseEncodedHash(encodedString) {
  if (typeof encodedString !== 'string') {
    throw new TypeError('Encoded hash must be a string');
  }

  const parts = encodedString.split('$');
  // Expected structure: ["", "argon2id", "v=19", "m=65536,t=3,p=4", "<salt>", "<hash>"]
  // Note: Optional version "v=19" might be absent in older versions, but RFC 9106 specifies it.
  if (parts.length < 5 || parts[0] !== '') {
    throw new Error('Invalid encoded Argon2 hash format');
  }

  let index = 1;
  const type = parts[index++];
  let version = 19; // Default v1.3

  if (parts[index].startsWith('v=')) {
    version = parseInt(parts[index].slice(2), 10);
    index++;
  }

  const paramStr = parts[index++];
  const saltStr = parts[index++];
  const hashStr = parts[index++];

  const params = {};
  for (const pair of paramStr.split(',')) {
    const [k, v] = pair.split('=');
    params[k] = parseInt(v, 10);
  }

  return {
    type,
    version,
    memoryCost: params.m,
    timeCost: params.t,
    parallelism: params.p,
    salt: fromUnpaddedBase64(saltStr),
    hash: fromUnpaddedBase64(hashStr)
  };
}
