/**
 * HashForge — Independent Argon2id Password Hashing Engine (RFC 9106)
 *
 * @module hashforge
 */

export { hash } from './api/hash.js';
export { verify } from './api/verify.js';
export { needsRehash } from './api/needsRehash.js';

export {
  ARGON2_TYPES,
  ARGON2_VERSIONS,
  DEFAULTS,
  LIMITS
} from './constants/index.js';
