/**
 * @fileoverview HashForge Example: Production Authentication Flow with Seamless Rehashing.
 *
 * Demonstrates:
 * 1. Secure password hashing with salt generation during user registration.
 * 2. Constant-time password verification during user authentication.
 * 3. Transparent password hash upgrading (rehash) upon policy increases.
 */

import { hash, verify, needsRehash } from '../src/index.js';

// In-memory mock user database
const userDatabase = new Map();

// Current system security policy
const SECURITY_POLICY = {
  memoryCost: 19456, // ~19 MiB (OWASP recommended minimum)
  timeCost: 2,       // 2 iterations
  parallelism: 1     // Single lane for microservice / container
};

/**
 * Registers a new user with a hashed password.
 */
async function register(email, plaintextPassword) {
  if (userDatabase.has(email)) {
    throw new Error('User already exists');
  }

  // Hash password using HashForge (automatically generates a 16-byte cryptographic salt)
  const passwordHash = await hash(plaintextPassword, SECURITY_POLICY);

  // Store user record in database
  userDatabase.set(email, {
    email,
    passwordHash,
    createdAt: new Date().toISOString()
  });

  console.log(`[AUTH] User "${email}" registered successfully.`);
  console.log(`       Stored MCF Hash: ${passwordHash}\n`);
}

/**
 * Authenticates a user and seamlessly upgrades hash if policies have changed.
 */
async function login(email, candidatePassword, currentPolicy) {
  const user = userDatabase.get(email);
  if (!user) {
    console.log(`[AUTH] Login failed: User "${email}" not found.`);
    return false;
  }

  // Verify candidate password against stored hash in constant time
  const isValid = await verify(user.passwordHash, candidatePassword);
  if (!isValid) {
    console.log(`[AUTH] Login failed: Incorrect password for "${email}".\n`);
    return false;
  }

  console.log(`[AUTH] Login successful for "${email}".`);

  // Check if password hash needs an upgrade due to policy change
  if (needsRehash(user.passwordHash, currentPolicy)) {
    console.log(`[AUTH] Security policy upgraded. Transparently rehashing for "${email}"...`);
    user.passwordHash = await hash(candidatePassword, currentPolicy);
    console.log(`       New Upgraded Hash: ${user.passwordHash}`);
  }

  console.log();
  return true;
}

// -------------------------------------------------------------
// Interactive Simulation
// -------------------------------------------------------------
async function runDemo() {
  console.log('--- Step 1: User Registration ---');
  await register('alice@example.com', 'Super$ecretP@ssword2026!');

  console.log('--- Step 2: Failed Login Attempt ---');
  await login('alice@example.com', 'WrongPassword!', SECURITY_POLICY);

  console.log('--- Step 3: Successful Login ---');
  await login('alice@example.com', 'Super$ecretP@ssword2026!', SECURITY_POLICY);

  console.log('--- Step 4: Security Policy Upgrade Simulation ---');
  // Operations team upgrades memory and iteration cost
  const UPGRADED_POLICY = {
    memoryCost: 32768, // Upgraded to 32 MiB
    timeCost: 3,       // Upgraded to 3 passes
    parallelism: 1
  };
  console.log('[SYSTEM] Security policy updated to m=32768 KiB, t=3.');

  // Next user login will verify and automatically update the stored hash
  await login('alice@example.com', 'Super$ecretP@ssword2026!', UPGRADED_POLICY);

  // Subsequent login with the upgraded policy will not require another rehash
  console.log('--- Step 5: Subsequent Login with Upgraded Policy ---');
  await login('alice@example.com', 'Super$ecretP@ssword2026!', UPGRADED_POLICY);
}

runDemo().catch(console.error);
