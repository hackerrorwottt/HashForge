/**
 * @fileoverview HashForge Performance Benchmarking Suite.
 *
 * Measures:
 * 1. Low-level cryptographic primitives:
 *    - BLAKE2b (MB/s)
 *    - BlaMka 64-bit integer mixing (ops/sec)
 *    - Compression Function G (1024-byte blocks/sec)
 * 2. Argon2id end-to-end hashing across standard profiles:
 *    - Test profile: m=64 KiB, t=1, p=1
 *    - Lightweight profile: m=1024 KiB (1 MiB), t=1, p=1
 *    - Moderate profile: m=8192 KiB (8 MiB), t=2, p=2
 *    - OWASP minimum: m=19456 KiB (~19 MiB), t=2, p=1
 */

import { performance } from 'node:perf_hooks';
import { blake2b } from '../src/crypto/blake2b.js';
import { fBlaMka, compressBlock } from '../src/core/compression.js';
import { hash, verify } from '../src/index.js';

console.log('='.repeat(70));
console.log('           HashForge Argon2id Performance Benchmark');
console.log('='.repeat(70));
console.log(`Node.js: ${process.version} | V8 Engine | Platform: ${process.platform} (${process.arch})\n`);

// -------------------------------------------------------------
// 1. Primitive Benchmarks
// -------------------------------------------------------------
console.log('--- 1. Cryptographic Primitives ---');

// BLAKE2b Throughput
{
  const chunk = new Uint8Array(64 * 1024); // 64 KiB
  chunk.fill(0x5a);
  const iters = 200;
  const start = performance.now();
  for (let i = 0; i < iters; i++) {
    blake2b(chunk, null, 64);
  }
  const elapsedMs = performance.now() - start;
  const totalMB = (iters * 64) / 1024;
  const mbps = (totalMB / (elapsedMs / 1000)).toFixed(2);
  console.log(`BLAKE2b (512-bit, 64 KiB inputs) : ${mbps} MB/s (${elapsedMs.toFixed(1)} ms for ${totalMB} MB)`);
}

// BlaMka Throughput
{
  let x = 0x123456789abcdef0n;
  let y = 0xfedcba9876543210n;
  const iters = 1_000_000;
  const start = performance.now();
  for (let i = 0; i < iters; i++) {
    x = fBlaMka(x, y);
    y ^= x;
  }
  const elapsedMs = performance.now() - start;
  const mops = ((iters / (elapsedMs / 1000)) / 1_000_000).toFixed(2);
  console.log(`BlaMka 64-bit non-linear mixing   : ${mops} Million ops/sec (${elapsedMs.toFixed(1)} ms for 1M ops)`);
}

// Function G (1024-byte block compression)
{
  const X = new BigUint64Array(128);
  const Y = new BigUint64Array(128);
  const dest = new BigUint64Array(128);
  const scratch = new BigUint64Array(128);
  X.fill(0x1111111111111111n);
  Y.fill(0x2222222222222222n);

  const iters = 20_000;
  const start = performance.now();
  for (let i = 0; i < iters; i++) {
    compressBlock(X, Y, dest, false, scratch);
  }
  const elapsedMs = performance.now() - start;
  const blocksPerSec = Math.round(iters / (elapsedMs / 1000));
  const throughputMBps = ((iters * 1024) / (1024 * 1024) / (elapsedMs / 1000)).toFixed(2);
  console.log(`Function G (1024-byte block)      : ${blocksPerSec.toLocaleString()} blocks/sec (${throughputMBps} MB/s)`);
}

// -------------------------------------------------------------
// 2. Argon2id End-to-End Benchmarks
// -------------------------------------------------------------
console.log('\n--- 2. End-to-End Argon2id Hashing Profiles ---');

const profiles = [
  { name: 'Ultra-Fast (Testing)', memoryCost: 64, timeCost: 1, parallelism: 1, runs: 50 },
  { name: 'Lightweight (Mobile/IoT)', memoryCost: 1024, timeCost: 1, parallelism: 1, runs: 10 },
  { name: 'Microservice Default', memoryCost: 4096, timeCost: 2, parallelism: 2, runs: 5 },
  { name: 'OWASP Minimum Recom.', memoryCost: 19456, timeCost: 2, parallelism: 1, runs: 2 }
];

for (const profile of profiles) {
  const times = [];
  let sampleHash = '';

  for (let r = 0; r < profile.runs; r++) {
    const start = performance.now();
    sampleHash = await hash('BenchmarkPassword2026!', {
      memoryCost: profile.memoryCost,
      timeCost: profile.timeCost,
      parallelism: profile.parallelism
    });
    times.push(performance.now() - start);
  }

  const avgMs = (times.reduce((a, b) => a + b, 0) / times.length).toFixed(1);
  const minMs = Math.min(...times).toFixed(1);
  const maxMs = Math.max(...times).toFixed(1);

  // Measure single verify pass
  const verifyStart = performance.now();
  await verify(sampleHash, 'BenchmarkPassword2026!');
  const verifyMs = (performance.now() - verifyStart).toFixed(1);

  console.log(`\n• ${profile.name}`);
  console.log(`  Params : m=${profile.memoryCost} KiB (${(profile.memoryCost / 1024).toFixed(1)} MiB), t=${profile.timeCost}, p=${profile.parallelism}`);
  console.log(`  Hash   : Avg: ${avgMs} ms | Min: ${minMs} ms | Max: ${maxMs} ms (over ${profile.runs} runs)`);
  console.log(`  Verify : ${verifyMs} ms`);
}

console.log('\n' + '='.repeat(70));
console.log('Benchmark completed successfully.');
console.log('='.repeat(70));
