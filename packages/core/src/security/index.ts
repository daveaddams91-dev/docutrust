import * as crypto from 'crypto';

/**
 * Constant-Time String Comparison using crypto.timingSafeEqual
 * Prevents side-channel timing attacks that leak signature bytes or hashes.
 */
export function constantTimeCompare(a: string | Buffer, b: string | Buffer): boolean {
  const bufA = typeof a === 'string' ? Buffer.from(a, 'utf-8') : a;
  const bufB = typeof b === 'string' ? Buffer.from(b, 'utf-8') : b;

  if (bufA.length !== bufB.length) {
    // Perform dummy constant time compare to prevent length leakage
    const dummy = Buffer.alloc(bufA.length);
    crypto.timingSafeEqual(bufA, dummy);
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Constant-Time Hex Comparison
 */
export function constantTimeCompareHex(hexA: string, hexB: string): boolean {
  const cleanA = hexA.toLowerCase().replace(/^0x/, '');
  const cleanB = hexB.toLowerCase().replace(/^0x/, '');
  return constantTimeCompare(cleanA, cleanB);
}

/**
 * Deep Prototype Pollution & Injection Defense
 * Recursively strips dangerous object prototype properties (__proto__, constructor, prototype).
 */
export function sanitizeJsonPayload<T = any>(input: any, maxDepth: number = 20): T {
  if (input === null || typeof input !== 'object') {
    return input;
  }

  if (maxDepth <= 0) {
    throw new Error('JSON payload exceeds maximum allowed nesting depth (possible cyclic or recursion attack).');
  }

  if (Array.isArray(input)) {
    return input.map(item => sanitizeJsonPayload(item, maxDepth - 1)) as any;
  }

  const cleanObj: Record<string, any> = Object.create(null);
  const dangerousKeys = new Set(['__proto__', 'constructor', 'prototype']);

  for (const key of Object.keys(input)) {
    if (dangerousKeys.has(key)) {
      continue; // Block prototype pollution attempt
    }
    cleanObj[key] = sanitizeJsonPayload(input[key], maxDepth - 1);
  }

  return cleanObj as T;
}

/**
 * Shannon Entropy Calculator
 * Verifies that generated salts, private keys, and nonces possess sufficient cryptographic randomness.
 */
export function calculateShannonEntropy(data: Buffer | string): number {
  const buf = typeof data === 'string' ? Buffer.from(data, 'hex') : data;
  if (buf.length === 0) return 0;

  const frequencies: { [byte: number]: number } = {};
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    frequencies[byte] = (frequencies[byte] || 0) + 1;
  }

  let entropy = 0;
  for (const byte in frequencies) {
    const p = frequencies[byte] / buf.length;
    entropy -= p * Math.log2(p);
  }

  return entropy; // Value between 0 and 8 bits per byte
}

/**
 * Validates that private key or salt has at least 3.5 bits/byte of Shannon entropy.
 */
export function validateCryptographicEntropy(hexString: string, minEntropy: number = 3.5): boolean {
  const buf = Buffer.from(hexString, 'hex');
  if (buf.length < 16) return false;
  return calculateShannonEntropy(buf) >= minEntropy;
}

/**
 * Replay Attack Prevention Guard
 * Enforces cryptographic timestamp window (default max 5 minutes) and nonce uniqueness.
 */
export class AntiReplayGuard {
  private static seenNonces: Map<string, number> = new Map();
  private static maxDriftMs: number = 300000; // 5 minutes

  public static validateRequest(nonce: string, timestamp: number | string): { valid: boolean; error?: string } {
    const reqTime = typeof timestamp === 'string' ? new Date(timestamp).getTime() : timestamp;
    const now = Date.now();

    // 1. Timestamp Drift check
    if (Math.abs(now - reqTime) > this.maxDriftMs) {
      return { valid: false, error: 'Timestamp drift exceeded allowable window (possible replay attack).' };
    }

    // 2. Nonce Uniqueness check
    if (this.seenNonces.has(nonce)) {
      return { valid: false, error: 'Cryptographic nonce already used (replay attack detected).' };
    }

    // Record nonce and cleanup old entries
    this.seenNonces.set(nonce, now);
    this.cleanupOldNonces(now);

    return { valid: true };
  }

  private static cleanupOldNonces(now: number): void {
    if (this.seenNonces.size > 50000) {
      for (const [nonce, time] of this.seenNonces.entries()) {
        if (now - time > this.maxDriftMs) {
          this.seenNonces.delete(nonce);
        }
      }
    }
  }
}

/**
 * Double SHA-256 Hash (Bitcoin-Grade Anti-Extension Hashing)
 */
export function doubleSha256Hex(data: string | Buffer): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  const first = crypto.createHash('sha256').update(buf).digest();
  return crypto.createHash('sha256').update(first).digest('hex');
}
