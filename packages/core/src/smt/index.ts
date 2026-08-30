/**
 * @file packages/core/src/smt/index.ts
 * @description 256-bit Sparse Merkle Tree (SMT) Engine (DocuTrust v10.0.0)
 * Provides cryptographically verifiable key transparency logs, real-time revocation checking,
 * and compact logarithmic non-membership / inclusion proofs for EVM and off-chain verifiers.
 */

import * as crypto from 'crypto';
import { sha256Hex } from '../crypto/index.js';

export interface SMTProof {
  type: 'DocuTrustSparseMerkleProof2026';
  root: string;
  key: string;
  value: string;
  exists: boolean;
  siblings: Array<{
    depth: number;
    hash: string;
    isRight: boolean;
  }>;
}

export class SparseMerkleTree {
  private depth: number;
  private defaultHashes: string[];
  private db: Map<string, string>; // Maps path (bit prefix) to node hash
  private leafDb: Map<string, string>; // Maps keyHex to valueHex

  constructor(depth: number = 256) {
    this.depth = depth;
    this.db = new Map();
    this.leafDb = new Map();
    this.defaultHashes = this.computeDefaultHashes(depth);
  }

  /**
   * Precomputes zero-hashes for empty subtrees up to max depth.
   */
  private computeDefaultHashes(depth: number): string[] {
    const defaults: string[] = new Array(depth + 1);
    defaults[0] = '0000000000000000000000000000000000000000000000000000000000000000';
    for (let d = 1; d <= depth; d++) {
      const prev = defaults[d - 1];
      defaults[d] = this.hashChildren(prev, prev);
    }
    return defaults;
  }

  /**
   * Combines left and right child hashes.
   */
  private hashChildren(left: string, right: string): string {
    return sha256Hex(Buffer.from(`${left}:${right}`, 'hex'));
  }

  /**
   * Normalizes an arbitrary key string into a 64-character hex key (via sha256 if needed).
   */
  public static normalizeKey(key: string): string {
    const clean = key.replace(/^0x/, '');
    if (clean.length === 64 && /^[0-9a-fA-F]+$/.test(clean)) {
      return clean.toLowerCase();
    }
    return sha256Hex(Buffer.from(key, 'utf-8')).toLowerCase();
  }

  /**
   * Hashes a leaf key-value pair.
   */
  public static hashLeaf(keyHex: string, valueHex: string): string {
    const cleanKey = SparseMerkleTree.normalizeKey(keyHex);
    const cleanVal = valueHex.replace(/^0x/, '').toLowerCase();
    return sha256Hex(Buffer.from(`SMT_LEAF:${cleanKey}:${cleanVal}`, 'utf-8'));
  }

  /**
   * Converts a 64-char hex key into a 256-character binary bitstring.
   */
  private keyToBits(keyHex: string): string {
    const clean = SparseMerkleTree.normalizeKey(keyHex);
    let bits = '';
    for (let i = 0; i < clean.length; i++) {
      const nibble = parseInt(clean[i], 16);
      bits += nibble.toString(2).padStart(4, '0');
    }
    return bits.slice(0, this.depth);
  }

  /**
   * Inserts or updates a key-value entry in the Sparse Merkle Tree.
   */
  public set(keyHex: string, valueHex: string): void {
    const cleanKey = SparseMerkleTree.normalizeKey(keyHex);
    const cleanVal = valueHex.replace(/^0x/, '').toLowerCase();

    if (cleanVal === '' || cleanVal === '00' || cleanVal === '0'.repeat(64)) {
      this.leafDb.delete(cleanKey);
    } else {
      this.leafDb.set(cleanKey, cleanVal);
    }

    // Rebuild the path from leaf to root
    const bits = this.keyToBits(cleanKey);
    let currentHash = this.leafDb.has(cleanKey)
      ? SparseMerkleTree.hashLeaf(cleanKey, this.leafDb.get(cleanKey)!)
      : this.defaultHashes[0];

    let pathPrefix = bits;
    this.db.set(pathPrefix, currentHash);

    for (let d = 1; d <= this.depth; d++) {
      const bit = bits[this.depth - d];
      const parentPrefix = bits.slice(0, this.depth - d);
      const siblingBit = bit === '0' ? '1' : '0';
      const siblingPrefix = parentPrefix + siblingBit;

      const siblingHash = this.db.get(siblingPrefix) || this.defaultHashes[d - 1];

      if (bit === '0') {
        currentHash = this.hashChildren(currentHash, siblingHash);
      } else {
        currentHash = this.hashChildren(siblingHash, currentHash);
      }

      this.db.set(parentPrefix, currentHash);
    }
  }

  /**
   * Retrieves a value from the SMT by key.
   */
  public get(keyHex: string): string | null {
    const cleanKey = SparseMerkleTree.normalizeKey(keyHex);
    return this.leafDb.get(cleanKey) || null;
  }

  /**
   * Returns the current root hash of the Sparse Merkle Tree.
   */
  public getRoot(): string {
    return this.db.get('') || this.defaultHashes[this.depth];
  }

  /**
   * Generates a cryptographic audit proof for inclusion or non-membership.
   */
  public prove(keyHex: string): SMTProof {
    const cleanKey = SparseMerkleTree.normalizeKey(keyHex);
    const value = this.leafDb.get(cleanKey) || '0'.repeat(64);
    const exists = this.leafDb.has(cleanKey);
    const bits = this.keyToBits(cleanKey);

    const siblings: Array<{ depth: number; hash: string; isRight: boolean }> = [];

    for (let d = 1; d <= this.depth; d++) {
      const bit = bits[this.depth - d];
      const parentPrefix = bits.slice(0, this.depth - d);
      const siblingBit = bit === '0' ? '1' : '0';
      const siblingPrefix = parentPrefix + siblingBit;

      const siblingHash = this.db.get(siblingPrefix) || this.defaultHashes[d - 1];

      // Only include non-empty default hashes if needed or all siblings for deterministic audit
      siblings.push({
        depth: d,
        hash: siblingHash,
        isRight: bit === '0' // If current is left (0), sibling is right
      });
    }

    return {
      type: 'DocuTrustSparseMerkleProof2026',
      root: this.getRoot(),
      key: cleanKey,
      value,
      exists,
      siblings
    };
  }

  /**
   * Cryptographically verifies an SMT inclusion or non-membership proof.
   */
  public static verifyProof(proof: SMTProof, expectedRoot?: string): boolean {
    if (!proof || proof.type !== 'DocuTrustSparseMerkleProof2026') {
      return false;
    }

    const cleanKey = proof.key.replace(/^0x/, '').padStart(64, '0').toLowerCase();
    const cleanVal = proof.value.replace(/^0x/, '').toLowerCase();
    const targetRoot = (expectedRoot || proof.root).replace(/^0x/, '').toLowerCase();

    // Reconstruct leaf hash
    let currentHash = proof.exists
      ? SparseMerkleTree.hashLeaf(cleanKey, cleanVal)
      : '0000000000000000000000000000000000000000000000000000000000000000';

    for (const sib of proof.siblings) {
      if (sib.isRight) {
        // Current is Left, Sibling is Right
        currentHash = sha256Hex(Buffer.from(`${currentHash}:${sib.hash}`, 'hex'));
      } else {
        // Sibling is Left, Current is Right
        currentHash = sha256Hex(Buffer.from(`${sib.hash}:${currentHash}`, 'hex'));
      }
    }

    return currentHash.toLowerCase() === targetRoot;
  }
}
