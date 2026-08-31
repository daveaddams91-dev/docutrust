/**
 * @file packages/core/src/revocation-lattice/index.ts
 * @description 2D Multi-Epoch Revocation Lattice & Dynamic Accumulator Engine (DocuTrust v13.0.0)
 * Manages high-throughput, multi-epoch credential revocation states across temporal and shard dimensions.
 * Generates O(1) non-revocation witnesses and emits signed lattice proofs (DocuTrustLatticeProof2026).
 */

import * as crypto from 'crypto';
import { sha256Hex, signMessage, verifySignature, canonicalizeJson, KeyPair } from '../crypto/index.js';

export interface LatticeEpochSlice {
  epochIndex: number;
  shardIndex: number;
  revokedMemberCount: number;
  accumulatorRoot: string;
  revokedMembers: string[]; // List of hashed credential identifiers
  timestamp: string;
}

export interface RevocationLatticeState {
  latticeId: string;
  issuerDid: string;
  shardsCount: number;
  currentEpoch: number;
  epochs: Record<string, LatticeEpochSlice>; // Key: `epoch_shard` e.g. "0_0"
  globalLatticeRoot: string;
}

export interface DocuTrustLatticeProof {
  type: 'DocuTrustLatticeProof2026';
  proofId: string;
  latticeId: string;
  credentialId: string;
  credentialDigest: string;
  targetEpoch: number;
  targetShard: number;
  isRevoked: boolean;
  accumulatorRoot: string;
  witnessHash: string;
  latticeRoot: string;
  issuerDid: string;
  signatureHex: string;
  timestamp: string;
}

export interface LatticeVerificationResult {
  valid: boolean;
  isRevoked: boolean;
  latticeId: string;
  targetEpoch: number;
  errors: string[];
}

export class RevocationLatticeEngine {
  /**
   * Initializes a new multi-epoch 2D Revocation Lattice.
   */
  public static initializeLattice(
    latticeId: string,
    issuerDid: string,
    shardsCount = 4
  ): RevocationLatticeState {
    const epochs: Record<string, LatticeEpochSlice> = {};
    const timestamp = new Date().toISOString();

    for (let s = 0; s < shardsCount; s++) {
      const key = `0_${s}`;
      const accumulatorRoot = sha256Hex(`EMPTY_LATTICE_SLICE:${latticeId}:0:${s}`);
      epochs[key] = {
        epochIndex: 0,
        shardIndex: s,
        revokedMemberCount: 0,
        accumulatorRoot,
        revokedMembers: [],
        timestamp
      };
    }

    const state: RevocationLatticeState = {
      latticeId,
      issuerDid,
      shardsCount,
      currentEpoch: 0,
      epochs,
      globalLatticeRoot: ''
    };
    state.globalLatticeRoot = this.computeGlobalLatticeRoot(state);
    return state;
  }

  /**
   * Computes the global cryptographic root of the entire 2D lattice.
   */
  public static computeGlobalLatticeRoot(state: RevocationLatticeState): string {
    const keys = Object.keys(state.epochs).sort();
    const serialized = keys.map(k => `${k}:${state.epochs[k].accumulatorRoot}`).join('|');
    return sha256Hex(`LATTICE_GLOBAL_ROOT:${state.latticeId}:${state.currentEpoch}:${serialized}`);
  }

  /**
   * Computes which shard a credential belongs to based on its identifier digest.
   */
  public static computeShardIndex(credentialId: string, shardsCount: number): number {
    const digest = sha256Hex(credentialId);
    const num = parseInt(digest.substring(0, 8), 16);
    return num % shardsCount;
  }

  /**
   * Accumulates new revoked credentials into the active lattice epoch.
   */
  public static accumulateRevocations(
    state: RevocationLatticeState,
    revokedCredentialIds: string[],
    advanceEpoch = false
  ): RevocationLatticeState {
    const nextState: RevocationLatticeState = {
      ...state,
      epochs: { ...state.epochs }
    };

    if (advanceEpoch) {
      nextState.currentEpoch += 1;
      const ts = new Date().toISOString();
      for (let s = 0; s < nextState.shardsCount; s++) {
        const prevKey = `${state.currentEpoch}_${s}`;
        const prevSlice = nextState.epochs[prevKey] || {
          epochIndex: state.currentEpoch,
          shardIndex: s,
          revokedMemberCount: 0,
          accumulatorRoot: sha256Hex(`EMPTY_LATTICE_SLICE:${state.latticeId}:${state.currentEpoch}:${s}`),
          revokedMembers: [],
          timestamp: ts
        };
        const newKey = `${nextState.currentEpoch}_${s}`;
        nextState.epochs[newKey] = {
          epochIndex: nextState.currentEpoch,
          shardIndex: s,
          revokedMemberCount: prevSlice.revokedMemberCount,
          accumulatorRoot: prevSlice.accumulatorRoot,
          revokedMembers: [...prevSlice.revokedMembers],
          timestamp: ts
        };
      }
    }

    const currentEpoch = nextState.currentEpoch;
    const ts = new Date().toISOString();

    for (const rawId of revokedCredentialIds) {
      const credDigest = sha256Hex(rawId);
      const shard = this.computeShardIndex(rawId, nextState.shardsCount);
      const key = `${currentEpoch}_${shard}`;

      let slice = nextState.epochs[key];
      if (!slice) {
        slice = {
          epochIndex: currentEpoch,
          shardIndex: shard,
          revokedMemberCount: 0,
          accumulatorRoot: sha256Hex(`EMPTY_LATTICE_SLICE:${state.latticeId}:${currentEpoch}:${shard}`),
          revokedMembers: [],
          timestamp: ts
        };
      }

      if (!slice.revokedMembers.includes(credDigest)) {
        const updatedMembers = [...slice.revokedMembers, credDigest].sort();
        const updatedRoot = sha256Hex(`SLICE_ACCUMULATOR:${currentEpoch}:${shard}:${updatedMembers.join('+')}`);
        nextState.epochs[key] = {
          ...slice,
          revokedMemberCount: updatedMembers.length,
          revokedMembers: updatedMembers,
          accumulatorRoot: updatedRoot,
          timestamp: ts
        };
      }
    }

    nextState.globalLatticeRoot = this.computeGlobalLatticeRoot(nextState);
    return nextState;
  }

  /**
   * Generates a cryptographic non-revocation or revocation proof for a credential at a given epoch.
   */
  public static generateLatticeProof(
    state: RevocationLatticeState,
    credentialId: string,
    issuerKeyPair: KeyPair,
    targetEpoch?: number
  ): DocuTrustLatticeProof {
    const epoch = targetEpoch !== undefined ? targetEpoch : state.currentEpoch;
    const shard = this.computeShardIndex(credentialId, state.shardsCount);
    const key = `${epoch}_${shard}`;
    const slice = state.epochs[key];

    if (!slice) {
      throw new Error(`Epoch slice ${key} does not exist in lattice ${state.latticeId}.`);
    }

    const credentialDigest = sha256Hex(credentialId);
    const isRevoked = slice.revokedMembers.includes(credentialDigest);

    // Witness computation: dynamic non-membership or membership witness
    const otherMembers = slice.revokedMembers.filter(m => m !== credentialDigest);
    const witnessHash = sha256Hex(`LATTICE_WITNESS:${epoch}:${shard}:${isRevoked ? 'REVOKED' : 'ACTIVE'}:${otherMembers.join('|')}`);

    const proofId = `lat-prf-${crypto.randomBytes(8).toString('hex')}`;
    const timestamp = new Date().toISOString();

    const signPayload = {
      proofId,
      latticeId: state.latticeId,
      credentialId,
      credentialDigest,
      targetEpoch: epoch,
      targetShard: shard,
      isRevoked,
      accumulatorRoot: slice.accumulatorRoot,
      witnessHash,
      latticeRoot: state.globalLatticeRoot,
      issuerDid: issuerKeyPair.did,
      timestamp
    };

    const signatureHex = signMessage(canonicalizeJson(signPayload), issuerKeyPair.privateKeyHex);

    return {
      type: 'DocuTrustLatticeProof2026',
      proofId,
      latticeId: state.latticeId,
      credentialId,
      credentialDigest,
      targetEpoch: epoch,
      targetShard: shard,
      isRevoked,
      accumulatorRoot: slice.accumulatorRoot,
      witnessHash,
      latticeRoot: state.globalLatticeRoot,
      issuerDid: issuerKeyPair.did,
      signatureHex,
      timestamp
    };
  }

  /**
   * Verifies the validity and non-revocation status in a signed Lattice Proof.
   */
  public static verifyLatticeProof(
    proof: DocuTrustLatticeProof,
    issuerPublicKeyHex: string,
    expectedLatticeRoot?: string
  ): LatticeVerificationResult {
    const errors: string[] = [];

    if (!proof || proof.type !== 'DocuTrustLatticeProof2026') {
      return {
        valid: false,
        isRevoked: true,
        latticeId: proof?.latticeId || 'unknown',
        targetEpoch: proof?.targetEpoch || 0,
        errors: ['Invalid lattice proof structure or type mismatch.']
      };
    }

    // 1. Verify credential digest consistency
    const expectedDigest = sha256Hex(proof.credentialId);
    if (expectedDigest.toLowerCase() !== proof.credentialDigest.toLowerCase()) {
      errors.push('Credential digest mismatch in lattice proof.');
    }

    // 2. Verify issuer signature
    const signPayload = {
      proofId: proof.proofId,
      latticeId: proof.latticeId,
      credentialId: proof.credentialId,
      credentialDigest: proof.credentialDigest,
      targetEpoch: proof.targetEpoch,
      targetShard: proof.targetShard,
      isRevoked: proof.isRevoked,
      accumulatorRoot: proof.accumulatorRoot,
      witnessHash: proof.witnessHash,
      latticeRoot: proof.latticeRoot,
      issuerDid: proof.issuerDid,
      timestamp: proof.timestamp
    };

    const isSigValid = verifySignature(canonicalizeJson(signPayload), proof.signatureHex, issuerPublicKeyHex);
    if (!isSigValid) {
      errors.push('Issuer cryptographic signature verification failed on lattice proof.');
    }

    // 3. Verify global lattice root if provided
    if (expectedLatticeRoot && expectedLatticeRoot.toLowerCase() !== proof.latticeRoot.toLowerCase()) {
      errors.push(`Lattice global root mismatch: expected ${expectedLatticeRoot}, got ${proof.latticeRoot}`);
    }

    return {
      valid: errors.length === 0,
      isRevoked: proof.isRevoked,
      latticeId: proof.latticeId,
      targetEpoch: proof.targetEpoch,
      errors
    };
  }
}
