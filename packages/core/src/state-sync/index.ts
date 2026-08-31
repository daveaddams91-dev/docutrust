/**
 * @file packages/core/src/state-sync/index.ts
 * @description Cross-Ledger Sovereign Registry StateSync & Delta Proof Engine (DocuTrust v12.0.0)
 * Computes compact cryptographic Delta Proofs between distributed registry replicas across chains
 * (EVM, Solana, DIDComm mesh, offline caches) in O(Δ) time without transferring full ledger history.
 */

import * as crypto from 'crypto';
import { sha256Hex, signMessage, verifySignature, canonicalizeJson, KeyPair } from '../crypto/index.js';

export interface RegistryStateRecord {
  entityDid: string;
  status: 'ACTIVE' | 'REVOKED' | 'SUSPENDED';
  accreditationLevel: number;
  updatedEpoch: number;
  metadataHash: string;
}

export interface StateDeltaEntry {
  action: 'UPSERT' | 'REVOKE' | 'DELETE';
  entityDid: string;
  previousHash?: string;
  newRecord: RegistryStateRecord;
}

export interface DocuTrustDeltaProof {
  type: 'DocuTrustDeltaProof2026';
  syncId: string;
  sourceChainOrMesh: string;
  destinationChainOrMesh: string;
  baseStateRoot: string;
  targetStateRoot: string;
  deltaCount: number;
  deltas: StateDeltaEntry[];
  deltaCommitment: string;
  relayerDid: string;
  signatureHex: string;
  timestamp: string;
}

export class StateSyncEngine {
  /**
   * Computes the cryptographic root hash for a given snapshot of registry records.
   */
  public static computeStateRoot(records: Record<string, RegistryStateRecord>): string {
    const keys = Object.keys(records).sort();
    if (keys.length === 0) {
      return sha256Hex('EMPTY_REGISTRY_STATE');
    }
    const serialized = keys.map(k => `${k}:${canonicalizeJson(records[k])}`).join('|');
    return sha256Hex(serialized);
  }

  /**
   * Generates a compact State Delta Proof between base and target registry states.
   */
  public static generateDeltaProof(
    baseState: Record<string, RegistryStateRecord>,
    targetState: Record<string, RegistryStateRecord>,
    relayerKeyPair: KeyPair,
    route: { source?: string; destination?: string } = { source: 'Mesh:Source', destination: 'Mesh:Destination' }
  ): DocuTrustDeltaProof {
    const baseStateRoot = this.computeStateRoot(baseState);
    const targetStateRoot = this.computeStateRoot(targetState);
    const sourceChainOrMesh = route.source || 'Mesh:Source';
    const destinationChainOrMesh = route.destination || 'Mesh:Destination';

    const deltas: StateDeltaEntry[] = [];

    // Detect additions and modifications
    for (const [did, targetRecord] of Object.entries(targetState)) {
      const baseRecord = baseState[did];
      if (!baseRecord) {
        deltas.push({
          action: 'UPSERT',
          entityDid: did,
          newRecord: targetRecord
        });
      } else {
        const baseHash = sha256Hex(canonicalizeJson(baseRecord));
        const targetHash = sha256Hex(canonicalizeJson(targetRecord));
        if (baseHash !== targetHash) {
          deltas.push({
            action: targetRecord.status === 'REVOKED' ? 'REVOKE' : 'UPSERT',
            entityDid: did,
            previousHash: baseHash,
            newRecord: targetRecord
          });
        }
      }
    }

    // Detect deletions
    for (const [did, baseRecord] of Object.entries(baseState)) {
      if (!targetState[did]) {
        deltas.push({
          action: 'DELETE',
          entityDid: did,
          previousHash: sha256Hex(canonicalizeJson(baseRecord)),
          newRecord: {
            entityDid: did,
            status: 'REVOKED',
            accreditationLevel: 0,
            updatedEpoch: Math.floor(Date.now() / 1000),
            metadataHash: sha256Hex('DELETED')
          }
        });
      }
    }

    const deltaCommitment = sha256Hex(canonicalizeJson(deltas));
    const syncId = `sync-${crypto.randomBytes(8).toString('hex')}`;
    const timestamp = new Date().toISOString();

    const signPayload = {
      syncId,
      sourceChainOrMesh,
      destinationChainOrMesh,
      baseStateRoot,
      targetStateRoot,
      deltaCount: deltas.length,
      deltaCommitment,
      relayerDid: relayerKeyPair.did,
      timestamp
    };

    const signatureHex = signMessage(canonicalizeJson(signPayload), relayerKeyPair.privateKeyHex);

    return {
      type: 'DocuTrustDeltaProof2026',
      syncId,
      sourceChainOrMesh,
      destinationChainOrMesh,
      baseStateRoot,
      targetStateRoot,
      deltaCount: deltas.length,
      deltas,
      deltaCommitment,
      relayerDid: relayerKeyPair.did,
      signatureHex,
      timestamp
    };
  }

  /**
   * Applies and cryptographically verifies a Delta Proof against a local base state.
   */
  public static applyAndVerifyDelta(
    currentState: Record<string, RegistryStateRecord>,
    proof: DocuTrustDeltaProof,
    relayerPublicKeyHex: string
  ): {
    valid: boolean;
    newState?: Record<string, RegistryStateRecord>;
    computedTargetRoot?: string;
    errors: string[];
  } {
    const errors: string[] = [];

    if (!proof || proof.type !== 'DocuTrustDeltaProof2026') {
      return { valid: false, errors: ['Invalid state delta proof type.'] };
    }

    // Verify relayer signature
    const signPayload = {
      syncId: proof.syncId,
      sourceChainOrMesh: proof.sourceChainOrMesh,
      destinationChainOrMesh: proof.destinationChainOrMesh,
      baseStateRoot: proof.baseStateRoot,
      targetStateRoot: proof.targetStateRoot,
      deltaCount: proof.deltaCount,
      deltaCommitment: proof.deltaCommitment,
      relayerDid: proof.relayerDid,
      timestamp: proof.timestamp
    };

    const isSigValid = verifySignature(canonicalizeJson(signPayload), proof.signatureHex, relayerPublicKeyHex);
    if (!isSigValid) {
      errors.push('Relayer cryptographic signature verification failed on state delta proof.');
    }

    // Verify base root alignment
    const actualBaseRoot = this.computeStateRoot(currentState);
    if (actualBaseRoot.toLowerCase() !== proof.baseStateRoot.toLowerCase()) {
      errors.push(`Local base state root mismatch: expected ${proof.baseStateRoot}, computed ${actualBaseRoot}`);
    }

    // Verify delta commitment
    const actualDeltaCommitment = sha256Hex(canonicalizeJson(proof.deltas));
    if (actualDeltaCommitment.toLowerCase() !== proof.deltaCommitment.toLowerCase()) {
      errors.push('Delta commitment does not match deltas array payload.');
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    // Clone state and apply deltas
    const nextState: Record<string, RegistryStateRecord> = { ...currentState };
    for (const delta of proof.deltas) {
      if (delta.action === 'DELETE') {
        delete nextState[delta.entityDid];
      } else {
        nextState[delta.entityDid] = delta.newRecord;
      }
    }

    const computedTargetRoot = this.computeStateRoot(nextState);
    if (computedTargetRoot.toLowerCase() !== proof.targetStateRoot.toLowerCase()) {
      errors.push(`Target state root mismatch after applying deltas: expected ${proof.targetStateRoot}, computed ${computedTargetRoot}`);
    }

    return {
      valid: errors.length === 0,
      newState: errors.length === 0 ? nextState : undefined,
      computedTargetRoot,
      errors
    };
  }
}
