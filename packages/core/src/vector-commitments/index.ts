/**
 * @file packages/core/src/vector-commitments/index.ts
 * @description Succinct Vector Commitments & Subvector Openings Engine (DocuTrust v19.0.0)
 * Implements O(1) constant-size vector commitments, single-position proofs,
 * and aggregated subvector opening proofs for high-throughput batch credential validation.
 */

import * as crypto from 'crypto';
import { canonicalizeJson, sha256Hex } from '../crypto';

export const VC_PRIME = BigInt('0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47'); // BN254 scalar field

export interface VectorCRS {
  maxVectorLength: number;
  generatorSeed: string;
  generatorsHex: string[];
  crsHash: string;
}

export interface VectorCommitment {
  type: 'DocuTrustVectorCommitment2026';
  commitmentId: string;
  vectorLength: number;
  commitmentHex: string;
  crsHash: string;
  stateHash: string;
}

export interface PositionOpeningProof {
  index: number; // 0-indexed position
  valueHex: string;
  proofHex: string;
  commitmentHex: string;
}

export interface SubvectorOpeningProof {
  type: 'DocuTrustSubvectorProof2026';
  proofId: string;
  commitmentHex: string;
  indices: number[];
  valuesHex: string[];
  aggregatedProofHex: string;
  crsHash: string;
  proofHash: string;
}

export class VectorCommitmentEngine {
  private static crsCache: Map<number, VectorCRS> = new Map();

  /**
   * Derives a deterministic generator scalar for index i from a base seed.
   */
  public static deriveGenerator(seed: string, index: number): bigint {
    const hash = sha256Hex(`VC_SRS_GEN_V19:${seed}:${index}`);
    return BigInt('0x' + hash) % VC_PRIME;
  }

  /**
   * Generates public Structured Reference String (CRS) up to maxVectorLength.
   */
  public static generateCRS(maxVectorLength: number = 64, seed: string = 'docutrust_srs_master_seed_v19'): VectorCRS {
    if (this.crsCache.has(maxVectorLength)) {
      return this.crsCache.get(maxVectorLength)!;
    }

    const generatorsHex: string[] = [];
    for (let i = 0; i < maxVectorLength; i++) {
      const g = this.deriveGenerator(seed, i);
      generatorsHex.push(g.toString(16).padStart(64, '0'));
    }

    const crsHash = sha256Hex(canonicalizeJson({
      maxVectorLength,
      seed,
      generatorSample: generatorsHex.slice(0, 4)
    }));

    const crs: VectorCRS = {
      maxVectorLength,
      generatorSeed: seed,
      generatorsHex,
      crsHash
    };

    this.crsCache.set(maxVectorLength, crs);
    return crs;
  }

  /**
   * Maps an arbitrary value (string, number, object) to a field scalar in VC_PRIME.
   */
  public static toScalar(val: any): bigint {
    if (typeof val === 'bigint') return (val % VC_PRIME + VC_PRIME) % VC_PRIME;
    if (typeof val === 'number') return BigInt(val) % VC_PRIME;
    const str = typeof val === 'string' ? val : canonicalizeJson(val);
    const hash = sha256Hex(str);
    return BigInt('0x' + hash) % VC_PRIME;
  }

  /**
   * Commits to an ordered array of attributes vector = [a_0, a_1, ..., a_{N-1}].
   */
  public static commit(vector: any[], crs?: VectorCRS): VectorCommitment {
    const effectiveCRS = crs || this.generateCRS(Math.max(vector.length, 16));
    if (vector.length > effectiveCRS.maxVectorLength) {
      throw new Error(`Vector length ${vector.length} exceeds CRS capacity ${effectiveCRS.maxVectorLength}`);
    }

    let commitmentVal = 0n;
    const scalarList: bigint[] = [];

    for (let i = 0; i < vector.length; i++) {
      const ai = this.toScalar(vector[i]);
      scalarList.push(ai);
      const gi = BigInt('0x' + effectiveCRS.generatorsHex[i]);
      commitmentVal = (commitmentVal + ai * gi) % VC_PRIME;
    }

    const commitmentHex = commitmentVal.toString(16).padStart(64, '0');
    const commitmentId = 'vcom_' + sha256Hex(`vc:${commitmentHex}:${Date.now()}`).substring(0, 16);

    const stateHash = sha256Hex(canonicalizeJson({
      commitmentId,
      vectorLength: vector.length,
      commitmentHex,
      crsHash: effectiveCRS.crsHash
    }));

    return {
      type: 'DocuTrustVectorCommitment2026',
      commitmentId,
      vectorLength: vector.length,
      commitmentHex,
      crsHash: effectiveCRS.crsHash,
      stateHash
    };
  }

  /**
   * Generates an individual position opening proof for index i.
   */
  public static provePosition(vector: any[], index: number, crs?: VectorCRS): PositionOpeningProof {
    if (index < 0 || index >= vector.length) {
      throw new Error(`Index out of bounds: ${index} (length: ${vector.length})`);
    }

    const effectiveCRS = crs || this.generateCRS(Math.max(vector.length, 16));
    const targetVal = this.toScalar(vector[index]);

    // Proof witness = sum_{j != index} a_j * g_j mod p
    let witnessVal = 0n;
    for (let j = 0; j < vector.length; j++) {
      if (j === index) continue;
      const aj = this.toScalar(vector[j]);
      const gj = BigInt('0x' + effectiveCRS.generatorsHex[j]);
      witnessVal = (witnessVal + aj * gj) % VC_PRIME;
    }

    const commitment = this.commit(vector, effectiveCRS);

    return {
      index,
      valueHex: targetVal.toString(16).padStart(64, '0'),
      proofHex: witnessVal.toString(16).padStart(64, '0'),
      commitmentHex: commitment.commitmentHex
    };
  }

  /**
   * Verifies an individual position opening proof.
   */
  public static verifyPosition(
    commitmentHex: string,
    proof: PositionOpeningProof,
    crs?: VectorCRS
  ): { valid: boolean; error?: string } {
    const effectiveCRS = crs || this.generateCRS(Math.max(proof.index + 1, 16));
    if (proof.index >= effectiveCRS.maxVectorLength) {
      return { valid: false, error: 'Index exceeds CRS capacity' };
    }

    const gi = BigInt('0x' + effectiveCRS.generatorsHex[proof.index]);
    const ai = BigInt('0x' + proof.valueHex);
    const witness = BigInt('0x' + proof.proofHex);
    const targetCommitment = BigInt('0x' + commitmentHex);

    const reconstructed = (witness + ai * gi) % VC_PRIME;
    if (reconstructed !== targetCommitment) {
      return { valid: false, error: 'Position opening proof mismatch' };
    }

    return { valid: true };
  }

  /**
   * Generates an aggregated subvector opening proof for an arbitrary subset of indices.
   */
  public static proveSubvector(
    vector: any[],
    indices: number[],
    crs?: VectorCRS
  ): SubvectorOpeningProof {
    const effectiveCRS = crs || this.generateCRS(Math.max(vector.length, 16));
    const sortedIndices = Array.from(new Set(indices)).sort((a, b) => a - b);

    for (const idx of sortedIndices) {
      if (idx < 0 || idx >= vector.length) {
        throw new Error(`Index out of bounds: ${idx}`);
      }
    }

    const queriedSet = new Set(sortedIndices);
    let witnessVal = 0n;
    const valuesHex: string[] = [];

    for (let i = 0; i < vector.length; i++) {
      const ai = this.toScalar(vector[i]);
      if (queriedSet.has(i)) {
        valuesHex.push(ai.toString(16).padStart(64, '0'));
      } else {
        const gi = BigInt('0x' + effectiveCRS.generatorsHex[i]);
        witnessVal = (witnessVal + ai * gi) % VC_PRIME;
      }
    }

    const commitment = this.commit(vector, effectiveCRS);
    const proofId = 'sub_prf_' + sha256Hex(`subprf:${commitment.commitmentHex}:${sortedIndices.join(',')}`).substring(0, 16);

    const proofPayload = {
      type: 'DocuTrustSubvectorProof2026' as const,
      proofId,
      commitmentHex: commitment.commitmentHex,
      indices: sortedIndices,
      valuesHex,
      aggregatedProofHex: witnessVal.toString(16).padStart(64, '0'),
      crsHash: effectiveCRS.crsHash
    };

    const proofHash = sha256Hex(canonicalizeJson(proofPayload));

    return {
      ...proofPayload,
      proofHash
    };
  }

  /**
   * Verifies an aggregated subvector opening proof in O(|I|) steps.
   */
  public static verifySubvector(
    commitmentHex: string,
    proof: SubvectorOpeningProof,
    crs?: VectorCRS
  ): { valid: boolean; error?: string } {
    if (!proof || proof.type !== 'DocuTrustSubvectorProof2026') {
      return { valid: false, error: 'Invalid subvector proof type' };
    }

    if (proof.indices.length !== proof.valuesHex.length) {
      return { valid: false, error: 'Indices and values length mismatch' };
    }

    const maxIdx = Math.max(...proof.indices, 0);
    const effectiveCRS = crs || this.generateCRS(Math.max(maxIdx + 1, 16));

    let subvectorSum = 0n;
    for (let k = 0; k < proof.indices.length; k++) {
      const idx = proof.indices[k];
      if (idx >= effectiveCRS.maxVectorLength) {
        return { valid: false, error: `Index ${idx} exceeds CRS capacity` };
      }
      const val = BigInt('0x' + proof.valuesHex[k]);
      const gi = BigInt('0x' + effectiveCRS.generatorsHex[idx]);
      subvectorSum = (subvectorSum + val * gi) % VC_PRIME;
    }

    const witness = BigInt('0x' + proof.aggregatedProofHex);
    const targetCommitment = BigInt('0x' + commitmentHex);

    const reconstructed = (witness + subvectorSum) % VC_PRIME;
    if (reconstructed !== targetCommitment) {
      return { valid: false, error: 'Subvector opening verification equation failed' };
    }

    return { valid: true };
  }
}
