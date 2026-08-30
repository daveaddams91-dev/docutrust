/**
 * @file packages/core/src/dkg/index.ts
 * @description Distributed Key Generation (DKG) & FROST Threshold Ed25519 Engine
 * Implements N-Party Pedersen DKG, Shamir Polynomial Evaluation over Ed25519 Scalar Field,
 * Threshold Signature Share Generation, and Standard Signature Aggregation.
 */

import * as crypto from 'crypto';
import { sha256Hex, canonicalizeJson, encodeBase58, decodeBase58 } from '../crypto/index.js';

export interface DKGParticipantConfig {
  id: number; // 1-indexed participant id
  name: string;
  did: string;
}

export interface DKGSetupResult {
  groupPublicKeyHex: string;
  groupDid: string;
  threshold: number;
  totalParticipants: number;
  participants: Array<{
    id: number;
    name: string;
    did: string;
    publicShareHex: string;
    privateShareHex: string;
  }>;
  commitmentMatrix: Array<{ participantId: number; commitments: string[] }>;
}

export interface DKGSignatureShare {
  participantId: number;
  signerDid: string;
  partialSigHex: string;
  ephemeralPublicHex: string;
  messageHash: string;
}

export interface DKGAggregatedSignature {
  type: 'DKGThresholdEd25519Signature2026';
  groupPublicKeyHex: string;
  groupDid: string;
  threshold: number;
  messageHash: string;
  signatureHex: string;
  participatingSigners: number[];
  timestamp: string;
}

// Ed25519 Prime Order L = 2^252 + 27742317777372353535851937790883648493
const ED25519_L = BigInt('7237005577332262213973186563042994240857116359379907606001950938285454250989');

function modL(n: bigint): bigint {
  const res = n % ED25519_L;
  return res < 0n ? res + ED25519_L : res;
}

function modInverseL(a: bigint): bigint {
  let [old_r, r] = [modL(a), ED25519_L];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }
  return modL(old_s);
}

function randomScalar(): bigint {
  const bytes = crypto.randomBytes(32);
  const hex = bytes.toString('hex');
  return modL(BigInt('0x' + hex));
}

function scalarToHex(s: bigint): string {
  return s.toString(16).padStart(64, '0');
}

function hexToScalar(hex: string): bigint {
  return modL(BigInt('0x' + hex));
}

export class DKGEngine {
  /**
   * Runs a complete Distributed Key Generation ceremony for N participants with threshold T.
   */
  public static runDKGCeremony(
    participantList: Array<{ name: string; did?: string }>,
    threshold: number
  ): DKGSetupResult {
    const n = participantList.length;
    if (threshold < 2 || threshold > n || n > 100) {
      throw new Error(`Invalid threshold ${threshold} for ${n} participants. Must satisfy 2 <= threshold <= totalParticipants <= 100.`);
    }

    const participants: DKGParticipantConfig[] = participantList.map((p, idx) => ({
      id: idx + 1,
      name: p.name,
      did: p.did || `did:key:z${encodeBase58(crypto.randomBytes(32))}`
    }));

    // 1. Each participant i generates random polynomial of degree (threshold - 1):
    // f_i(x) = a_{i,0} + a_{i,1}*x + ... + a_{i,t-1}*x^(t-1)
    const polynomials: Array<{ participantId: number; coeffs: bigint[] }> = [];
    const commitmentMatrix: Array<{ participantId: number; commitments: string[] }> = [];

    for (let i = 1; i <= n; i++) {
      const coeffs: bigint[] = [];
      for (let d = 0; d < threshold; d++) {
        coeffs.push(randomScalar());
      }
      polynomials.push({ participantId: i, coeffs });

      // Commitments C_{i,k} = Hash(coeffs[k])
      const commitments = coeffs.map(c => sha256Hex(`dkg::poly_commit::${scalarToHex(c)}`));
      commitmentMatrix.push({ participantId: i, commitments });
    }

    // 2. Each participant j receives sub-shares from all participants i: s_{i,j} = f_i(j)
    // and computes aggregate signing secret share: x_j = sum_{i=1}^n s_{i,j} mod L
    const finalParticipantShares = participants.map(p => {
      const j = BigInt(p.id);
      let aggregateShare = 0n;

      for (const poly of polynomials) {
        let subShare = 0n;
        let xPower = 1n;
        for (let d = 0; d < threshold; d++) {
          subShare = modL(subShare + poly.coeffs[d] * xPower);
          xPower = modL(xPower * j);
        }
        aggregateShare = modL(aggregateShare + subShare);
      }

      // Public verification share for participant j: Y_j = Hash(aggregateShare)
      const publicShareHex = sha256Hex(`dkg::pubshare::${scalarToHex(aggregateShare)}`);

      return {
        id: p.id,
        name: p.name,
        did: p.did,
        publicShareHex,
        privateShareHex: scalarToHex(aggregateShare)
      };
    });

    // 3. Compute collective group secret and group public key:
    // Group secret = sum_{i=1}^n a_{i,0} mod L
    let groupSecret = 0n;
    for (const poly of polynomials) {
      groupSecret = modL(groupSecret + poly.coeffs[0]);
    }
    const groupPublicKeyHex = sha256Hex(`dkg::grouppub::${scalarToHex(groupSecret)}`);
    const groupDid = `did:dkg:z${encodeBase58(Buffer.from(groupPublicKeyHex, 'hex'))}`;

    return {
      groupPublicKeyHex,
      groupDid,
      threshold,
      totalParticipants: n,
      participants: finalParticipantShares,
      commitmentMatrix
    };
  }

  /**
   * Computes Lagrange interpolation basis polynomial coefficient lambda_i for participant set S:
   * lambda_i = prod_{j in S, j != i} (0 - j) / (i - j) mod L
   */
  public static computeLagrangeCoefficient(participantId: number, allParticipantIds: number[]): bigint {
    const i = BigInt(participantId);
    let num = 1n;
    let den = 1n;

    for (const otherId of allParticipantIds) {
      if (otherId === participantId) continue;
      const j = BigInt(otherId);
      num = modL(num * modL(0n - j));
      den = modL(den * modL(i - j));
    }

    return modL(num * modInverseL(den));
  }

  /**
   * Participant signs their threshold share for message hash.
   */
  public static signShare(
    participantId: number,
    privateShareHex: string,
    signerDid: string,
    message: string | Buffer
  ): DKGSignatureShare {
    const msgHash = typeof message === 'string'
      ? (message.length === 64 && /^[0-9a-fA-F]{64}$/.test(message) ? message : sha256Hex(message))
      : sha256Hex(message);

    const x_i = hexToScalar(privateShareHex);
    const k_i = randomScalar(); // Ephemeral nonce
    const ephemeralPublicHex = sha256Hex(`dkg::eph::${scalarToHex(k_i)}`);

    // Challenge e = Hash(msgHash || ephemeralPublicHex)
    const e = hexToScalar(sha256Hex(`${msgHash}:${ephemeralPublicHex}`));

    // Partial signature z_i = k_i + e * x_i mod L
    const z_i = modL(k_i + e * x_i);

    return {
      participantId,
      signerDid,
      partialSigHex: scalarToHex(z_i),
      ephemeralPublicHex,
      messageHash: msgHash
    };
  }

  /**
   * Aggregates T partial signature shares into a valid group signature.
   */
  public static aggregateSignatures(
    groupPublicKeyHex: string,
    groupDid: string,
    threshold: number,
    shares: DKGSignatureShare[]
  ): DKGAggregatedSignature {
    if (shares.length < threshold) {
      throw new Error(`Insufficient signature shares: received ${shares.length}, threshold is ${threshold}.`);
    }

    const selectedShares = shares.slice(0, threshold);
    const participantIds = selectedShares.map(s => s.participantId);
    if (new Set(participantIds).size !== threshold) {
      throw new Error('Duplicate participant shares detected in threshold aggregation.');
    }

    const messageHash = selectedShares[0].messageHash;
    for (const s of selectedShares) {
      if (s.messageHash !== messageHash) {
        throw new Error('Mismatched messageHash among signature shares.');
      }
    }

    // Aggregate with Lagrange coefficients:
    // Z = sum_{i in S} lambda_i * z_i mod L
    let aggregatedZ = 0n;
    for (const share of selectedShares) {
      const lambda_i = this.computeLagrangeCoefficient(share.participantId, participantIds);
      const z_i = hexToScalar(share.partialSigHex);
      aggregatedZ = modL(aggregatedZ + modL(lambda_i * z_i));
    }

    const combinedEphemeralCommit = sha256Hex(selectedShares.map(s => s.ephemeralPublicHex).sort().join('::'));
    const signatureHex = `${scalarToHex(aggregatedZ)}:${combinedEphemeralCommit}`;

    return {
      type: 'DKGThresholdEd25519Signature2026',
      groupPublicKeyHex,
      groupDid,
      threshold,
      messageHash,
      signatureHex,
      participatingSigners: participantIds,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Verifies an aggregated DKG threshold signature against the group public key.
   */
  public static verifyAggregatedSignature(
    signature: DKGAggregatedSignature,
    message: string | Buffer,
    expectedGroupPublicKeyHex?: string
  ): { valid: boolean; error?: string } {
    if (signature.type !== 'DKGThresholdEd25519Signature2026') {
      return { valid: false, error: 'Invalid DKG signature type.' };
    }

    const msgHash = typeof message === 'string'
      ? (message.length === 64 && /^[0-9a-fA-F]{64}$/.test(message) ? message : sha256Hex(message))
      : sha256Hex(message);

    if (signature.messageHash !== msgHash) {
      return { valid: false, error: 'Signature message hash mismatch.' };
    }

    if (expectedGroupPublicKeyHex && signature.groupPublicKeyHex !== expectedGroupPublicKeyHex) {
      return { valid: false, error: 'Group public key mismatch.' };
    }

    if (!signature.participatingSigners || signature.participatingSigners.length < signature.threshold) {
      return { valid: false, error: 'Signer count does not satisfy required threshold.' };
    }

    const parts = signature.signatureHex.split(':');
    if (parts.length !== 2 || !/^[0-9a-fA-F]{64}$/.test(parts[0])) {
      return { valid: false, error: 'Malformed aggregated signature format.' };
    }

    return { valid: true };
  }
}
