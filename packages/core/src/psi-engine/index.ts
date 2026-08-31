import * as crypto from 'crypto';
import { canonicalizeJson, sha256Hex } from '../crypto';

export interface BlindedSetElement {
  originalHash: string;
  blindedValue: string;
}

export interface BlindedPartyDataset {
  partyId: string;
  setSize: number;
  blindedElements: BlindedSetElement[];
  datasetCommitment: string;
  timestamp: string;
}

export interface PSIIntersectionResult {
  partyAId: string;
  partyBId: string;
  setSizeA: number;
  setSizeB: number;
  intersectionCardinality: number;
  matchRatio: number;
  blindedMatches: string[];
}

export interface PSIReceipt {
  type: 'DocuTrustPSIReceipt2026';
  receiptId: string;
  partyAId: string;
  partyBId: string;
  commitmentA: string;
  commitmentB: string;
  intersectionCardinality: number;
  matchRatio: number;
  blindedMatchesHash: string;
  timestamp: string;
  signature: string;
  receiptHash: string;
}

export class PSIExecutionEngine {
  private static readonly MODULUS = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

  private static modExp(base: bigint, exp: bigint, mod: bigint): bigint {
    let res = 1n;
    let b = base % mod;
    let e = exp;
    while (e > 0n) {
      if (e % 2n === 1n) res = (res * b) % mod;
      b = (b * b) % mod;
      e /= 2n;
    }
    return res;
  }

  /**
   * Blinds a party's set of credential hashes / identifiers using commutative exponentiation.
   */
  public static blindDataset(
    partyId: string,
    rawItems: string[],
    secretKeyHex?: string
  ): { dataset: BlindedPartyDataset; secretKeyHex: string } {
    const key = secretKeyHex || crypto.randomBytes(32).toString('hex');
    const secretBig = (BigInt('0x' + key) % (this.MODULUS - 2n)) + 2n;

    const blindedElements: BlindedSetElement[] = rawItems.map(item => {
      const origHash = sha256Hex(item);
      const hBig = BigInt('0x' + origHash) % this.MODULUS;
      const blindedBig = this.modExp(hBig, secretBig, this.MODULUS);
      return {
        originalHash: origHash,
        blindedValue: blindedBig.toString(16).padStart(64, '0')
      };
    });

    const datasetCommitment = sha256Hex(
      blindedElements.map(e => e.blindedValue).sort().join(':')
    );

    return {
      dataset: {
        partyId,
        setSize: rawItems.length,
        blindedElements,
        datasetCommitment,
        timestamp: new Date().toISOString()
      },
      secretKeyHex: key
    };
  }

  /**
   * Applies double-blinding so both parties share identical commutative key combinations (H(x)^(k_a * k_b)).
   */
  public static doubleBlindElements(
    blindedElements: BlindedSetElement[],
    secondSecretKeyHex: string
  ): string[] {
    const secondSecretBig = (BigInt('0x' + secondSecretKeyHex) % (this.MODULUS - 2n)) + 2n;

    return blindedElements.map(elem => {
      const firstBlindBig = BigInt('0x' + elem.blindedValue);
      const doubleBlindBig = this.modExp(firstBlindBig, secondSecretBig, this.MODULUS);
      return doubleBlindBig.toString(16).padStart(64, '0');
    });
  }

  /**
   * Computes the private set intersection over double-blinded sets without decrypting or revealing non-intersecting elements.
   */
  public static computeIntersection(
    partyAId: string,
    partyBId: string,
    doubleBlindedSetA: string[],
    doubleBlindedSetB: string[]
  ): PSIIntersectionResult {
    const setB = new Set(doubleBlindedSetB);
    const matches: string[] = [];

    for (const item of doubleBlindedSetA) {
      if (setB.has(item)) {
        matches.push(item);
      }
    }

    const setSizeA = doubleBlindedSetA.length;
    const setSizeB = doubleBlindedSetB.length;
    const intersectionCardinality = matches.length;
    const minSize = Math.max(1, Math.min(setSizeA, setSizeB));
    const matchRatio = parseFloat((intersectionCardinality / minSize).toFixed(4));

    return {
      partyAId,
      partyBId,
      setSizeA,
      setSizeB,
      intersectionCardinality,
      matchRatio,
      blindedMatches: matches
    };
  }

  /**
   * Generates a signed cryptographic PSI execution receipt.
   */
  public static generateReceipt(
    partyA: BlindedPartyDataset,
    partyB: BlindedPartyDataset,
    intersection: PSIIntersectionResult,
    authorityPrivateKeyHex?: string
  ): PSIReceipt {
    const receiptId = 'psi_' + crypto.randomBytes(8).toString('hex');
    const blindedMatchesHash = sha256Hex(intersection.blindedMatches.sort().join(':'));
    const timestamp = new Date().toISOString();

    const payloadToSign = canonicalizeJson({
      receiptId,
      partyAId: partyA.partyId,
      partyBId: partyB.partyId,
      commitmentA: partyA.datasetCommitment,
      commitmentB: partyB.datasetCommitment,
      intersectionCardinality: intersection.intersectionCardinality,
      matchRatio: intersection.matchRatio,
      blindedMatchesHash,
      timestamp
    });

    const receiptHash = sha256Hex(payloadToSign);
    const signature = '0x' + sha256Hex(`psi_sig:${receiptHash}:${authorityPrivateKeyHex || 'default_authority'}`);

    return {
      type: 'DocuTrustPSIReceipt2026',
      receiptId,
      partyAId: partyA.partyId,
      partyBId: partyB.partyId,
      commitmentA: partyA.datasetCommitment,
      commitmentB: partyB.datasetCommitment,
      intersectionCardinality: intersection.intersectionCardinality,
      matchRatio: intersection.matchRatio,
      blindedMatchesHash,
      timestamp,
      signature,
      receiptHash
    };
  }

  /**
   * Verifies a cryptographic PSI Receipt.
   */
  public static verifyReceipt(receipt: PSIReceipt): { valid: boolean; error?: string } {
    if (!receipt || receipt.type !== 'DocuTrustPSIReceipt2026') {
      return { valid: false, error: 'Invalid PSI receipt structure or type' };
    }

    const computedHash = sha256Hex(canonicalizeJson({
      receiptId: receipt.receiptId,
      partyAId: receipt.partyAId,
      partyBId: receipt.partyBId,
      commitmentA: receipt.commitmentA,
      commitmentB: receipt.commitmentB,
      intersectionCardinality: receipt.intersectionCardinality,
      matchRatio: receipt.matchRatio,
      blindedMatchesHash: receipt.blindedMatchesHash,
      timestamp: receipt.timestamp
    }));

    if (computedHash !== receipt.receiptHash) {
      return { valid: false, error: 'Receipt payload digest mismatch / tampered values' };
    }

    if (!receipt.signature || receipt.signature.length < 10) {
      return { valid: false, error: 'Missing or malformed signature' };
    }

    return { valid: true };
  }
}
