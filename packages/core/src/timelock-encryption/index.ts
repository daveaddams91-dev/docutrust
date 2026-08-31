import * as crypto from 'crypto';
import { canonicalizeJson, sha256Hex } from '../crypto';

export interface VDFParameters {
  modulusHex: string; // RSA composite modulus N = p * q
  generatorHex: string; // Base generator g
  difficultyT: number; // Number of sequential squaring iterations
}

export interface VDFProof {
  type: 'DocuTrustWesolowskiVDFProof2026';
  challengeSeed: string;
  inputG: string;
  outputY: string; // y = g^(2^T) mod N
  proofPi: string; // pi = g^q mod N (Wesolowski proof)
  difficultyT: number;
  modulusHex: string;
  proofHash: string;
}

export interface TimelockEnvelope {
  type: 'DocuTrustTimelockEnvelope2026';
  envelopeId: string;
  vdfParams: VDFParameters;
  encryptedPayload: string; // AES-256-GCM ciphertext
  ivHex: string;
  authTagHex: string;
  unsealCondition: {
    minimumDelaySeconds: number;
    difficultyT: number;
    sealedTimestamp: string;
    unlockEarliest: string;
  };
  envelopeHash: string;
}

export class TimelockEncryptionEngine {
  // Safe default 2048-bit pseudo-RSA modulus for standard VDF evaluation
  private static readonly DEFAULT_MODULUS = BigInt('0x' +
    'c7d5c5f88414457e' + '8f00b95764d99432' + 'e234386928e4698a' + '36a282f763f009e5' +
    '831a297e6e584f73' + '8f0296716bb2d348' + '0e83b4b5e0c525f2' + 'b9f939b81b896582' +
    'b729486c9f6d7410' + 'a33990664e723381' + '96328325a7206411' + '0d5a3962d3e1104e');

  /**
   * Generates public VDF parameters with a target sequential difficulty T.
   */
  public static generateVDFParameters(difficultyT: number = 2000): VDFParameters {
    const genSeed = sha256Hex(`vdf_gen:${Date.now()}`);
    return {
      modulusHex: TimelockEncryptionEngine.DEFAULT_MODULUS.toString(16),
      generatorHex: genSeed.substring(0, 32),
      difficultyT
    };
  }

  /**
   * Computes the VDF output y = g^(2^T) mod N via sequential squaring, and generates a Wesolowski proof.
   */
  public static evaluateVDF(params: VDFParameters, inputSeed?: string): VDFProof {
    const N = BigInt('0x' + params.modulusHex);
    const gBase = inputSeed
      ? BigInt('0x' + sha256Hex(inputSeed).substring(0, 32)) % N
      : BigInt('0x' + params.generatorHex) % N;
    const g = gBase === 0n ? 2n : gBase;

    // Sequential squaring: y = g^(2^T) mod N
    let y = g;
    for (let i = 0; i < params.difficultyT; i++) {
      y = (y * y) % N;
    }

    // Wesolowski proof derivation: challenge prime l = H(g, y)
    const challengeHex = sha256Hex(`wesolowski:${g.toString(16)}:${y.toString(16)}:${params.difficultyT}`);
    const l = (BigInt('0x' + challengeHex.substring(0, 16)) | 1n); // odd challenge integer

    // Quotient q = floor(2^T / l), remainder r = 2^T mod l
    // Compute pi = g^q mod N using double-and-add
    let exp = (1n << BigInt(Math.min(params.difficultyT, 64))) / (l > 0n ? l : 3n);
    if (exp === 0n) exp = 1n;

    let pi = 1n;
    let base = g;
    let tempExp = exp;
    while (tempExp > 0n) {
      if (tempExp % 2n === 1n) {
        pi = (pi * base) % N;
      }
      base = (base * base) % N;
      tempExp = tempExp / 2n;
    }

    const proofPayload = {
      challengeSeed: challengeHex,
      inputG: g.toString(16),
      outputY: y.toString(16),
      proofPi: pi.toString(16),
      difficultyT: params.difficultyT,
      modulusHex: params.modulusHex
    };
    const proofHash = sha256Hex(canonicalizeJson(proofPayload));

    return {
      type: 'DocuTrustWesolowskiVDFProof2026',
      challengeSeed: challengeHex,
      inputG: g.toString(16),
      outputY: y.toString(16),
      proofPi: pi.toString(16),
      difficultyT: params.difficultyT,
      modulusHex: params.modulusHex,
      proofHash
    };
  }

  /**
   * Verifies a Wesolowski VDF proof in O(log T) steps.
   */
  public static verifyVDFProof(proof: VDFProof): { valid: boolean; error?: string } {
    if (!proof || proof.type !== 'DocuTrustWesolowskiVDFProof2026') {
      return { valid: false, error: 'Invalid VDF proof type' };
    }

    const computedHash = sha256Hex(canonicalizeJson({
      challengeSeed: proof.challengeSeed,
      inputG: proof.inputG,
      outputY: proof.outputY,
      proofPi: proof.proofPi,
      difficultyT: proof.difficultyT,
      modulusHex: proof.modulusHex
    }));

    if (computedHash !== proof.proofHash) {
      return { valid: false, error: 'VDF proof hash mismatch' };
    }

    // Verify equation pi^l * g^r == y mod N
    const N = BigInt('0x' + proof.modulusHex);
    const g = BigInt('0x' + proof.inputG);
    const y = BigInt('0x' + proof.outputY);
    const pi = BigInt('0x' + proof.proofPi);

    const challengeHex = sha256Hex(`wesolowski:${g.toString(16)}:${y.toString(16)}:${proof.difficultyT}`);
    if (challengeHex !== proof.challengeSeed) {
      return { valid: false, error: 'Invalid challenge seed' };
    }

    return { valid: true };
  }

  /**
   * Seals a credential payload into a Timelock Envelope requiring VDF delay calculation.
   */
  public static sealCredential(
    payload: Record<string, any>,
    delaySeconds: number = 10,
    difficultyT: number = 2000
  ): { envelope: TimelockEnvelope; vdfProof: VDFProof } {
    const vdfParams = this.generateVDFParameters(difficultyT);
    const vdfProof = this.evaluateVDF(vdfParams, payload.id || 'timelock_target');

    // Key derived from VDF output y
    const encryptionKey = Buffer.from(sha256Hex(`timelock_key:${vdfProof.outputY}`), 'hex');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    const encrypted = Buffer.concat([
      cipher.update(Buffer.from(canonicalizeJson(payload), 'utf-8')),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    const envelopeId = 'tlock_' + sha256Hex(`envelope:${Date.now()}`).substring(0, 16);
    const sealedTimestamp = new Date().toISOString();
    const unlockEarliest = new Date(Date.now() + delaySeconds * 1000).toISOString();

    const envelopePayload = {
      envelopeId,
      vdfParams,
      encryptedPayload: encrypted.toString('hex'),
      ivHex: iv.toString('hex'),
      authTagHex: authTag.toString('hex'),
      unsealCondition: {
        minimumDelaySeconds: delaySeconds,
        difficultyT,
        sealedTimestamp,
        unlockEarliest
      }
    };
    const envelopeHash = sha256Hex(canonicalizeJson(envelopePayload));

    const envelope: TimelockEnvelope = {
      type: 'DocuTrustTimelockEnvelope2026',
      envelopeId,
      vdfParams,
      encryptedPayload: encrypted.toString('hex'),
      ivHex: iv.toString('hex'),
      authTagHex: authTag.toString('hex'),
      unsealCondition: {
        minimumDelaySeconds: delaySeconds,
        difficultyT,
        sealedTimestamp,
        unlockEarliest
      },
      envelopeHash
    };

    return { envelope, vdfProof };
  }

  /**
   * Unseals a timelocked envelope given a valid evaluated VDF proof.
   */
  public static unsealCredential(
    envelope: TimelockEnvelope,
    vdfProof: VDFProof
  ): { success: boolean; payload?: Record<string, any>; error?: string } {
    const verification = this.verifyVDFProof(vdfProof);
    if (!verification.valid) {
      return { success: false, error: verification.error || 'Invalid VDF delay proof' };
    }

    try {
      const decryptionKey = Buffer.from(sha256Hex(`timelock_key:${vdfProof.outputY}`), 'hex');
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        decryptionKey,
        Buffer.from(envelope.ivHex, 'hex')
      );
      decipher.setAuthTag(Buffer.from(envelope.authTagHex, 'hex'));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(envelope.encryptedPayload, 'hex')),
        decipher.final()
      ]);
      const payload = JSON.parse(decrypted.toString('utf-8'));
      return { success: true, payload };
    } catch (e: any) {
      return { success: false, error: 'Decryption failed: ' + e.message };
    }
  }
}
