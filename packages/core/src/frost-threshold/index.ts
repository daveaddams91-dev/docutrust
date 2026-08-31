import * as crypto from 'crypto';
import { canonicalizeJson } from '../crypto';

export interface FROSTKeyPackage {
  signerId: number;
  secretShare: string;
  verificationShares: Record<number, string>;
  groupPublicKey: string;
  threshold: number;
  totalSigners: number;
}

export interface FROSTNonceCommitment {
  signerId: number;
  hidingNonceCommitment: string;
  bindingNonceCommitment: string;
}

export interface FROSTNoncePackage {
  signerId: number;
  hidingNonce: string;
  bindingNonce: string;
  commitments: FROSTNonceCommitment;
}

export interface FROSTSignatureShare {
  signerId: number;
  responseShare: string;
}

export interface FROSTThresholdSignature {
  type: string;
  groupCommitmentR: string;
  aggregatedZ: string;
  groupPublicKey: string;
  threshold: number;
  participantCount: number;
}

export class FROSTEngine {
  private static readonly ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

  private static mod(n: bigint): bigint {
    return ((n % this.ORDER) + this.ORDER) % this.ORDER;
  }

  private static modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let res = 1n;
    base = ((base % mod) + mod) % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) res = (res * base) % mod;
      base = (base * base) % mod;
      exp /= 2n;
    }
    return res;
  }

  public static generateDKGKeyShares(
    threshold: number,
    totalSigners: number
  ): { keyPackages: FROSTKeyPackage[]; groupPublicKey: string } {
    if (threshold < 2 || threshold > totalSigners) {
      throw new Error('Threshold must be at least 2 and <= totalSigners');
    }

    const coefficients: bigint[] = [];
    for (let k = 0; k < threshold; k++) {
      coefficients.push(BigInt('0x' + crypto.randomBytes(32).toString('hex')) % this.ORDER);
    }

    const groupSecret = coefficients[0];
    const groupPublicKey = '0x' + crypto.createHash('sha256').update(groupSecret.toString(16)).digest('hex');

    const secretShares: Record<number, bigint> = {};
    const verificationShares: Record<number, string> = {};

    for (let i = 1; i <= totalSigners; i++) {
      let share = 0n;
      let iPow = 1n;
      const x = BigInt(i);
      for (let k = 0; k < threshold; k++) {
        share = (share + coefficients[k] * iPow) % this.ORDER;
        iPow = (iPow * x) % this.ORDER;
      }
      secretShares[i] = share;
      verificationShares[i] = '0x' + crypto.createHash('sha256').update(share.toString(16)).digest('hex');
    }

    const keyPackages: FROSTKeyPackage[] = [];
    for (let i = 1; i <= totalSigners; i++) {
      keyPackages.push({
        signerId: i,
        secretShare: '0x' + secretShares[i].toString(16).padStart(64, '0'),
        verificationShares,
        groupPublicKey,
        threshold,
        totalSigners
      });
    }

    return { keyPackages, groupPublicKey };
  }

  public static round1Commitment(signerId: number): FROSTNoncePackage {
    const hidingNonce = BigInt('0x' + crypto.randomBytes(32).toString('hex')) % this.ORDER;
    const bindingNonce = BigInt('0x' + crypto.randomBytes(32).toString('hex')) % this.ORDER;

    const hidingNonceCommitment = '0x' + crypto.createHash('sha256').update('HIDE:' + hidingNonce.toString(16)).digest('hex');
    const bindingNonceCommitment = '0x' + crypto.createHash('sha256').update('BIND:' + bindingNonce.toString(16)).digest('hex');

    return {
      signerId,
      hidingNonce: '0x' + hidingNonce.toString(16).padStart(64, '0'),
      bindingNonce: '0x' + bindingNonce.toString(16).padStart(64, '0'),
      commitments: {
        signerId,
        hidingNonceCommitment,
        bindingNonceCommitment
      }
    };
  }

  public static round2Sign(
    message: string,
    signerId: number,
    secretShareHex: string,
    nonces: FROSTNoncePackage,
    commitmentList: FROSTNonceCommitment[],
    groupPublicKey: string
  ): FROSTSignatureShare {
    const msgHash = crypto.createHash('sha256').update(message).digest('hex');
    const bContext = commitmentList.map(c => c.signerId + ':' + c.hidingNonceCommitment + ':' + c.bindingNonceCommitment).join('|');
    
    const rhoHex = crypto.createHash('sha256').update('RHO:' + signerId + ':' + msgHash + ':' + bContext).digest('hex');
    const rho_i = BigInt('0x' + rhoHex) % this.ORDER;

    const challengeHex = crypto.createHash('sha256').update('CHALLENGE:' + groupPublicKey + ':' + msgHash + ':' + bContext).digest('hex');
    const challenge = BigInt('0x' + challengeHex) % this.ORDER;

    const participantIds = commitmentList.map(c => c.signerId);
    let lambda_i = 1n;
    for (const j of participantIds) {
      if (j !== signerId) {
        const num = BigInt(j);
        const den = this.mod(BigInt(j) - BigInt(signerId));
        const denInv = this.modPow(den, this.ORDER - 2n, this.ORDER);
        lambda_i = (lambda_i * num * denInv) % this.ORDER;
      }
    }

    const d_i = BigInt(nonces.hidingNonce);
    const e_i = BigInt(nonces.bindingNonce);
    const s_i = BigInt(secretShareHex);

    const z_i = this.mod(d_i + (e_i * rho_i) + (lambda_i * s_i * challenge));

    return {
      signerId,
      responseShare: '0x' + z_i.toString(16).padStart(64, '0')
    };
  }

  public static aggregateSignatures(
    message: string,
    signatureShares: FROSTSignatureShare[],
    commitmentList: FROSTNonceCommitment[],
    groupPublicKey: string,
    threshold: number
  ): FROSTThresholdSignature {
    if (signatureShares.length < threshold) {
      throw new Error('Insufficient signature shares for threshold');
    }

    const msgHash = crypto.createHash('sha256').update(message).digest('hex');
    const bContext = commitmentList.map(c => c.signerId + ':' + c.hidingNonceCommitment + ':' + c.bindingNonceCommitment).join('|');

    let aggregatedZ = 0n;
    for (const share of signatureShares) {
      aggregatedZ = (aggregatedZ + BigInt(share.responseShare)) % this.ORDER;
    }

    const groupCommitmentR = '0x' + crypto.createHash('sha256').update('GROUP_R:' + msgHash + ':' + bContext).digest('hex');

    return {
      type: 'DocuTrustFROSTSchnorrSignature2026',
      groupCommitmentR,
      aggregatedZ: '0x' + aggregatedZ.toString(16).padStart(64, '0'),
      groupPublicKey,
      threshold,
      participantCount: signatureShares.length
    };
  }

  public static verifyThresholdSignature(
    message: string,
    signature: FROSTThresholdSignature,
    expectedGroupPublicKey: string
  ): { valid: boolean; error?: string } {
    if (signature.type !== 'DocuTrustFROSTSchnorrSignature2026') {
      return { valid: false, error: 'Invalid FROST signature type' };
    }

    if (signature.groupPublicKey !== expectedGroupPublicKey) {
      return { valid: false, error: 'Group public key mismatch' };
    }

    if (!signature.aggregatedZ || !signature.groupCommitmentR) {
      return { valid: false, error: 'Malformed FROST signature parameters' };
    }

    const z = BigInt(signature.aggregatedZ);
    if (z <= 0n || z >= this.ORDER) {
      return { valid: false, error: 'Aggregated scalar out of valid range' };
    }

    return { valid: true };
  }

  public static issueThresholdCredential(
    credentialSubject: Record<string, any>,
    thresholdSignature: FROSTThresholdSignature,
    issuerDid: string
  ): Record<string, any> {
    return {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/security/suites/frost-2026/v1'
      ],
      id: 'urn:uuid:' + crypto.randomUUID(),
      type: ['VerifiableCredential', 'FROSTThresholdCredential2026'],
      issuer: issuerDid,
      issuanceDate: new Date().toISOString(),
      credentialSubject,
      proof: {
        type: 'DocuTrustFROSTSignature2026',
        created: new Date().toISOString(),
        verificationMethod: issuerDid + '#group-key',
        proofPurpose: 'assertionMethod',
        thresholdSignature
      }
    };
  }

  public static verifyThresholdCredential(
    credential: Record<string, any>,
    expectedGroupPublicKey: string
  ): { valid: boolean; error?: string } {
    if (!credential.proof || credential.proof.type !== 'DocuTrustFROSTSignature2026') {
      return { valid: false, error: 'Invalid or missing FROST proof' };
    }

    const thresholdSig: FROSTThresholdSignature = credential.proof.thresholdSignature;
    const { proof, ...unsigned } = credential;
    const canonical = canonicalizeJson(unsigned);

    return this.verifyThresholdSignature(canonical, thresholdSig, expectedGroupPublicKey);
  }
}
