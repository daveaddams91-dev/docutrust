import { KeyPair, canonicalizeJson, sha256Hex, signData, verifySignature } from '../crypto';
import { VerifiableCredential } from '../vc';
import { constantTimeCompareHex } from '../security';

export interface SignerAuthority {
  did: string;
  role: string; // e.g. "Dean", "Chancellor", "Registrar"
  publicKeyHex?: string;
}

export interface ThresholdPolicy {
  policyId?: string;
  requiredSignatures?: number; // M
  threshold?: number; // M alias
  totalAuthorizedSigners?: number; // N
  authorizedSigners?: SignerAuthority[];
  authorities?: SignerAuthority[];
}

export interface MultiSignatureEntry {
  signerDid: string;
  role: string;
  signature: string;
  signedAt: string;
}

export interface MultiSigProof {
  type: 'MultiSigThresholdSignature2026';
  created: string;
  policyId?: string;
  threshold: {
    required: number;
    total: number;
  };
  signatures: MultiSignatureEntry[];
  jcsCanonicalHash: string;
}

/**
 * Multi-Signature Threshold (M-of-N) Cryptographic Suite
 */
export class MultiSigEngine {
  public static normalizePolicy(policy: ThresholdPolicy): {
    policyId: string;
    requiredSignatures: number;
    totalAuthorizedSigners: number;
    authorizedSigners: SignerAuthority[];
  } {
    const required = policy.requiredSignatures ?? policy.threshold ?? 1;
    const signers = policy.authorizedSigners ?? policy.authorities ?? [];
    return {
      policyId: policy.policyId || 'policy-default',
      requiredSignatures: required,
      totalAuthorizedSigners: policy.totalAuthorizedSigners ?? signers.length,
      authorizedSigners: signers
    };
  }

  /**
   * Create an unsigned Multi-Sig Credential package.
   */
  public static createMultiSigDraft(
    unsignedCredential: Omit<VerifiableCredential, 'proof'>,
    policy: ThresholdPolicy
  ): { canonicalHash: string; payloadToSign: string; policy: ThresholdPolicy } {
    const norm = this.normalizePolicy(policy);
    const payloadToSign = canonicalizeJson({
      ...unsignedCredential,
      thresholdPolicy: {
        policyId: norm.policyId,
        required: norm.requiredSignatures,
        signers: norm.authorizedSigners.map(s => ({ did: s.did, role: s.role }))
      }
    });

    const canonicalHash = sha256Hex(payloadToSign);
    return { canonicalHash, payloadToSign, policy };
  }

  public static createDraft(
    unsignedCredential: Omit<VerifiableCredential, 'proof'>,
    policy: ThresholdPolicy
  ) {
    return this.createMultiSigDraft(unsignedCredential, policy);
  }

  /**
   * Add a signature from an authorized authority.
   */
  public static signAsAuthority(
    canonicalHash: string,
    signerOrDid: SignerAuthority | string,
    roleOrKeyPair: string | KeyPair,
    privateKeyHex?: string
  ): MultiSignatureEntry {
    let signerDid: string;
    let role: string;
    let privHex: string;

    if (typeof signerOrDid === 'object' && typeof roleOrKeyPair === 'object') {
      signerDid = signerOrDid.did;
      role = signerOrDid.role;
      privHex = roleOrKeyPair.privateKeyHex;
    } else if (typeof signerOrDid === 'string' && typeof roleOrKeyPair === 'string' && privateKeyHex) {
      signerDid = signerOrDid;
      role = roleOrKeyPair;
      privHex = privateKeyHex;
    } else {
      throw new Error('Invalid arguments passed to signAsAuthority.');
    }

    const signature = signData(canonicalHash, privHex);
    return {
      signerDid,
      role,
      signature,
      signedAt: new Date().toISOString()
    };
  }

  /**
   * Finalize and attach M-of-N MultiSig proof to credential.
   */
  public static assembleMultiSigCredential(
    unsignedCredential: Omit<VerifiableCredential, 'proof'>,
    policy: ThresholdPolicy,
    collectedSignatures: MultiSignatureEntry[]
  ): VerifiableCredential {
    const norm = this.normalizePolicy(policy);
    const { canonicalHash } = this.createMultiSigDraft(unsignedCredential, policy);

    const proof: MultiSigProof = {
      type: 'MultiSigThresholdSignature2026',
      created: new Date().toISOString(),
      policyId: norm.policyId,
      threshold: {
        required: norm.requiredSignatures,
        total: norm.totalAuthorizedSigners
      },
      signatures: collectedSignatures,
      jcsCanonicalHash: canonicalHash
    };

    return {
      ...unsignedCredential,
      proof: proof as any
    } as VerifiableCredential;
  }

  /**
   * Verify an M-of-N MultiSig Credential.
   */
  public static verifyMultiSigCredential(
    credential: VerifiableCredential,
    policy?: ThresholdPolicy
  ): {
    valid: boolean;
    policyId?: string;
    threshold?: number;
    validSignaturesCount?: number;
    verifiedCount: number;
    requiredCount: number;
    signers: string[];
    errors: string[];
    error?: string;
  } {
    const errors: string[] = [];
    const proof = credential.proof as unknown as MultiSigProof;

    if (!proof || proof.type !== 'MultiSigThresholdSignature2026') {
      return {
        valid: false,
        verifiedCount: 0,
        requiredCount: 0,
        signers: [],
        errors: ['Not a MultiSig credential'],
        error: 'Not a MultiSig credential'
      };
    }

    const effectivePolicy = policy ? this.normalizePolicy(policy) : {
      policyId: proof.policyId || 'policy-default',
      requiredSignatures: proof.threshold?.required || 1,
      totalAuthorizedSigners: proof.threshold?.total || proof.signatures.length,
      authorizedSigners: proof.signatures.map(s => ({ did: s.signerDid, role: s.role }))
    };

    // 1. Recompute canonical hash
    const { proof: _, ...unsigned } = credential;
    const { canonicalHash } = this.createMultiSigDraft(unsigned, effectivePolicy);

    // 2. Validate individual signatures
    const verifiedDids = new Set<string>();
    const validSigners: string[] = [];

    for (const sigEntry of proof.signatures) {
      if (verifiedDids.has(sigEntry.signerDid)) {
        errors.push(`Duplicate signature from DID: ${sigEntry.signerDid}`);
        continue;
      }

      const isValid = verifySignature(canonicalHash, sigEntry.signature, sigEntry.signerDid);
      if (isValid) {
        verifiedDids.add(sigEntry.signerDid);
        validSigners.push(sigEntry.signerDid);
      } else {
        errors.push(`Invalid signature for authority role: ${sigEntry.role} (${sigEntry.signerDid})`);
      }
    }

    const verifiedCount = verifiedDids.size;
    const valid = verifiedCount >= effectivePolicy.requiredSignatures && errors.length === 0;

    if (verifiedCount < effectivePolicy.requiredSignatures) {
      errors.push(`Threshold not met. Collected ${verifiedCount} of ${effectivePolicy.requiredSignatures} required signatures.`);
    }

    return {
      valid,
      policyId: effectivePolicy.policyId,
      threshold: effectivePolicy.requiredSignatures,
      validSignaturesCount: verifiedCount,
      verifiedCount,
      requiredCount: effectivePolicy.requiredSignatures,
      signers: validSigners,
      errors,
      error: errors.length > 0 ? errors.join('; ') : undefined
    };
  }
}

export const MultiSigThresholdEngine = MultiSigEngine;

