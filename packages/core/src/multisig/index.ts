import { KeyPair, canonicalizeJson, sha256Hex, signData, verifySignature } from '../crypto';
import { VerifiableCredential } from '../vc';
import { constantTimeCompareHex } from '../security';

export interface SignerAuthority {
  did: string;
  role: string; // e.g. "Dean", "Chancellor", "Registrar"
  publicKeyHex: string;
}

export interface ThresholdPolicy {
  requiredSignatures: number; // M
  totalAuthorizedSigners: number; // N
  authorizedSigners: SignerAuthority[];
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
  /**
   * Create an unsigned Multi-Sig Credential package.
   */
  public static createMultiSigDraft(
    unsignedCredential: Omit<VerifiableCredential, 'proof'>,
    policy: ThresholdPolicy
  ): { canonicalHash: string; payloadToSign: string; policy: ThresholdPolicy } {
    const payloadToSign = canonicalizeJson({
      ...unsignedCredential,
      thresholdPolicy: {
        required: policy.requiredSignatures,
        signers: policy.authorizedSigners.map(s => ({ did: s.did, role: s.role }))
      }
    });

    const canonicalHash = sha256Hex(payloadToSign);
    return { canonicalHash, payloadToSign, policy };
  }

  /**
   * Add a signature from an authorized authority.
   */
  public static signAsAuthority(
    canonicalHash: string,
    signer: SignerAuthority,
    keyPair: KeyPair
  ): MultiSignatureEntry {
    const signature = signData(canonicalHash, keyPair);
    return {
      signerDid: signer.did,
      role: signer.role,
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
    const { canonicalHash } = this.createMultiSigDraft(unsignedCredential, policy);

    const proof: MultiSigProof = {
      type: 'MultiSigThresholdSignature2026',
      created: new Date().toISOString(),
      threshold: {
        required: policy.requiredSignatures,
        total: policy.totalAuthorizedSigners
      },
      signatures: collectedSignatures,
      jcsCanonicalHash: canonicalHash
    };

    return {
      ...unsignedCredential,
      proof: proof as any
    };
  }

  /**
   * Verify an M-of-N MultiSig Credential.
   */
  public static verifyMultiSigCredential(
    credential: VerifiableCredential,
    policy: ThresholdPolicy
  ): { valid: boolean; verifiedCount: number; requiredCount: number; errors: string[] } {
    const errors: string[] = [];
    const proof = credential.proof as unknown as MultiSigProof;

    if (!proof || proof.type !== 'MultiSigThresholdSignature2026') {
      return { valid: false, verifiedCount: 0, requiredCount: policy.requiredSignatures, errors: ['Not a MultiSig credential'] };
    }

    // 1. Recompute canonical hash
    const { proof: _, ...unsigned } = credential;
    const { canonicalHash } = this.createMultiSigDraft(unsigned, policy);

    // 2. Validate individual signatures
    const verifiedDids = new Set<string>();

    for (const sigEntry of proof.signatures) {
      const authorized = policy.authorizedSigners.find(s => s.did === sigEntry.signerDid);
      if (!authorized) {
        errors.push(`Unauthorized signer detected: ${sigEntry.signerDid}`);
        continue;
      }

      if (verifiedDids.has(sigEntry.signerDid)) {
        errors.push(`Duplicate signature from DID: ${sigEntry.signerDid}`);
        continue;
      }

      const isValid = verifySignature(canonicalHash, sigEntry.signature, authorized.publicKeyHex);
      if (isValid) {
        verifiedDids.add(sigEntry.signerDid);
      } else {
        errors.push(`Invalid signature for authority role: ${sigEntry.role}`);
      }
    }

    const verifiedCount = verifiedDids.size;
    const valid = verifiedCount >= policy.requiredSignatures && errors.length === 0;

    if (verifiedCount < policy.requiredSignatures) {
      errors.push(`Threshold not met. Collected ${verifiedCount} of ${policy.requiredSignatures} required signatures.`);
    }

    return {
      valid,
      verifiedCount,
      requiredCount: policy.requiredSignatures,
      errors
    };
  }
}
