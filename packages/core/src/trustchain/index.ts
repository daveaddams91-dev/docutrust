/**
 * @file packages/core/src/trustchain/index.ts
 * @description Hierarchical Verifiable Trust Chains & Authority Delegation Engine
 * Enables multi-tier institutional governance (Root Institutional Authority -> Regional Registrar -> Department Sub-Issuer)
 * with cryptographic delegation tokens, constraint path validation, and decentralized trust resolution.
 */

import * as crypto from 'crypto';
import { sha256Hex, canonicalizeJson, signData, verifySignature, KeyPair, decodeBase58 } from '../crypto/index.js';
import { DIDResolver } from '../did/index.js';

export interface DelegationConstraints {
  allowedCredentialTypes: string[]; // e.g. ['UniversityDegreeCredential', 'TranscriptCredential'] or ['*']
  maxDepth: number; // Maximum sub-delegation levels permitted
  disallowedSubjectDids?: string[];
  maxIssuedCount?: number;
}

export interface DelegationToken {
  type: 'DocuTrustDelegationToken2026';
  id: string;
  delegatorDid: string;
  delegateDid: string;
  constraints: DelegationConstraints;
  validFrom: string;
  validUntil: string;
  proof: {
    type: 'Ed25519Signature2020';
    created: string;
    verificationMethod: string;
    proofValue: string;
  };
}

export interface TrustChainVerificationResult {
  valid: boolean;
  rootAuthorityDid: string;
  leafIssuerDid: string;
  chainDepth: number;
  tokensVerified: number;
  isAccreditedRoot: boolean;
  errors: string[];
}

export class TrustChainEngine {
  /**
   * Creates a signed Delegation Token from a Delegator to a Delegate.
   */
  public static createDelegationToken(
    options: {
      delegatorKeyPair: KeyPair;
      delegateDid: string;
      allowedCredentialTypes?: string[];
      maxDepth?: number;
      validFrom?: string;
      validUntil?: string;
    }
  ): DelegationToken {
    const id = `urn:uuid:delegation-${crypto.randomUUID()}`;
    const validFrom = options.validFrom || new Date().toISOString();
    const validUntil = options.validUntil || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

    const constraints: DelegationConstraints = {
      allowedCredentialTypes: options.allowedCredentialTypes || ['*'],
      maxDepth: options.maxDepth !== undefined ? options.maxDepth : 2
    };

    const tokenUnsigned = {
      type: 'DocuTrustDelegationToken2026' as const,
      id,
      delegatorDid: options.delegatorKeyPair.did,
      delegateDid: options.delegateDid,
      constraints,
      validFrom,
      validUntil
    };

    const canonical = canonicalizeJson(tokenUnsigned);
    const digest = sha256Hex(canonical);
    const created = new Date().toISOString();
    const proofValue = signData(`${digest}:${created}`, options.delegatorKeyPair.privateKeyHex);

    return {
      ...tokenUnsigned,
      proof: {
        type: 'Ed25519Signature2020',
        created,
        verificationMethod: `${options.delegatorKeyPair.did}#key-1`,
        proofValue
      }
    };
  }

  /**
   * Verifies an individual Delegation Token.
   */
  public static verifyDelegationToken(token: DelegationToken, expectedDelegatorPublicKeyHex?: string): boolean {
    if (!token || token.type !== 'DocuTrustDelegationToken2026' || !token.proof) {
      return false;
    }

    // Check expiration
    const now = Date.now();
    const from = new Date(token.validFrom).getTime();
    const until = new Date(token.validUntil).getTime();
    if (now < from || now > until) {
      return false;
    }

    const copy = { ...token };
    delete (copy as any).proof;

    const canonical = canonicalizeJson(copy);
    const digest = sha256Hex(canonical);

    let pubHex = expectedDelegatorPublicKeyHex;
    if (!pubHex && token.delegatorDid.startsWith('did:key:')) {
      try {
        const raw = decodeBase58(token.delegatorDid.replace('did:key:z', ''));
        pubHex = raw.subarray(2).toString('hex');
      } catch (_) {}
    }

    if (!pubHex) return false;

    return verifySignature(`${digest}:${token.proof.created}`, token.proof.proofValue, pubHex);
  }

  /**
   * Recursively verifies an end-to-end Trust Chain against an issued Verifiable Credential or target authority.
   */
  public static verifyTrustChain(options: {
    chain?: DelegationToken[];
    delegationTokens?: DelegationToken[];
    credential?: {
      type: string | string[];
      issuer: string | { id: string };
      validFrom?: string;
    };
    rootAuthorityDid?: string;
    accreditedRootDids?: string[];
    leafIssuerDid?: string;
    targetCredentialType?: string;
    maxAllowedDepth?: number;
  }): TrustChainVerificationResult {
    const errors: string[] = [];
    const chain = options.chain || options.delegationTokens || [];
    const accreditedRootDids = options.accreditedRootDids || (options.rootAuthorityDid ? [options.rootAuthorityDid] : []);

    if (!chain || !Array.isArray(chain) || chain.length === 0) {
      return {
        valid: false,
        rootAuthorityDid: '',
        leafIssuerDid: '',
        chainDepth: 0,
        tokensVerified: 0,
        isAccreditedRoot: false,
        errors: ['Trust chain is empty or invalid.']
      };
    }

    let credIssuer = options.leafIssuerDid;
    let credTypes: string[] = options.targetCredentialType ? [options.targetCredentialType] : [];
    if (options.credential) {
      credIssuer = typeof options.credential.issuer === 'string' ? options.credential.issuer : options.credential.issuer.id;
      credTypes = Array.isArray(options.credential.type) ? options.credential.type : [options.credential.type];
    }

    // 1. Root token delegator must be in accreditedRootDids
    const rootToken = chain[0];
    const isAccreditedRoot = accreditedRootDids.length === 0 || accreditedRootDids.includes(rootToken.delegatorDid);
    if (!isAccreditedRoot) {
      errors.push(`Root delegator ${rootToken.delegatorDid} is not accredited.`);
    }

    // 2. Verify each link in the chain
    let currentDelegator = rootToken.delegatorDid;
    for (let i = 0; i < chain.length; i++) {
      const token = chain[i];

      // Delegator linkage check
      if (token.delegatorDid !== currentDelegator) {
        errors.push(`Chain broken at step ${i}: expected delegator ${currentDelegator}, found ${token.delegatorDid}`);
      }

      // Cryptographic signature check
      if (!this.verifyDelegationToken(token)) {
        errors.push(`Delegation token at step ${i} (ID: ${token.id}) failed cryptographic signature or date check.`);
      }

      // Check max depth constraint (remaining hops below this delegation level)
      const remainingDepth = chain.length - 1 - i;
      if (remainingDepth > token.constraints.maxDepth) {
        errors.push(`Remaining delegation depth ${remainingDepth} exceeds token ${token.id} maxDepth limit (${token.constraints.maxDepth}).`);
      }

      if (options.maxAllowedDepth !== undefined && chain.length > options.maxAllowedDepth) {
        errors.push(`Delegation chain length ${chain.length} exceeds maxAllowedDepth ${options.maxAllowedDepth}.`);
      }

      // Check credential type scope
      const allowed = token.constraints.allowedCredentialTypes;
      if (credTypes.length > 0 && !allowed.includes('*')) {
        const hasMatchingType = credTypes.some(t => allowed.includes(t));
        if (!hasMatchingType) {
          errors.push(`Credential type [${credTypes.join(', ')}] not permitted by delegation token ${token.id} (allowed: [${allowed.join(', ')}]).`);
        }
      }

      currentDelegator = token.delegateDid;
    }

    // 3. Final delegate in chain must match the credential issuer if specified
    const leafToken = chain[chain.length - 1];
    if (credIssuer && leafToken.delegateDid !== credIssuer) {
      errors.push(`Leaf delegate ${leafToken.delegateDid} does not match credential issuer ${credIssuer}.`);
    }

    return {
      valid: errors.length === 0,
      rootAuthorityDid: rootToken.delegatorDid,
      leafIssuerDid: leafToken.delegateDid,
      chainDepth: chain.length,
      tokensVerified: chain.length,
      isAccreditedRoot,
      errors
    };
  }
}
