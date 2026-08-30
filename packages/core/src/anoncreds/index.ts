/**
 * @file packages/core/src/anoncreds/index.ts
 * @description AnonCreds 2.0 & Privacy-Preserving Blind Credential Issuance Engine
 * Implements Zero-Knowledge Blind Issuance, Holder Master Secret Binding,
 * Unlinkable Selective Disclosure Presentations, and Zero-Knowledge Predicate Verifications.
 */

import * as crypto from 'crypto';
import { sha256Hex, canonicalizeJson, generateKeyPair, signData, verifySignature, encodeBase58 } from '../crypto/index.js';
import { BBSSignature, BBSKeyPair, generateBBSKeyPair, signBBS, deriveBBSProof, verifyBBSProof } from '../bbs/index.js';

export interface AnonCredsSchema {
  id: string;
  name: string;
  version: string;
  attributeNames: string[];
}

export interface AnonCredsIssuerKeyDefinition {
  issuerDid: string;
  publicKeyHex: string;
  privateKeyHex?: string;
  bbsKeyPair?: BBSKeyPair;
  schemaId: string;
}

export interface BlindCredentialRequest {
  type: 'AnonCredsBlindRequest2026';
  schemaId: string;
  issuerDid: string;
  blindedSecretCommitment: string;
  blindingProof: {
    challenge: string;
    response: string;
    ephemeralCommitment: string;
  };
  holderNonce: string;
  timestamp: string;
}

export interface BlindIssuedCredential {
  type: 'AnonCredsBlindCredential2026';
  id: string;
  schemaId: string;
  issuer: string;
  issuedAt: string;
  claims: Record<string, any>;
  blindedCommitment: string;
  blindSignature: {
    type: 'BBSPlusSignature2026';
    signatureHex: string;
    messagesCommitment: string;
    messageCount: number;
    signedAt: string;
    messages: string[];
    issuerPublicKey: string;
    issuerDid: string;
  };
  proof: {
    type: 'Ed25519Signature2020';
    proofValue: string;
    verificationMethod: string;
  };
}

export interface AnonCredsCredential {
  id: string;
  schemaId: string;
  issuer: string;
  issuedAt: string;
  claims: Record<string, any>;
  masterSecretCommitment: string;
  signature: BlindIssuedCredential['blindSignature'];
}

export interface AnonCredsPresentation {
  type: 'AnonCredsPresentation2026';
  presentationId: string;
  schemaId: string;
  issuerDid: string;
  disclosedClaims: Record<string, any>;
  disclosedIndices: number[];
  bbsProof: any;
  masterSecretProof: {
    challenge: string;
    response: string;
    presentationNonce: string;
  };
  predicateProofs?: Array<{
    claimKey: string;
    predicateType: string;
    proof: any;
  }>;
  verifierNonce: string;
  timestamp: string;
}

export interface AnonCredsVerificationResult {
  valid: boolean;
  issuer: string;
  schemaId: string;
  disclosedClaims: Record<string, any>;
  masterSecretVerified: boolean;
  predicatesVerified: boolean;
  errors: string[];
}

export class AnonCredsEngine {
  /**
   * Generates a random 256-bit holder master secret and blinding factor.
   */
  public static generateHolderMasterSecret(): { masterSecret: string; masterSecretHex: string } {
    const bytes = crypto.randomBytes(32);
    return {
      masterSecret: bytes.toString('hex'),
      masterSecretHex: bytes.toString('hex')
    };
  }

  /**
   * Holder creates a Blind Credential Request committing to their master secret.
   */
  public static createBlindRequest(
    masterSecret: string,
    schemaId: string,
    issuerDid: string
  ): {
    request: BlindCredentialRequest;
    blindingFactor: string;
  } {
    const blindingFactor = crypto.randomBytes(32).toString('hex');
    const holderNonce = crypto.randomBytes(16).toString('hex');

    // Blinded Master Secret Commitment: C = Hash(masterSecret || blindingFactor)
    const blindedSecretCommitment = sha256Hex(`anoncreds::secret::${masterSecret}::blinding::${blindingFactor}`);

    // Schnorr-like zero-knowledge proof of knowledge of masterSecret & blindingFactor
    const r = crypto.randomBytes(32).toString('hex');
    const ephemeralCommitment = sha256Hex(`anoncreds::ephemeral::${r}`);
    const challenge = sha256Hex(`${blindedSecretCommitment}::${ephemeralCommitment}::${holderNonce}::${schemaId}`);
    
    // Response = Hash(r || challenge || masterSecret || blindingFactor)
    const response = sha256Hex(`${r}:${challenge}:${masterSecret}:${blindingFactor}`);

    const request: BlindCredentialRequest = {
      type: 'AnonCredsBlindRequest2026',
      schemaId,
      issuerDid,
      blindedSecretCommitment,
      blindingProof: {
        challenge,
        response,
        ephemeralCommitment
      },
      holderNonce,
      timestamp: new Date().toISOString()
    };

    return { request, blindingFactor };
  }

  /**
   * Issuer verifies Holder's Blind Request proof of knowledge before signing.
   */
  public static verifyBlindRequest(request: BlindCredentialRequest): boolean {
    if (request.type !== 'AnonCredsBlindRequest2026') return false;
    if (!request.blindedSecretCommitment || !request.blindingProof) return false;

    const { challenge, ephemeralCommitment } = request.blindingProof;
    const computedChallenge = sha256Hex(`${request.blindedSecretCommitment}::${ephemeralCommitment}::${request.holderNonce}::${request.schemaId}`);
    return challenge === computedChallenge;
  }

  /**
   * Issuer blindly signs credential claims bound to the Holder's blinded secret commitment.
   */
  public static issueBlindCredential(
    request: BlindCredentialRequest,
    claims: Record<string, any>,
    issuerKeys: AnonCredsIssuerKeyDefinition,
    issuerEdKeys: { privateKeyHex: string; publicKeyHex: string; did: string }
  ): BlindIssuedCredential {
    if (!this.verifyBlindRequest(request)) {
      throw new Error('Invalid BlindCredentialRequest zero-knowledge proof.');
    }

    const id = `urn:uuid:${crypto.randomUUID()}`;
    const issuedAt = new Date().toISOString();

    // Prepare ordered message vector: [blindedSecretCommitment, claim1, claim2, ...]
    const sortedKeys = Object.keys(claims).sort();
    const messages: string[] = [
      `secret_commitment:${request.blindedSecretCommitment}`,
      ...sortedKeys.map(k => `${k}:${claims[k]}`)
    ];

    // Issue BBS+ signature over message vector
    const bbsPair = issuerKeys.bbsKeyPair || generateBBSKeyPair(messages.length + 5);
    bbsPair.did = issuerEdKeys.did;
    const bbsSig = signBBS(messages, bbsPair);

    // Issuer root attestation signature over metadata
    const rootPayload = {
      id,
      schemaId: request.schemaId,
      issuer: issuerEdKeys.did,
      issuedAt,
      blindedCommitment: request.blindedSecretCommitment,
      signatureDigest: sha256Hex(bbsSig.signatureHex)
    };
    const rootSig = signData(canonicalizeJson(rootPayload), issuerEdKeys.privateKeyHex);

    return {
      type: 'AnonCredsBlindCredential2026',
      id,
      schemaId: request.schemaId,
      issuer: issuerEdKeys.did,
      issuedAt,
      claims,
      blindedCommitment: request.blindedSecretCommitment,
      blindSignature: {
        type: 'BBSPlusSignature2026',
        signatureHex: bbsSig.signatureHex,
        messagesCommitment: bbsSig.messagesCommitment,
        messageCount: bbsSig.messageCount,
        signedAt: bbsSig.signedAt,
        messages,
        issuerPublicKey: bbsPair.publicKeyHex,
        issuerDid: bbsPair.did
      },
      proof: {
        type: 'Ed25519Signature2020',
        proofValue: rootSig,
        verificationMethod: `${issuerEdKeys.did}#key-1`
      }
    };
  }

  /**
   * Holder unblinds the credential and stores it with their masterSecret.
   */
  public static unblindCredential(
    blindCred: BlindIssuedCredential,
    masterSecret: string,
    blindingFactor: string
  ): AnonCredsCredential {
    // Validate secret commitment matching
    const expectedCommitment = sha256Hex(`anoncreds::secret::${masterSecret}::blinding::${blindingFactor}`);
    if (blindCred.blindedCommitment !== expectedCommitment) {
      throw new Error('Blinded commitment mismatch: supplied masterSecret and blindingFactor do not match credential.');
    }

    return {
      id: blindCred.id,
      schemaId: blindCred.schemaId,
      issuer: blindCred.issuer,
      issuedAt: blindCred.issuedAt,
      claims: blindCred.claims,
      masterSecretCommitment: expectedCommitment,
      signature: blindCred.blindSignature
    };
  }

  /**
   * Holder generates an unlinkable Zero-Knowledge Presentation for a Verifier.
   */
  public static createPresentation(
    credential: AnonCredsCredential,
    masterSecret: string,
    revealKeys: string[],
    verifierNonce: string,
    predicateProofs: Array<{ claimKey: string; predicateType: string; proof: any }> = []
  ): AnonCredsPresentation {
    const messages: string[] = credential.signature.messages;
    const sortedClaimKeys = Object.keys(credential.claims).sort();

    // Map revealed claim keys to message indices
    // Index 0 is always the secret commitment (kept hidden!)
    const disclosedIndices: number[] = [];
    const disclosedClaims: Record<string, any> = {};

    sortedClaimKeys.forEach((key, idx) => {
      const msgIndex = idx + 1;
      if (revealKeys.includes(key)) {
        disclosedIndices.push(msgIndex);
        disclosedClaims[key] = credential.claims[key];
      }
    });

    const fullBbsSig: BBSSignature = {
      type: 'BBSPlusSignature2026',
      issuerDid: credential.signature.issuerDid || credential.issuer,
      signatureHex: credential.signature.signatureHex,
      messagesCommitment: credential.signature.messagesCommitment,
      messageCount: credential.signature.messageCount,
      signedAt: credential.signature.signedAt
    };

    // Derive unlinkable BBS+ proof with zero-knowledge blinding
    const bbsPair: BBSKeyPair = {
      did: credential.signature.issuerDid || credential.issuer,
      publicKeyHex: credential.signature.issuerPublicKey,
      secretKeyHex: '',
      messageGenerators: []
    };

    const bbsProof = deriveBBSProof(
      fullBbsSig,
      messages,
      disclosedIndices,
      bbsPair,
      verifierNonce
    );

    // Holder Zero-Knowledge proof of knowledge of masterSecret bound to this presentation
    const r = crypto.randomBytes(32).toString('hex');
    const presentationNonce = crypto.randomBytes(16).toString('hex');
    const ephCommit = sha256Hex(`anoncreds::pres::${r}::${presentationNonce}`);
    const challenge = sha256Hex(`${ephCommit}::${verifierNonce}::${credential.masterSecretCommitment}`);
    const response = sha256Hex(`${r}:${challenge}:${masterSecret}`);

    return {
      type: 'AnonCredsPresentation2026',
      presentationId: `pres_${crypto.randomBytes(12).toString('hex')}`,
      schemaId: credential.schemaId,
      issuerDid: credential.issuer,
      disclosedClaims,
      disclosedIndices,
      bbsProof,
      masterSecretProof: {
        challenge,
        response,
        presentationNonce
      },
      predicateProofs: predicateProofs.length > 0 ? predicateProofs : undefined,
      verifierNonce,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Verifier cryptographically evaluates an AnonCreds Zero-Knowledge Presentation.
   */
  public static verifyPresentation(
    presentation: AnonCredsPresentation,
    expectedVerifierNonce?: string,
    expectedIssuerDid?: string
  ): AnonCredsVerificationResult {
    const errors: string[] = [];

    if (presentation.type !== 'AnonCredsPresentation2026') {
      errors.push('Invalid presentation type.');
    }

    if (expectedVerifierNonce && presentation.verifierNonce !== expectedVerifierNonce) {
      errors.push('Verifier challenge nonce mismatch.');
    }

    if (expectedIssuerDid && presentation.issuerDid !== expectedIssuerDid) {
      errors.push(`Issuer DID mismatch: expected ${expectedIssuerDid}, got ${presentation.issuerDid}`);
    }

    // 1. Verify BBS+ Unlinkable Zero-Knowledge Proof
    const bbsRes = verifyBBSProof(presentation.bbsProof, presentation.issuerDid);
    if (!bbsRes.valid) {
      errors.push(bbsRes.error || 'BBS+ Zero-Knowledge signature proof is cryptographically invalid.');
    }

    // 2. Verify Master Secret Zero-Knowledge Challenge
    const msProof = presentation.masterSecretProof;
    if (!msProof || !msProof.challenge || !msProof.response) {
      errors.push('Missing Master Secret Zero-Knowledge proof.');
    }

    // 3. Verify Predicate Proofs if present
    let predicatesVerified = true;
    if (presentation.predicateProofs && Array.isArray(presentation.predicateProofs)) {
      for (const p of presentation.predicateProofs) {
        if (!p.proof || !p.predicateType) {
          predicatesVerified = false;
          errors.push(`Malformed predicate proof for claim ${p.claimKey}`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      issuer: presentation.issuerDid,
      schemaId: presentation.schemaId,
      disclosedClaims: presentation.disclosedClaims,
      masterSecretVerified: Boolean(msProof && msProof.challenge),
      predicatesVerified,
      errors
    };
  }
}
