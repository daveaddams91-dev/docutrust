import * as crypto from 'crypto';
import { KeyPair, signData, verifySignature, sha256Hex, canonicalizeJson } from '../crypto';
import { VerifiableCredential, VerifiableCredentialsEngine } from '../vc';

export interface PoPChallenge {
  challengeId: string;
  nonce: string;
  audience: string; // Verifier DID or URL
  expiresAt: number;
}

export interface PoPPresentation {
  credential: VerifiableCredential;
  challengeId: string;
  nonce: string;
  audience: string;
  holderDid: string;
  holderSignature: string;
  timestamp: string;
}

export class ProofOfPossessionProtocol {
  private static activeChallenges: Map<string, PoPChallenge> = new Map();

  /**
   * Verifier generates a cryptographic challenge nonce with short TTL (2 minutes).
   */
  public static createChallenge(audience: string, ttlMs: number = 120000): PoPChallenge {
    const challengeId = `pop_${crypto.randomBytes(16).toString('hex')}`;
    const nonce = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + ttlMs;

    const challenge: PoPChallenge = {
      challengeId,
      nonce,
      audience,
      expiresAt
    };

    this.activeChallenges.set(challengeId, challenge);
    return challenge;
  }

  /**
   * Holder signs the challenge and binds it to their credential presentation.
   */
  public static createPresentation(
    credential: VerifiableCredential,
    challenge: PoPChallenge,
    holderKeyPair: KeyPair
  ): PoPPresentation {
    const holderDid = holderKeyPair.did;
    const timestamp = new Date().toISOString();

    const signPayload = canonicalizeJson({
      credentialId: credential.id,
      challengeId: challenge.challengeId,
      nonce: challenge.nonce,
      audience: challenge.audience,
      holderDid,
      timestamp
    });

    const holderSignature = signData(sha256Hex(signPayload), holderKeyPair);

    return {
      credential,
      challengeId: challenge.challengeId,
      nonce: challenge.nonce,
      audience: challenge.audience,
      holderDid,
      holderSignature,
      timestamp
    };
  }

  /**
   * Verifier validates both the credential validity AND holder proof of possession.
   */
  public static async verifyPresentation(
    presentation: PoPPresentation,
    expectedAudience?: string
  ): Promise<{
    valid: boolean;
    credentialValid: boolean;
    holderPossessionValid: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];

    // 1. Verify Issuer Signature & Credential integrity
    const vcAudit = await VerifiableCredentialsEngine.verify(presentation.credential);
    if (!vcAudit.valid) {
      errors.push(...vcAudit.errors);
    }

    // 2. Verify Subject Binding: Holder DID must match credentialSubject.id (or if subject id missing, holderDid must match)
    const subjectId = presentation.credential.credentialSubject?.id;
    if (subjectId && subjectId !== presentation.holderDid) {
      errors.push(`Holder DID mismatch: credential belongs to ${subjectId}, presented by ${presentation.holderDid}`);
    }

    // 3. Audience check
    if (expectedAudience && presentation.audience !== expectedAudience) {
      errors.push(`Audience mismatch: expected ${expectedAudience}, got ${presentation.audience}`);
    }

    // 4. Verify Holder Signature over challenge payload
    const signPayload = canonicalizeJson({
      credentialId: presentation.credential.id,
      challengeId: presentation.challengeId,
      nonce: presentation.nonce,
      audience: presentation.audience,
      holderDid: presentation.holderDid,
      timestamp: presentation.timestamp
    });

    const isHolderSigValid = verifySignature(sha256Hex(signPayload), presentation.holderSignature, presentation.holderDid);
    if (!isHolderSigValid) {
      errors.push('Holder cryptographic proof-of-possession signature is INVALID.');
    }

    const valid = vcAudit.valid && isHolderSigValid && errors.length === 0;

    return {
      valid,
      credentialValid: vcAudit.valid,
      holderPossessionValid: isHolderSigValid,
      errors
    };
  }
}
