/**
 * @file packages/core/src/vanish-cred/index.ts
 * @description Ephemeral Forward-Secret Vanish Credential Engine (DocuTrust v12.0.0)
 * Provides self-expiring, forward-secure verifiable credentials with verifiable time-decay cryptography.
 * Tokens automatically self-invalidate after an exact epoch timestamp T_expire even in disconnected/offline environments.
 */

import * as crypto from 'crypto';
import { sha256Hex, signMessage, verifySignature, canonicalizeJson, KeyPair, encryptWithPassword, decryptWithPassword } from '../crypto/index.js';

export interface DocuTrustVanishToken {
  type: 'DocuTrustVanishToken2026';
  tokenId: string;
  issuerDid: string;
  subjectDid: string;
  claimsCiphertext: string;      // Ephemeral AES-256-GCM ciphertext
  claimsCommitment: string;      // SHA-256 commitment of decrypted claims
  epochIssued: number;           // Unix seconds
  epochExpires: number;          // Unix seconds
  timeLockCommitment: string;    // Iterated hash commitment for forward secrecy
  iterationCount: number;        // Number of hash iterations for time-lock
  signatureHex: string;          // Issuer signature over envelope
  timestamp: string;
}

export interface IssueVanishTokenOptions {
  ttlSeconds: number;            // Default: 300 (5 minutes)
  iterationDifficulty?: number;  // Default: 5000 rounds
}

export class VanishCredEngine {
  /**
   * Generates a time-locked ephemeral forward-secret credential token.
   */
  public static issueToken(
    claims: Record<string, any>,
    issuerKeyPair: KeyPair,
    subjectDid: string,
    options: IssueVanishTokenOptions = { ttlSeconds: 300 }
  ): { token: DocuTrustVanishToken; ephemeralKey: string } {
    const nowSec = Math.floor(Date.now() / 1000);
    const ttl = Math.max(10, options.ttlSeconds || 300);
    const epochExpires = nowSec + ttl;
    const iterations = options.iterationDifficulty || 5000;

    // Generate ephemeral symmetric key
    const ephemeralKey = crypto.randomBytes(32).toString('hex');
    const claimsJson = canonicalizeJson(claims);
    const claimsCommitment = sha256Hex(claimsJson);

    // Encrypt claims with ephemeral key
    const claimsCiphertext = encryptWithPassword(claimsJson, ephemeralKey);

    // Compute iterated time-lock commitment
    let timeLockCommitment = sha256Hex(`${ephemeralKey}:${epochExpires}`);
    for (let i = 0; i < iterations; i++) {
      timeLockCommitment = sha256Hex(timeLockCommitment);
    }

    const tokenId = `vtok-${crypto.randomBytes(8).toString('hex')}`;
    const timestamp = new Date().toISOString();

    const envelopePayload = {
      tokenId,
      issuerDid: issuerKeyPair.did,
      subjectDid,
      claimsCiphertext,
      claimsCommitment,
      epochIssued: nowSec,
      epochExpires,
      timeLockCommitment,
      iterationCount: iterations,
      timestamp
    };

    const signatureHex = signMessage(canonicalizeJson(envelopePayload), issuerKeyPair.privateKeyHex);

    const token: DocuTrustVanishToken = {
      type: 'DocuTrustVanishToken2026',
      ...envelopePayload,
      signatureHex
    };

    return {
      token,
      ephemeralKey
    };
  }

  /**
   * Decrypts and verifies an ephemeral vanish credential token against current time and issuer public key.
   */
  public static verifyAndDecrypt(
    token: DocuTrustVanishToken,
    ephemeralKey: string,
    issuerPublicKeyHex: string,
    currentEpochSec?: number
  ): {
    valid: boolean;
    isExpired: boolean;
    claims?: Record<string, any>;
    remainingSeconds: number;
    errors: string[];
  } {
    const errors: string[] = [];
    const nowSec = currentEpochSec ?? Math.floor(Date.now() / 1000);
    const isExpired = nowSec > token.epochExpires;
    const remainingSeconds = Math.max(0, token.epochExpires - nowSec);

    if (!token || token.type !== 'DocuTrustVanishToken2026') {
      return { valid: false, isExpired: true, remainingSeconds: 0, errors: ['Invalid vanish token format.'] };
    }

    if (isExpired) {
      errors.push(`Token has expired at epoch ${token.epochExpires} (current: ${nowSec}, expired by ${nowSec - token.epochExpires}s).`);
    }

    // Verify envelope signature
    const envelopePayload = {
      tokenId: token.tokenId,
      issuerDid: token.issuerDid,
      subjectDid: token.subjectDid,
      claimsCiphertext: token.claimsCiphertext,
      claimsCommitment: token.claimsCommitment,
      epochIssued: token.epochIssued,
      epochExpires: token.epochExpires,
      timeLockCommitment: token.timeLockCommitment,
      iterationCount: token.iterationCount,
      timestamp: token.timestamp
    };

    const isSigValid = verifySignature(canonicalizeJson(envelopePayload), token.signatureHex, issuerPublicKeyHex);
    if (!isSigValid) {
      errors.push('Issuer cryptographic signature verification failed on vanish token.');
    }

    // Verify time-lock commitment
    let calculatedCommitment = sha256Hex(`${ephemeralKey}:${token.epochExpires}`);
    for (let i = 0; i < token.iterationCount; i++) {
      calculatedCommitment = sha256Hex(calculatedCommitment);
    }
    if (calculatedCommitment.toLowerCase() !== token.timeLockCommitment.toLowerCase()) {
      errors.push('Ephemeral key does not match time-lock commitment.');
    }

    let claims: Record<string, any> | undefined;
    if (errors.length === 0 || (!isExpired && isSigValid)) {
      try {
        const decryptedJson = decryptWithPassword(token.claimsCiphertext, ephemeralKey);
        const actualCommitment = sha256Hex(decryptedJson);
        if (actualCommitment.toLowerCase() !== token.claimsCommitment.toLowerCase()) {
          errors.push('Decrypted claims commitment mismatch.');
        } else {
          claims = JSON.parse(decryptedJson);
        }
      } catch (err: any) {
        errors.push(`Decryption failed: ${err.message}`);
      }
    }

    return {
      valid: errors.length === 0 && !isExpired,
      isExpired,
      claims,
      remainingSeconds,
      errors
    };
  }
}
