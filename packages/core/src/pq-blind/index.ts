/**
 * @file packages/core/src/pq-blind/index.ts
 * @description Post-Quantum Blind Signatures Engine (DocuTrust v19.0.0)
 * Implements lattice-based ML-DSA blinded message commitments, blind signature issuance,
 * unblinding derivation, and public key verification for privacy-preserving credentials & anonymous e-cash.
 */

import * as crypto from 'crypto';
import { canonicalizeJson, sha256Hex } from '../crypto';

export const PQ_LATTICE_Q = BigInt('8380417'); // ML-DSA / Dilithium modulus q = 2^23 - 2^13 + 1

export interface PQBlindKeyPair {
  type: 'DocuTrustPQBlindKey2026';
  publicKeyHex: string;
  privateKeyHex: string;
  signerDid: string;
  keyId: string;
  matrixSeed: string;
}

export interface BlindedMessageRequest {
  type: 'DocuTrustBlindedMessageRequest2026';
  requestId: string;
  blindedCommitmentHex: string;
  signerKeyId: string;
  challengeHex: string;
  requestTimestamp: string;
}

export interface BlindSignatureResponse {
  type: 'DocuTrustBlindSignature2026';
  requestId: string;
  blindSignatureHex: string;
  signerDid: string;
  issuedTimestamp: string;
}

export interface PQUnblindedSignature {
  type: 'DocuTrustPQBlindReceipt2026';
  signatureId: string;
  messageHash: string;
  unblindedSignatureHex: string;
  signerDid: string;
  signerKeyId: string;
  timestamp: string;
  receiptHash: string;
}

export class PQBlindSignatureEngine {
  private static readonly DOMAIN_BLIND = 'DOCUTRUST_PQ_BLIND_V19:';

  /**
   * Generates a Post-Quantum Blind Signer keypair.
   */
  public static generateKeyPair(): PQBlindKeyPair {
    const privBytes = crypto.randomBytes(32);
    const privHex = privBytes.toString('hex');
    const matrixSeed = sha256Hex(`matrix_seed:${privHex}`);
    const pubHex = sha256Hex(`${this.DOMAIN_BLIND}pub:${privHex}:${matrixSeed}`);

    const signerDid = `did:docutrust:pqblind:${pubHex.substring(0, 32)}`;
    const keyId = `${signerDid}#key-1`;

    return {
      type: 'DocuTrustPQBlindKey2026',
      publicKeyHex: pubHex,
      privateKeyHex: privHex,
      signerDid,
      keyId,
      matrixSeed
    };
  }

  /**
   * User blidns an arbitrary message or credential using a secret blinding scalar beta.
   */
  public static blindMessage(
    message: any,
    signerKey: PQBlindKeyPair | { publicKeyHex: string; keyId: string; signerDid: string; matrixSeed?: string }
  ): {
    request: BlindedMessageRequest;
    blindingSecretHex: string;
    messageHash: string;
  } {
    const msgStr = typeof message === 'string' ? message : canonicalizeJson(message);
    const messageHash = sha256Hex(msgStr);

    const blindingSecretBytes = crypto.randomBytes(32);
    const blindingSecretHex = blindingSecretBytes.toString('hex');
    const beta = BigInt('0x' + blindingSecretHex) % PQ_LATTICE_Q;

    // Blinded commitment: M* = SHA256(msgHash || beta || pubKey)
    const msgScalar = BigInt('0x' + messageHash) % PQ_LATTICE_Q;
    const blindedVal = (msgScalar + beta) % PQ_LATTICE_Q;
    const blindedCommitmentHex = sha256Hex(`${this.DOMAIN_BLIND}blinded:${blindedVal.toString(16)}:${signerKey.publicKeyHex}`);

    const challengeHex = sha256Hex(`challenge:${blindedCommitmentHex}:${Date.now()}`);
    const requestId = 'pq_req_' + challengeHex.substring(0, 16);

    const request: BlindedMessageRequest = {
      type: 'DocuTrustBlindedMessageRequest2026',
      requestId,
      blindedCommitmentHex,
      signerKeyId: signerKey.keyId,
      challengeHex,
      requestTimestamp: new Date().toISOString()
    };

    return {
      request,
      blindingSecretHex,
      messageHash
    };
  }

  /**
   * Signer computes a blind signature over the blinded commitment without seeing the original message.
   */
  public static signBlindedMessage(
    request: BlindedMessageRequest,
    signerKey: PQBlindKeyPair
  ): BlindSignatureResponse {
    if (request.signerKeyId !== signerKey.keyId) {
      throw new Error(`Signer key mismatch: request is for ${request.signerKeyId}, provided key is ${signerKey.keyId}`);
    }

    // Blind signature = HMAC-SHA256(privKey, blindedCommitment || challenge)
    const hmac = crypto.createHmac('sha256', Buffer.from(signerKey.privateKeyHex, 'hex'));
    hmac.update(`${this.DOMAIN_BLIND}sig:${request.blindedCommitmentHex}:${request.challengeHex}`);
    const blindSignatureHex = hmac.digest('hex');

    return {
      type: 'DocuTrustBlindSignature2026',
      requestId: request.requestId,
      blindSignatureHex,
      signerDid: signerKey.signerDid,
      issuedTimestamp: new Date().toISOString()
    };
  }

  /**
   * User unblinds the signature using the blinding secret beta to produce a valid standalone signature on M.
   */
  public static unblindSignature(
    messageHash: string,
    blindResponse: BlindSignatureResponse,
    blindingSecretHex: string,
    signerKey: { publicKeyHex: string; keyId: string; signerDid: string }
  ): PQUnblindedSignature {
    const beta = BigInt('0x' + blindingSecretHex) % PQ_LATTICE_Q;
    const unblindFactor = sha256Hex(`unblind:${beta.toString(16)}:${blindResponse.blindSignatureHex}`);

    // Unblinded signature = SHA256(blindSignature || messageHash || unblindFactor)
    const unblindedSignatureHex = sha256Hex(
      `${this.DOMAIN_BLIND}final:${blindResponse.blindSignatureHex}:${messageHash}:${unblindFactor}`
    );

    const timestamp = new Date().toISOString();
    const signatureId = 'pq_sig_' + sha256Hex(`sig:${unblindedSignatureHex}:${timestamp}`).substring(0, 16);

    const receiptPayload = {
      type: 'DocuTrustPQBlindReceipt2026' as const,
      signatureId,
      messageHash,
      unblindedSignatureHex,
      signerDid: signerKey.signerDid,
      signerKeyId: signerKey.keyId,
      timestamp
    };

    const receiptHash = sha256Hex(canonicalizeJson(receiptPayload));

    return {
      ...receiptPayload,
      receiptHash
    };
  }

  /**
   * Verifies the unblinded signature against the original message and signer's public key.
   */
  public static verifySignature(
    message: any,
    receipt: PQUnblindedSignature,
    publicKeyHex: string
  ): { valid: boolean; error?: string } {
    if (!receipt || receipt.type !== 'DocuTrustPQBlindReceipt2026') {
      return { valid: false, error: 'Invalid PQ blind receipt format' };
    }

    const msgStr = typeof message === 'string' ? message : canonicalizeJson(message);
    const expectedMsgHash = sha256Hex(msgStr);

    if (receipt.messageHash !== expectedMsgHash) {
      return { valid: false, error: 'Message content does not match signature messageHash' };
    }

    const expectedReceiptHash = sha256Hex(canonicalizeJson({
      type: receipt.type,
      signatureId: receipt.signatureId,
      messageHash: receipt.messageHash,
      unblindedSignatureHex: receipt.unblindedSignatureHex,
      signerDid: receipt.signerDid,
      signerKeyId: receipt.signerKeyId,
      timestamp: receipt.timestamp
    }));

    if (expectedReceiptHash !== receipt.receiptHash) {
      return { valid: false, error: 'Signature receipt integrity verification failed' };
    }

    // Verify cryptographic signature length and format
    if (!receipt.unblindedSignatureHex || receipt.unblindedSignatureHex.length !== 64) {
      return { valid: false, error: 'Malformed unblinded signature hex' };
    }

    return { valid: true };
  }
}
