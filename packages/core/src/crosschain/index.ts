/**
 * @file packages/core/src/crosschain/index.ts
 * @description Multi-Chain Verifiable Attestation Bridge & Interoperability Relayer Engine (DocuTrust v11.0.0)
 * Bridges verifiable state roots, SMT non-membership proofs, and credential revocations across
 * Ethereum (1), Polygon (137), Arbitrum (42161), Optimism (10), and Base (8453) with cryptographic quorum verification.
 */

import * as crypto from 'crypto';
import { sha256Hex, canonicalizeJson, signData, verifySignature, KeyPair } from '../crypto/index.js';

export interface CrossChainMessage {
  messageId: string;
  sourceChainId: number;
  destinationChainId: number;
  sequenceNonce: number;
  stateRoot: string; // 32-byte Merkle / SMT root hex
  payloadHash: string; // SHA-256 of anchored credential or revocation list
  timestamp: number;
  senderAddress: string;
  recipientAddress: string;
}

export interface RelayerSignature {
  relayerDid: string;
  relayerPublicKeyHex: string;
  signatureHex: string;
  signedAt: string;
}

export interface CrossChainAttestation {
  type: 'DocuTrustCrossChainAttestation2026';
  version: '11.0.0';
  message: CrossChainMessage;
  messageDigest: string;
  signatures: RelayerSignature[];
  quorumThreshold: number;
  relayStatus: 'PENDING' | 'RELAYED' | 'EXECUTED';
}

export class CrossChainBridgeEngine {
  private static processedNonces: Map<string, Set<number>> = new Map();

  /**
   * Constructs a deterministic cross-chain attestation message packet.
   */
  public static createMessage(params: {
    sourceChainId: number;
    destinationChainId: number;
    sequenceNonce: number;
    stateRoot: string;
    payloadHash: string;
    senderAddress: string;
    recipientAddress: string;
    timestamp?: number;
  }): CrossChainMessage {
    const timestamp = params.timestamp || Math.floor(Date.now() / 1000);
    const cleanRoot = params.stateRoot.startsWith('0x') ? params.stateRoot : `0x${params.stateRoot}`;
    const cleanPayload = params.payloadHash.startsWith('0x') ? params.payloadHash : `0x${params.payloadHash}`;

    const rawIdPayload = `${params.sourceChainId}:${params.destinationChainId}:${params.sequenceNonce}:${cleanRoot}:${cleanPayload}:${timestamp}`;
    const messageId = `cc_msg_${sha256Hex(rawIdPayload).slice(0, 24)}`;

    return {
      messageId,
      sourceChainId: params.sourceChainId,
      destinationChainId: params.destinationChainId,
      sequenceNonce: params.sequenceNonce,
      stateRoot: cleanRoot,
      payloadHash: cleanPayload,
      timestamp,
      senderAddress: params.senderAddress.toLowerCase(),
      recipientAddress: params.recipientAddress.toLowerCase()
    };
  }

  /**
   * Computes the canonical EIP-191 / SHA-256 cross-chain packet digest.
   */
  public static computeMessageDigest(message: CrossChainMessage): string {
    const canonicalStr = canonicalizeJson({
      messageId: message.messageId,
      sourceChainId: message.sourceChainId,
      destinationChainId: message.destinationChainId,
      sequenceNonce: message.sequenceNonce,
      stateRoot: message.stateRoot,
      payloadHash: message.payloadHash,
      timestamp: message.timestamp,
      senderAddress: message.senderAddress,
      recipientAddress: message.recipientAddress
    });
    return sha256Hex(canonicalStr);
  }

  /**
   * Signs a cross-chain message packet with a designated relayer key.
   */
  public static signMessage(
    message: CrossChainMessage,
    relayerKeyPair: KeyPair,
    relayerDid?: string
  ): RelayerSignature {
    const digest = this.computeMessageDigest(message);
    const signatureHex = signData(digest, relayerKeyPair);
    const did = relayerDid || `did:key:z${relayerKeyPair.publicKeyHex.slice(0, 16)}`;

    return {
      relayerDid: did,
      relayerPublicKeyHex: relayerKeyPair.publicKeyHex,
      signatureHex,
      signedAt: new Date().toISOString()
    };
  }

  /**
   * Assembles a verified cross-chain attestation packet with multiple relayer signatures.
   */
  public static assembleAttestation(
    message: CrossChainMessage,
    signatures: RelayerSignature[],
    quorumThreshold: number = 1
  ): CrossChainAttestation {
    const messageDigest = this.computeMessageDigest(message);

    return {
      type: 'DocuTrustCrossChainAttestation2026',
      version: '11.0.0',
      message,
      messageDigest,
      signatures,
      quorumThreshold,
      relayStatus: signatures.length >= quorumThreshold ? 'RELAYED' : 'PENDING'
    };
  }

  /**
   * Resets the processed nonces cache (useful for testing or cache rotation).
   */
  public static resetNonceCache(): void {
    this.processedNonces.clear();
  }

  /**
   * Verifies a cross-chain attestation packet on destination chain or off-chain client.
   */
  public static verifyAttestation(
    attestation: CrossChainAttestation,
    allowedRelayerPublicKeys?: string[],
    options?: { executeNonce?: boolean }
  ): { valid: boolean; validSignaturesCount: number; errors: string[] } {
    const errors: string[] = [];
    const shouldExecute = options?.executeNonce !== false;

    if (!attestation || !attestation.message || !Array.isArray(attestation.signatures)) {
      return { valid: false, validSignaturesCount: 0, errors: ['Invalid attestation packet structure.'] };
    }

    const expectedDigest = this.computeMessageDigest(attestation.message);
    if (attestation.messageDigest.toLowerCase() !== expectedDigest.toLowerCase()) {
      errors.push(`Attestation messageDigest mismatch. Expected ${expectedDigest}, received ${attestation.messageDigest}`);
    }

    const keyFilter = allowedRelayerPublicKeys
      ? new Set(allowedRelayerPublicKeys.map(k => k.toLowerCase().replace(/^0x/, '')))
      : null;

    let validCount = 0;
    const seenSigners = new Set<string>();

    for (const sig of attestation.signatures) {
      const pubHex = sig.relayerPublicKeyHex.toLowerCase().replace(/^0x/, '');
      if (seenSigners.has(pubHex)) continue; // Prevent duplicate vote stuffing

      if (keyFilter && !keyFilter.has(pubHex)) {
        errors.push(`Relayer key ${pubHex.slice(0, 16)}... is not an authorized bridge validator.`);
        continue;
      }

      const isSigValid = verifySignature(expectedDigest, sig.signatureHex, pubHex);
      if (isSigValid) {
        validCount++;
        seenSigners.add(pubHex);
      } else {
        errors.push(`Signature verification failed for relayer: ${sig.relayerDid}`);
      }
    }

    if (validCount < attestation.quorumThreshold) {
      errors.push(`Insufficient relayer quorum: received ${validCount} valid signatures, required ${attestation.quorumThreshold}`);
    }

    // Replay check
    const chainKey = `${attestation.message.sourceChainId}:${attestation.message.destinationChainId}`;
    if (!this.processedNonces.has(chainKey)) {
      this.processedNonces.set(chainKey, new Set());
    }
    const nonces = this.processedNonces.get(chainKey)!;
    if (nonces.has(attestation.message.sequenceNonce)) {
      errors.push(`Replay attack detected: sequenceNonce ${attestation.message.sequenceNonce} already executed for chain route ${chainKey}`);
    }

    const valid = errors.length === 0 && validCount >= attestation.quorumThreshold;
    if (valid && shouldExecute) {
      nonces.add(attestation.message.sequenceNonce);
    }

    return {
      valid,
      validSignaturesCount: validCount,
      errors
    };
  }
}
