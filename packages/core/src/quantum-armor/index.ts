/**
 * @file packages/core/src/quantum-armor/index.ts
 * @description Post-Quantum Dual Hybrid KEM Armor (X25519 + NIST ML-KEM-768 Kyber)
 * Implements dual-layer classical + post-quantum key encapsulation with HKDF-SHA512 secret expansion
 * and AES-256-GCM envelope sealing, defending against "Harvest Now, Decrypt Later" quantum attacks.
 */

import * as crypto from 'crypto';
import { sha256Hex, encodeBase58 } from '../crypto/index.js';
import { generateKEMKeyPair, encapsulateSecret, decapsulateSecret, KEMKeyPair, EncapsulatedSecret } from '../kem/index.js';
import { encryptAESGCM, decryptAESGCM, EncryptedPayload } from '../encryption/index.js';

export interface DualKEMKeyPair {
  classicalPublicKeyHex: string;
  classicalPrivateKeyHex: string;
  pqcPublicKeyHex: string;
  pqcPrivateKeyHex: string;
  hybridPublicKey: {
    classicalPub: string;
    pqcPub: string;
    x25519PublicKeyHex: string;
    publicKeyHex: string;
    did: string;
  };
  hybridSecretKey: {
    classicalPriv: string;
    pqcPriv: string;
    x25519PrivateKeyHex: string;
    privateKeyHex: string;
  };
}

export interface DualKEMCiphertextBundle {
  classicalEphemeralPub: string;
  pqcEncapsulation: EncapsulatedSecret;
  authTag: string;
  algorithm: 'X25519-ML-KEM-768-HKDF-SHA512';
}

export interface DualKEMEncapsulationResult {
  sharedSecretHex: string;
  ciphertextBundle: DualKEMCiphertextBundle;
}

export interface QuantumSealedEnvelope {
  type: 'DocuTrustQuantumSealedEnvelope2026';
  ciphertextBundle: DualKEMCiphertextBundle;
  encryptedPayload: EncryptedPayload;
  recipientDid: string;
  timestamp: string;
}

export class DualHybridKEMEngine {
  /**
   * Generates a Dual-KEM Hybrid KeyPair (X25519 + NIST ML-KEM-768).
   */
  public static generateDualKeyPair(): DualKEMKeyPair {
    const kemKey = generateKEMKeyPair();

    return {
      classicalPublicKeyHex: kemKey.x25519PublicKeyHex,
      classicalPrivateKeyHex: kemKey.x25519PrivateKeyHex,
      pqcPublicKeyHex: kemKey.publicKeyHex,
      pqcPrivateKeyHex: kemKey.privateKeyHex,
      hybridPublicKey: {
        classicalPub: kemKey.x25519PublicKeyHex,
        pqcPub: kemKey.publicKeyHex,
        x25519PublicKeyHex: kemKey.x25519PublicKeyHex,
        publicKeyHex: kemKey.publicKeyHex,
        did: kemKey.hybridRecipientId
      },
      hybridSecretKey: {
        classicalPriv: kemKey.x25519PrivateKeyHex,
        pqcPriv: kemKey.privateKeyHex,
        x25519PrivateKeyHex: kemKey.x25519PrivateKeyHex,
        privateKeyHex: kemKey.privateKeyHex
      }
    };
  }

  /**
   * Encapsulates a dual shared secret against a recipient's hybrid public key.
   */
  public static encapsulate(recipientPubKey: {
    classicalPub?: string;
    pqcPub?: string;
    x25519PublicKeyHex?: string;
    publicKeyHex?: string;
  }): DualKEMEncapsulationResult {
    const pqcKeyParam = {
      x25519PublicKeyHex: recipientPubKey.x25519PublicKeyHex || recipientPubKey.classicalPub || '',
      publicKeyHex: recipientPubKey.publicKeyHex || recipientPubKey.pqcPub || ''
    };
    const pqcRes = encapsulateSecret(pqcKeyParam);
    const sharedSecretHex = pqcRes.sharedSecret.toString('hex');
    const authTag = sha256Hex(`DUAL_KEM_TAG:${pqcRes.encapsulation.ephemeralPublicKeyHex}:${pqcRes.encapsulation.ciphertext}:${sharedSecretHex}`).slice(0, 32);

    return {
      sharedSecretHex,
      ciphertextBundle: {
        classicalEphemeralPub: pqcRes.encapsulation.ephemeralPublicKeyHex,
        pqcEncapsulation: pqcRes.encapsulation,
        authTag,
        algorithm: 'X25519-ML-KEM-768-HKDF-SHA512'
      }
    };
  }

  /**
   * Decapsulates the dual shared secret using recipient's hybrid private key.
   */
  public static decapsulate(
    bundle: DualKEMCiphertextBundle,
    recipientHybridKeys: {
      classicalPriv?: string;
      pqcPriv?: string;
      x25519PrivateKeyHex?: string;
      publicKeyHex?: string;
      x25519PublicKeyHex?: string;
      privateKeyHex?: string;
      hybridRecipientId?: string;
    }
  ): string {
    const kemKeys: KEMKeyPair = {
      algorithm: 'ML-KEM-768-X25519-Hybrid',
      publicKeyHex: recipientHybridKeys.publicKeyHex || (recipientHybridKeys as any).pqcPub || '',
      privateKeyHex: recipientHybridKeys.privateKeyHex || recipientHybridKeys.pqcPriv || '',
      x25519PublicKeyHex: recipientHybridKeys.x25519PublicKeyHex || (recipientHybridKeys as any).classicalPub || '',
      x25519PrivateKeyHex: recipientHybridKeys.x25519PrivateKeyHex || recipientHybridKeys.classicalPriv || '',
      hybridRecipientId: recipientHybridKeys.hybridRecipientId || ''
    };
    const pqcSharedSecret = decapsulateSecret(bundle.pqcEncapsulation, kemKeys);
    return pqcSharedSecret.toString('hex');
  }

  /**
   * Encrypts and seals any credential payload inside a Quantum-Sealed Envelope.
   */
  public static sealCredential(
    payload: Record<string, any>,
    recipientHybridPub: {
      classicalPub?: string;
      pqcPub?: string;
      did?: string;
      x25519PublicKeyHex?: string;
      publicKeyHex?: string;
    }
  ): QuantumSealedEnvelope {
    const { sharedSecretHex, ciphertextBundle } = this.encapsulate(recipientHybridPub);
    const keyBuf = Buffer.from(sharedSecretHex, 'hex');

    const encryptedPayload = encryptAESGCM(JSON.stringify(payload), keyBuf);

    return {
      type: 'DocuTrustQuantumSealedEnvelope2026',
      ciphertextBundle,
      encryptedPayload,
      recipientDid: recipientHybridPub.did || 'did:kem:dual:recipient',
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Unseals and decrypts a Quantum-Sealed Envelope.
   */
  public static unsealCredential(
    envelope: QuantumSealedEnvelope,
    recipientHybridKeys: {
      classicalPriv?: string;
      pqcPriv?: string;
      x25519PrivateKeyHex?: string;
      publicKeyHex?: string;
      x25519PublicKeyHex?: string;
      privateKeyHex?: string;
      hybridRecipientId?: string;
    }
  ): Record<string, any> {
    const sharedSecretHex = this.decapsulate(envelope.ciphertextBundle, recipientHybridKeys);
    const keyBuf = Buffer.from(sharedSecretHex, 'hex');

    const decryptedBuf = decryptAESGCM(envelope.encryptedPayload, keyBuf);
    return JSON.parse(decryptedBuf.toString('utf8'));
  }
}
