/**
 * @file packages/core/src/jwe/index.ts
 * @description Multi-Recipient JSON Web Encryption (JWE) Engine
 * Implements General JWE specification with ECDH-ES+A256KW and AES-256-GCM content encryption.
 */

import * as crypto from 'crypto';
import { decodeBase58, encodeBase58, canonicalizeJson } from '../crypto/index.js';

export interface JWERecipientHeader {
  kid: string;
  alg: string;
  epk?: {
    kty: string;
    crv: string;
    x: string;
  };
}

export interface JWERecipient {
  header: JWERecipientHeader;
  encrypted_key: string; // base64url
  iv?: string; // base64url
  tag?: string; // base64url
}

export interface GeneralJWE {
  protected: string; // base64url
  recipients: JWERecipient[];
  iv: string; // base64url
  ciphertext: string; // base64url
  tag: string; // base64url
  aad?: string; // base64url
}

export interface JWERecipientConfig {
  did: string;
  publicKey: string; // 32-byte public key (Hex or Base58)
}

export class MultiRecipientJWE {
  private static base64urlEncode(buf: Buffer): string {
    return buf.toString('base64url');
  }

  private static base64urlDecode(str: string): Buffer {
    return Buffer.from(str, 'base64url');
  }

  private static to32ByteBuffer(key: string | Buffer): Buffer {
    if (Buffer.isBuffer(key)) return key.subarray(0, 32);
    if (typeof key === 'string' && /^[0-9a-fA-F]{64}$/.test(key)) {
      return Buffer.from(key, 'hex');
    }
    try {
      const decoded = decodeBase58(key);
      if (decoded.length >= 32) return decoded.subarray(0, 32);
    } catch {
      // ignore
    }
    return Buffer.from(key, 'utf-8').subarray(0, 32);
  }

  /**
   * Generates a native X25519 encryption keypair compatible with JWE ECDH-ES.
   */
  public static generateRecipientKeyPair(): {
    did: string;
    publicKeyHex: string;
    privateKeyHex: string;
    publicKeyBase58: string;
    privateKeyBase58: string;
  } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    const pubDer = publicKey.export({ type: 'spki', format: 'der' });
    const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });
    const rawPub = pubDer.subarray(pubDer.length - 32);
    const rawPriv = privDer.subarray(privDer.length - 32);

    const multicodec = Buffer.concat([Buffer.from([0xec, 0x01]), rawPub]); // X25519 multicodec 0xec
    const did = `did:key:z${encodeBase58(multicodec)}`;

    return {
      did,
      publicKeyHex: rawPub.toString('hex'),
      privateKeyHex: rawPriv.toString('hex'),
      publicKeyBase58: encodeBase58(rawPub),
      privateKeyBase58: encodeBase58(rawPriv)
    };
  }

  /**
   * Encrypts a plaintext payload for multiple recipient DIDs in General JWE format.
   */
  public static encrypt(
    payload: string | Buffer | object,
    recipients: (JWERecipientConfig | { did: string; publicKeyBase58?: string; publicKeyHex?: string; publicKey?: string })[],
    customProtectedHeader: Record<string, any> = {}
  ): GeneralJWE {
    if (!recipients || recipients.length === 0) {
      throw new Error('MultiRecipientJWE requires at least one recipient.');
    }

    const plaintextBuffer = typeof payload === 'string'
      ? Buffer.from(payload, 'utf8')
      : Buffer.isBuffer(payload)
      ? payload
      : Buffer.from(canonicalizeJson(payload), 'utf8');

    // 1. Generate random 256-bit Content Encryption Key (CEK) and 96-bit IV
    const cek = crypto.randomBytes(32);
    const contentIv = crypto.randomBytes(12);

    // 2. Prepare protected header
    const protectedHeaderObj = {
      enc: 'A256GCM',
      typ: 'JWT',
      cty: typeof payload === 'object' && !Buffer.isBuffer(payload) ? 'json' : 'text',
      ...customProtectedHeader
    };
    const protectedHeaderB64 = this.base64urlEncode(Buffer.from(JSON.stringify(protectedHeaderObj), 'utf8'));

    // 3. Encrypt payload with AES-256-GCM using CEK and protected header as AAD
    const cipher = crypto.createCipheriv('aes-256-gcm', cek, contentIv);
    cipher.setAAD(Buffer.from(protectedHeaderB64, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
    const tag = cipher.getAuthTag();

    // 4. For each recipient, derive KEK using ephemeral ECDH + HKDF and wrap CEK
    const jweRecipients: JWERecipient[] = [];

    for (const recipient of recipients) {
      // Generate Ephemeral X25519 KeyPair
      const epk = crypto.generateKeyPairSync('x25519');
      const epkPubBuf = epk.publicKey.export({ type: 'spki', format: 'der' });
      const rawEpkPub = epkPubBuf.subarray(epkPubBuf.length - 32);

      // Convert recipient public key to DER SPKI
      const pubKeyInput = (recipient as any).publicKey || (recipient as any).publicKeyHex || (recipient as any).publicKeyBase58;
      const recipientRawPub = this.to32ByteBuffer(pubKeyInput);
      const recipientSpkiDer = Buffer.concat([
        Buffer.from('302a300506032b656e032100', 'hex'),
        recipientRawPub.subarray(0, 32)
      ]);
      const recipientKeyObject = crypto.createPublicKey({
        key: recipientSpkiDer,
        format: 'der',
        type: 'spki'
      });

      // Compute ECDH Shared Secret
      const sharedSecret = crypto.diffieHellman({
        privateKey: epk.privateKey,
        publicKey: recipientKeyObject
      });

      // Derive Key Encryption Key (KEK) via HKDF-SHA256
      const kek = crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from('DocuTrust-JWE-KEK-v1', 'utf8'), 32);

      // Encrypt CEK with KEK using AES-256-GCM
      const kekIv = crypto.randomBytes(12);
      const kekCipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(kek), kekIv);
      const encryptedCek = Buffer.concat([kekCipher.update(cek), kekCipher.final()]);
      const kekTag = kekCipher.getAuthTag();

      jweRecipients.push({
        header: {
          kid: recipient.did,
          alg: 'ECDH-ES+A256KW',
          epk: {
            kty: 'OKP',
            crv: 'X25519',
            x: this.base64urlEncode(rawEpkPub)
          }
        },
        encrypted_key: this.base64urlEncode(encryptedCek),
        iv: this.base64urlEncode(kekIv),
        tag: this.base64urlEncode(kekTag)
      });
    }

    return {
      protected: protectedHeaderB64,
      recipients: jweRecipients,
      iv: this.base64urlEncode(contentIv),
      ciphertext: this.base64urlEncode(ciphertext),
      tag: this.base64urlEncode(tag)
    };
  }

  /**
   * Decrypts a General JWE for a specific authorized recipient DID and private key.
   */
  public static decrypt(
    jwe: GeneralJWE,
    recipientDid: string,
    recipientPrivateKey: string | Buffer
  ): { plaintext: string; parsedJson?: any } {
    if (!jwe || !jwe.recipients || jwe.recipients.length === 0) {
      throw new Error('Invalid JWE structure: missing recipients.');
    }

    // Locate recipient entry matching recipientDid
    let targetRecipient = jwe.recipients.find(r => r.header.kid === recipientDid);
    if (!targetRecipient && jwe.recipients.length === 1) {
      targetRecipient = jwe.recipients[0];
    }
    if (!targetRecipient || !targetRecipient.header.epk) {
      throw new Error(`Recipient DID "${recipientDid}" is not authorized or found in JWE recipients.`);
    }

    const rawPrivateKey = this.to32ByteBuffer(recipientPrivateKey);
    const privPkcs8Der = Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      rawPrivateKey.subarray(0, 32)
    ]);
    const recipientPrivKeyObject = crypto.createPrivateKey({
      key: privPkcs8Der,
      format: 'der',
      type: 'pkcs8'
    });

    // Reconstruct Ephemeral Public Key
    const epkRawPub = this.base64urlDecode(targetRecipient.header.epk.x);
    const epkSpkiDer = Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'),
      epkRawPub.subarray(0, 32)
    ]);
    const epkPublicKeyObject = crypto.createPublicKey({
      key: epkSpkiDer,
      format: 'der',
      type: 'spki'
    });

    // Compute ECDH Shared Secret
    const sharedSecret = crypto.diffieHellman({
      privateKey: recipientPrivKeyObject,
      publicKey: epkPublicKeyObject
    });

    // Derive KEK via HKDF-SHA256
    const kek = crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from('DocuTrust-JWE-KEK-v1', 'utf8'), 32);

    // Decrypt CEK
    const encryptedCek = this.base64urlDecode(targetRecipient.encrypted_key);
    const kekIv = this.base64urlDecode(targetRecipient.iv!);
    const kekTag = this.base64urlDecode(targetRecipient.tag!);

    const kekDecipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(kek), kekIv);
    kekDecipher.setAuthTag(kekTag);
    const cek = Buffer.concat([kekDecipher.update(encryptedCek), kekDecipher.final()]);

    // Decrypt Content Ciphertext
    const contentIv = this.base64urlDecode(jwe.iv);
    const ciphertext = this.base64urlDecode(jwe.ciphertext);
    const contentTag = this.base64urlDecode(jwe.tag);

    const decipher = crypto.createDecipheriv('aes-256-gcm', cek, contentIv);
    decipher.setAAD(Buffer.from(jwe.protected, 'utf8'));
    decipher.setAuthTag(contentTag);

    const decryptedBuffer = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const plaintext = decryptedBuffer.toString('utf8');

    let parsedJson: any = undefined;
    try {
      parsedJson = JSON.parse(plaintext);
    } catch {
      // not JSON
    }

    return { plaintext, parsedJson };
  }
}
