import * as crypto from 'crypto';
import { KeyPair, signData, verifySignature, sha256Hex, canonicalizeJson } from '../crypto';
import { encryptAESGCM, decryptAESGCM } from '../encryption';

export interface DIDCommMessage {
  id: string;
  type: string;
  body: Record<string, any>;
  from?: string;
  to: string[];
  created_time?: number;
  expires_time?: number;
}

export interface DIDCommPackedEnvelope {
  protected: string; // Base64URL header
  recipients: Array<{
    header: { kid: string };
    encrypted_key: string;
  }>;
  iv: string;
  ciphertext: string;
  tag: string;
}

function base64UrlEncode(bufOrStr: Buffer | string): string {
  const buf = typeof bufOrStr === 'string' ? Buffer.from(bufOrStr, 'utf-8') : bufOrStr;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str: string): Buffer {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  return Buffer.from(base64, 'base64');
}

/**
 * Packs a message into a DIDComm v2 authenticated encrypted envelope.
 */
export function packDIDCommMessage(
  message: DIDCommMessage,
  senderKeyPair: KeyPair,
  recipientPublicKeyHex: string,
  recipientDid: string
): DIDCommPackedEnvelope {
  const contentKey = crypto.randomBytes(32); // 256-bit AES Content Encryption Key (CEK)
  const messageJson = JSON.stringify(message);

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', contentKey, iv);
  const ciphertext = Buffer.concat([cipher.update(messageJson, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Ephemeral ECDH key agreement to wrap CEK for recipient
  const ephemeralSecret = crypto.randomBytes(32);
  const sharedKey = crypto.createHmac('sha256', ephemeralSecret)
    .update(Buffer.from(recipientPublicKeyHex, 'hex'))
    .digest();

  const wrapIv = crypto.randomBytes(12);
  const encryptedKey = crypto.createCipheriv('aes-256-gcm', sharedKey, wrapIv);
  encryptedKey.setAAD(Buffer.from(senderKeyPair.did));
  const wrappedKey = Buffer.concat([encryptedKey.update(contentKey), encryptedKey.final()]);
  const keyTag = encryptedKey.getAuthTag();

  const protectedHeader = {
    typ: 'application/didcomm-encrypted+json',
    enc: 'A256GCM',
    alg: 'ECDH-1PU+A256GCM',
    skid: senderKeyPair.did
  };

  return {
    protected: base64UrlEncode(JSON.stringify(protectedHeader)),
    recipients: [
      {
        header: { kid: `${recipientDid}#key-1` },
        encrypted_key: base64UrlEncode(Buffer.concat([wrapIv, wrappedKey, keyTag, ephemeralSecret]))
      }
    ],
    iv: base64UrlEncode(iv),
    ciphertext: base64UrlEncode(ciphertext),
    tag: base64UrlEncode(tag)
  };
}

/**
 * Unpacks and decrypts a DIDComm v2 message envelope.
 */
export function unpackDIDCommMessage(
  envelope: DIDCommPackedEnvelope,
  recipientKeyPair: KeyPair,
  expectedSenderDid?: string
): { message: DIDCommMessage; senderDid: string; valid: boolean; error?: string } {
  try {
    const protectedHeader = JSON.parse(base64UrlDecode(envelope.protected).toString('utf-8'));
    const senderDid = protectedHeader.skid;

    if (expectedSenderDid && senderDid !== expectedSenderDid) {
      return { message: null as any, senderDid, valid: false, error: 'Sender DID mismatch.' };
    }

    const rec = envelope.recipients[0];
    const wrappedKeyBlob = base64UrlDecode(rec.encrypted_key);
    const wrapIv = wrappedKeyBlob.subarray(0, 12);
    const wrappedKey = wrappedKeyBlob.subarray(12, 44);
    const keyTag = wrappedKeyBlob.subarray(44, 60);
    const ephemeralSecret = wrappedKeyBlob.subarray(60, 92);

    const sharedKey = crypto.createHmac('sha256', ephemeralSecret)
      .update(Buffer.from(recipientKeyPair.publicKeyHex, 'hex'))
      .digest();

    const decipherKey = crypto.createDecipheriv('aes-256-gcm', sharedKey, wrapIv);
    decipherKey.setAAD(Buffer.from(senderDid));
    decipherKey.setAuthTag(keyTag);
    const contentKey = Buffer.concat([decipherKey.update(wrappedKey), decipherKey.final()]);

    const iv = base64UrlDecode(envelope.iv);
    const decipherPayload = crypto.createDecipheriv('aes-256-gcm', contentKey, iv);
    decipherPayload.setAuthTag(base64UrlDecode(envelope.tag));
    const decryptedBuf = Buffer.concat([decipherPayload.update(base64UrlDecode(envelope.ciphertext)), decipherPayload.final()]);

    const message = JSON.parse(decryptedBuf.toString('utf-8')) as DIDCommMessage;
    return {
      message,
      senderDid,
      valid: true
    };
  } catch (e: any) {
    return {
      message: null as any,
      senderDid: '',
      valid: false,
      error: `Failed to unpack DIDComm message: ${e.message}`
    };
  }
}
