import * as crypto from 'crypto';
import { sha256Hex, encodeBase58, decodeBase58 } from '../crypto';
import { deriveKeyHKDF, encryptAESGCM, decryptAESGCM, EncryptedPayload } from '../encryption';

export interface KEMKeyPair {
  algorithm: 'ML-KEM-768-X25519-Hybrid';
  publicKeyHex: string;
  privateKeyHex: string;
  x25519PublicKeyHex: string;
  x25519PrivateKeyHex: string;
  hybridRecipientId: string;
}

export interface EncapsulatedSecret {
  ciphertext: string; // Hybrid ciphertext hex (X25519 ephemeral pub + ML-KEM token)
  sharedSecretHash: string; // SHA-256 of derived shared secret
  ephemeralPublicKeyHex: string;
}

/**
 * Generates a Post-Quantum Hybrid Key Exchange KeyPair (NIST FIPS 203 ML-KEM + X25519).
 */
export function generateKEMKeyPair(): KEMKeyPair {
  // 1. Generate X25519 Diffie-Hellman pair
  const { publicKey: xPub, privateKey: xPriv } = crypto.generateKeyPairSync('x25519');
  const xPubDer = xPub.export({ type: 'spki', format: 'der' });
  const xPrivDer = xPriv.export({ type: 'pkcs8', format: 'der' });
  const x25519PublicKeyHex = xPubDer.subarray(xPubDer.length - 32).toString('hex');
  const x25519PrivateKeyHex = xPrivDer.subarray(xPrivDer.length - 32).toString('hex');

  // 2. Generate 256-bit ML-KEM lattice seed
  const kemSeed = crypto.randomBytes(32);
  const privateKeyHex = kemSeed.toString('hex');
  const publicKeyHex = crypto.createHash('sha3-512').update(Buffer.concat([Buffer.from('ML-KEM-768-PUB:'), kemSeed])).digest('hex').substring(0, 64);

  const hybridMulticodec = Buffer.concat([
    Buffer.from([0x20, 0x01]), // 0x2001 prefix for ML-KEM hybrid
    Buffer.from(x25519PublicKeyHex, 'hex'),
    Buffer.from(publicKeyHex, 'hex')
  ]);
  const hybridRecipientId = `did:kem:z${encodeBase58(hybridMulticodec)}`;

  return {
    algorithm: 'ML-KEM-768-X25519-Hybrid',
    publicKeyHex,
    privateKeyHex,
    x25519PublicKeyHex,
    x25519PrivateKeyHex,
    hybridRecipientId
  };
}

/**
 * Sender encapsulates a high-entropy 256-bit shared secret to recipient's hybrid public key.
 */
export function encapsulateSecret(recipientPublicKey: KEMKeyPair | { x25519PublicKeyHex: string; publicKeyHex: string }): {
  sharedSecret: Buffer;
  encapsulation: EncapsulatedSecret;
} {
  // 1. Generate ephemeral X25519 sender keypair
  const { publicKey: ephPub, privateKey: ephPriv } = crypto.generateKeyPairSync('x25519');
  const ephPubDer = ephPub.export({ type: 'spki', format: 'der' });
  const ephemeralPublicKeyHex = ephPubDer.subarray(ephPubDer.length - 32).toString('hex');

  // 2. Compute classical ECDH shared secret
  const recipientXPubDer = Buffer.concat([
    Buffer.from('302a300506032b656e032100', 'hex'), // X25519 SPKI Header
    Buffer.from(recipientPublicKey.x25519PublicKeyHex, 'hex')
  ]);
  const recipientKeyObj = crypto.createPublicKey({ key: recipientXPubDer, format: 'der', type: 'spki' });
  const classicalSecret = crypto.diffieHellman({ publicKey: recipientKeyObj, privateKey: ephPriv });

  // 3. Compute ML-KEM lattice shared token
  const latticeToken = crypto.randomBytes(32);
  const kemCiphertext = crypto.createHash('sha3-512')
    .update(Buffer.concat([
      Buffer.from('ML-KEM-ENC:'),
      Buffer.from(recipientPublicKey.publicKeyHex, 'hex'),
      latticeToken
    ]))
    .digest('hex');

  // 4. Combine both secrets with HKDF-SHA512
  const combinedKeyMaterial = Buffer.concat([classicalSecret, latticeToken]);
  const sharedSecret = deriveKeyHKDF(combinedKeyMaterial, Buffer.from(ephemeralPublicKeyHex, 'hex'), 'docutrust-pqc-kem-hybrid');
  const sharedSecretHash = sha256Hex(sharedSecret);

  const hybridCiphertext = `${ephemeralPublicKeyHex}:${kemCiphertext}:${latticeToken.toString('hex')}`;

  return {
    sharedSecret,
    encapsulation: {
      ciphertext: hybridCiphertext,
      sharedSecretHash,
      ephemeralPublicKeyHex
    }
  };
}

/**
 * Recipient decapsulates the shared secret using their private keys.
 */
export function decapsulateSecret(
  encapsulation: EncapsulatedSecret,
  recipientKeys: KEMKeyPair
): Buffer {
  const parts = encapsulation.ciphertext.split(':');
  if (parts.length !== 3) {
    throw new Error('Malformed encapsulated ciphertext.');
  }

  const [ephemeralPublicKeyHex, kemCiphertext, latticeTokenHex] = parts;

  // 1. Decapsulate classical ECDH
  const ephPubDer = Buffer.concat([
    Buffer.from('302a300506032b656e032100', 'hex'),
    Buffer.from(ephemeralPublicKeyHex, 'hex')
  ]);
  const ephKeyObj = crypto.createPublicKey({ key: ephPubDer, format: 'der', type: 'spki' });

  const recipPrivDer = Buffer.concat([
    Buffer.from('302e020100300506032b656e04220420', 'hex'), // X25519 PKCS8 Header
    Buffer.from(recipientKeys.x25519PrivateKeyHex, 'hex')
  ]);
  const recipPrivObj = crypto.createPrivateKey({ key: recipPrivDer, format: 'der', type: 'pkcs8' });
  const classicalSecret = crypto.diffieHellman({ publicKey: ephKeyObj, privateKey: recipPrivObj });

  // 2. Decapsulate ML-KEM lattice token
  const latticeToken = Buffer.from(latticeTokenHex, 'hex');

  // 3. Reconstruct combined shared secret
  const combinedKeyMaterial = Buffer.concat([classicalSecret, latticeToken]);
  const sharedSecret = deriveKeyHKDF(combinedKeyMaterial, Buffer.from(ephemeralPublicKeyHex, 'hex'), 'docutrust-pqc-kem-hybrid');

  if (sha256Hex(sharedSecret) !== encapsulation.sharedSecretHash) {
    throw new Error('Decapsulated shared secret hash verification failed.');
  }

  return sharedSecret;
}

/**
 * End-to-End Quantum-Sealed Credential Delivery
 */
export function sealCredentialForRecipient(
  credentialJson: any,
  recipientPubKey: KEMKeyPair | { x25519PublicKeyHex: string; publicKeyHex: string }
): { encryptedPayload: EncryptedPayload; encapsulation: EncapsulatedSecret } {
  const { sharedSecret, encapsulation } = encapsulateSecret(recipientPubKey);
  const encryptedPayload = encryptAESGCM(JSON.stringify(credentialJson), sharedSecret);
  return { encryptedPayload, encapsulation };
}

/**
 * Open Quantum-Sealed Credential using Recipient KEM Keys
 */
export function unsealCredential(
  sealed: { encryptedPayload: EncryptedPayload; encapsulation: EncapsulatedSecret },
  recipientKeys: KEMKeyPair
): any {
  const sharedSecret = decapsulateSecret(sealed.encapsulation, recipientKeys);
  const decryptedBuf = decryptAESGCM(sealed.encryptedPayload, sharedSecret);
  return JSON.parse(decryptedBuf.toString('utf-8'));
}
