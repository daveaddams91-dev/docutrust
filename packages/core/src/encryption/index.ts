import * as crypto from 'crypto';

export interface EncryptedPayload {
  algorithm: 'AES-256-GCM' | 'ChaCha20-Poly1305';
  ciphertext: string; // Base64
  iv: string;         // Hex
  authTag: string;    // Hex
  salt: string;       // Hex
  keyDerivation: 'HKDF-SHA512' | 'PBKDF2-SHA512';
}

/**
 * Securely zeroizes sensitive memory buffers to prevent RAM dumping.
 */
export function zeroizeBuffer(buffer: Buffer): void {
  buffer.fill(0);
}

/**
 * Derives a 256-bit symmetric encryption key using HKDF-SHA512 with high entropy.
 */
export function deriveKeyHKDF(
  masterSecret: string | Buffer,
  salt: Buffer,
  info: string = 'docutrust-v1.3-envelope-encryption'
): Buffer {
  const secretBuf = typeof masterSecret === 'string' ? Buffer.from(masterSecret, 'utf-8') : masterSecret;
  return Buffer.from(crypto.hkdfSync('sha512', secretBuf, salt, Buffer.from(info, 'utf-8'), 32));
}

/**
 * Derives a 256-bit symmetric key using PBKDF2-SHA512 (100,000 iterations) for passphrases.
 */
export function deriveKeyPBKDF2(passphrase: string, salt: Buffer, iterations: number = 100000): Buffer {
  return crypto.pbkdf2Sync(passphrase, salt, iterations, 32, 'sha512');
}

/**
 * Encrypts arbitrary plaintext (string or Buffer) using AES-256-GCM authenticated encryption.
 */
export function encryptAESGCM(
  data: string | Buffer,
  passphraseOrKey: string | Buffer,
  usePassphraseKdf: boolean = false
): EncryptedPayload {
  const payloadBuf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12); // Standard 96-bit IV for GCM

  const key = usePassphraseKdf && typeof passphraseOrKey === 'string'
    ? deriveKeyPBKDF2(passphraseOrKey, salt)
    : deriveKeyHKDF(passphraseOrKey, salt);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(payloadBuf), cipher.final()]);
  const authTag = cipher.getAuthTag();

  zeroizeBuffer(key);

  return {
    algorithm: 'AES-256-GCM',
    ciphertext: encrypted.toString('base64'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    salt: salt.toString('hex'),
    keyDerivation: usePassphraseKdf ? 'PBKDF2-SHA512' : 'HKDF-SHA512'
  };
}

/**
 * Decrypts AES-256-GCM encrypted payload and verifies authentication tag.
 */
export function decryptAESGCM(
  payload: EncryptedPayload,
  passphraseOrKey: string | Buffer
): Buffer {
  if (payload.algorithm !== 'AES-256-GCM') {
    throw new Error(`Unsupported encryption algorithm: ${payload.algorithm}`);
  }

  const salt = Buffer.from(payload.salt, 'hex');
  const iv = Buffer.from(payload.iv, 'hex');
  const authTag = Buffer.from(payload.authTag, 'hex');
  const ciphertext = Buffer.from(payload.ciphertext, 'base64');

  const key = payload.keyDerivation === 'PBKDF2-SHA512' && typeof passphraseOrKey === 'string'
    ? deriveKeyPBKDF2(passphraseOrKey, salt)
    : deriveKeyHKDF(passphraseOrKey, salt);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  try {
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    zeroizeBuffer(key);
    return decrypted;
  } catch (err) {
    zeroizeBuffer(key);
    throw new Error('Decryption or cryptographic authentication tag verification failed. Ciphertext may be corrupted or tampered.');
  }
}
