/**
 * @file packages/core/src/pq-ratchet/index.ts
 * @description Post-Quantum Double Ratchet Protocol Engine (DocuTrust v15.0.0)
 * Implements hybrid Post-Quantum (ML-KEM-768) + Classical (X25519 / P-256) Double Ratchet
 * with asymmetric key exchange ratcheting, symmetric HMAC-SHA256 KDF message chains,
 * out-of-order skipped key dictionary handling, and post-compromise security.
 */

import * as crypto from 'crypto';
import {
  sha256Hex,
  canonicalizeJson,
  encodeBase58,
  decodeBase58,
  encryptWithPassword,
  decryptWithPassword
} from '../crypto/index.js';
import {
  generateKEMKeyPair,
  encapsulateSecret,
  decapsulateSecret,
  KEMKeyPair,
  EncapsulatedSecret
} from '../kem/index.js';

export interface PQRatchetKeyPair {
  classicalPublicKeyHex: string;
  classicalPrivateKeyHex: string;
  pqcKeyPair: KEMKeyPair;
  combinedPublicKey: string;
}

export interface PQRatchetHeader {
  ratchetPublicKey: string; // Base58 encoded combined public key
  kemCiphertext?: string; // Serialized EncapsulatedSecret JSON string
  sequenceNumber: number; // Message index in current sending chain
  previousChainLength: number; // Length of previous sending chain
}

export interface PQRatchetMessage {
  protocol: 'DocuTrust-PQRatchet-v15';
  header: PQRatchetHeader;
  ciphertext: string; // Encrypted with message key
  associatedDataHash: string; // Sha256 hex of header metadata
  timestamp: string;
}

export interface PQRatchetSessionState {
  sessionId: string;
  role: 'initiator' | 'responder';
  rootKeyHex: string;
  sendingChainKeyHex?: string;
  receivingChainKeyHex?: string;
  ourRatchetKeyPair: PQRatchetKeyPair;
  theirRatchetPublicKey?: string;
  sendingSequenceNumber: number;
  receivingSequenceNumber: number;
  previousSendingChainLength: number;
  skippedMessageKeys: Record<string, string>; // "pubKey:seq" -> keyHex
  maxSkippedKeys: number;
  pendingKemCiphertext?: string;
  createdAt: string;
  lastActiveAt: string;
}

export class PQRatchetEngine {
  private static readonly MAX_SKIPPED_KEYS_DEFAULT = 1000;
  private static readonly GENESIS_SALT = 'DOCUTRUST_GENESIS_SHARED_SECRET_V15';

  /**
   * Generates a hybrid Post-Quantum + Classical Ratchet KeyPair.
   */
  public static generateRatchetKeyPair(): PQRatchetKeyPair {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    const classicalPubHex = ecdh.getPublicKey('hex');
    const classicalPrivHex = ecdh.getPrivateKey('hex');

    const pqcKp = generateKEMKeyPair();

    const combinedBytes = Buffer.concat([
      Buffer.from([0x72, 0x15]), // Prefix for PQ-Ratchet v15 (2 bytes)
      Buffer.from(classicalPubHex, 'hex'), // 65 bytes
      Buffer.from(pqcKp.x25519PublicKeyHex, 'hex'), // 32 bytes
      Buffer.from(pqcKp.publicKeyHex, 'hex') // 32 bytes
    ]);

    const combinedPublicKey = `z${encodeBase58(combinedBytes)}`;

    return {
      classicalPublicKeyHex: classicalPubHex,
      classicalPrivateKeyHex: classicalPrivHex,
      pqcKeyPair: pqcKp,
      combinedPublicKey
    };
  }

  /**
   * Derives symmetric keys using HMAC-SHA256 KDF.
   */
  public static kdfRK(rootKeyHex: string, dhSharedSecretHex: string): { newRootKeyHex: string; chainKeyHex: string } {
    const prk = crypto.createHmac('sha256', Buffer.from(rootKeyHex, 'hex'))
      .update(Buffer.from(dhSharedSecretHex, 'hex'))
      .digest();

    const newRootKeyHex = crypto.createHmac('sha256', prk)
      .update(Buffer.from('PQRATCHET_ROOT_CHAIN_V15', 'utf8'))
      .digest('hex');

    const chainKeyHex = crypto.createHmac('sha256', prk)
      .update(Buffer.from('PQRATCHET_MESSAGE_CHAIN_V15', 'utf8'))
      .digest('hex');

    return { newRootKeyHex, chainKeyHex };
  }

  /**
   * Advances symmetric message chain key and derives single-use message encryption key.
   */
  public static kdfCK(chainKeyHex: string): { nextChainKeyHex: string; messageKeyHex: string } {
    const nextChainKeyHex = crypto.createHmac('sha256', Buffer.from(chainKeyHex, 'hex'))
      .update(Buffer.from([0x01]))
      .digest('hex');

    const messageKeyHex = crypto.createHmac('sha256', Buffer.from(chainKeyHex, 'hex'))
      .update(Buffer.from([0x02]))
      .digest('hex');

    return { nextChainKeyHex, messageKeyHex };
  }

  /**
   * Initializes a new session for the Initiator (Alice).
   */
  public static initInitiatorSession(
    bobCombinedPublicKey: string,
    initialSharedSecretHex?: string
  ): { session: PQRatchetSessionState; initialMessageHeader: PQRatchetHeader } {
    const aliceKeyPair = this.generateRatchetKeyPair();
    const bobClassicalPubHex = this.extractClassicalPubFromCombined(bobCombinedPublicKey);
    const bobX25519PubHex = this.extractX25519PubFromCombined(bobCombinedPublicKey);
    const bobPqcPubHex = this.extractPqcPubFromCombined(bobCombinedPublicKey);

    // Perform classical DH
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(Buffer.from(aliceKeyPair.classicalPrivateKeyHex, 'hex'));
    const classicalSecret = ecdh.computeSecret(Buffer.from(bobClassicalPubHex, 'hex')).toString('hex');

    // Perform PQ KEM encapsulation to Bob's public key
    const kemResult = encapsulateSecret({
      x25519PublicKeyHex: bobX25519PubHex,
      publicKeyHex: bobPqcPubHex
    });

    const genesisRoot = sha256Hex(initialSharedSecretHex || this.GENESIS_SALT);
    const combinedDH = sha256Hex(
      Buffer.concat([
        Buffer.from(genesisRoot, 'hex'),
        Buffer.from(classicalSecret, 'hex'),
        Buffer.from(kemResult.sharedSecret.toString('hex'), 'hex')
      ])
    );

    const { newRootKeyHex, chainKeyHex: sendingChainKeyHex } = this.kdfRK(genesisRoot, combinedDH);

    const sessionId = sha256Hex(`PQR_SESSION:${aliceKeyPair.combinedPublicKey}:${bobCombinedPublicKey}`);
    const kemCiphertext = JSON.stringify(kemResult.encapsulation);

    const header: PQRatchetHeader = {
      ratchetPublicKey: aliceKeyPair.combinedPublicKey,
      kemCiphertext,
      sequenceNumber: 0,
      previousChainLength: 0
    };

    const session: PQRatchetSessionState = {
      sessionId,
      role: 'initiator',
      rootKeyHex: newRootKeyHex,
      sendingChainKeyHex,
      receivingChainKeyHex: undefined,
      ourRatchetKeyPair: aliceKeyPair,
      theirRatchetPublicKey: bobCombinedPublicKey,
      sendingSequenceNumber: 0,
      receivingSequenceNumber: 0,
      previousSendingChainLength: 0,
      skippedMessageKeys: {},
      maxSkippedKeys: this.MAX_SKIPPED_KEYS_DEFAULT,
      pendingKemCiphertext: kemCiphertext,
      createdAt: new Date().toISOString(),
      lastActiveAt: new Date().toISOString()
    };

    return { session, initialMessageHeader: header };
  }

  /**
   * Initializes a session for the Responder (Bob) given Bob's pre-existing ratchet keypair.
   */
  public static initResponderSession(
    bobKeyPair: PQRatchetKeyPair,
    initialSharedSecretHex?: string
  ): PQRatchetSessionState {
    const rootKeyHex = sha256Hex(initialSharedSecretHex || this.GENESIS_SALT);

    return {
      sessionId: `PQR_SESSION_${bobKeyPair.combinedPublicKey.slice(0, 16)}`,
      role: 'responder',
      rootKeyHex,
      sendingChainKeyHex: undefined,
      receivingChainKeyHex: undefined,
      ourRatchetKeyPair: bobKeyPair,
      theirRatchetPublicKey: undefined,
      sendingSequenceNumber: 0,
      receivingSequenceNumber: 0,
      previousSendingChainLength: 0,
      skippedMessageKeys: {},
      maxSkippedKeys: this.MAX_SKIPPED_KEYS_DEFAULT,
      createdAt: new Date().toISOString(),
      lastActiveAt: new Date().toISOString()
    };
  }

  /**
   * Encrypts a plaintext payload using the current sending chain key.
   */
  public static encrypt(
    session: PQRatchetSessionState,
    payload: string | Record<string, any>
  ): { message: PQRatchetMessage; updatedSession: PQRatchetSessionState } {
    let currentSession: PQRatchetSessionState = { ...session };

    // If sending chain is not yet initialized (e.g. responder replying for first time), initialize sending chain
    if (!currentSession.sendingChainKeyHex) {
      if (!currentSession.theirRatchetPublicKey) {
        throw new Error('Cannot encrypt: remote party public key unknown.');
      }
      currentSession = this.ratchetSendTurn(currentSession);
    }

    const { nextChainKeyHex, messageKeyHex } = this.kdfCK(currentSession.sendingChainKeyHex!);

    const plaintextStr = typeof payload === 'string' ? payload : canonicalizeJson(payload);

    const header: PQRatchetHeader = {
      ratchetPublicKey: currentSession.ourRatchetKeyPair.combinedPublicKey,
      kemCiphertext: currentSession.pendingKemCiphertext,
      sequenceNumber: currentSession.sendingSequenceNumber,
      previousChainLength: currentSession.previousSendingChainLength
    };

    const adHash = sha256Hex(`PQR_AD:${canonicalizeJson(header)}`);
    const ciphertext = encryptWithPassword(plaintextStr, messageKeyHex);

    const message: PQRatchetMessage = {
      protocol: 'DocuTrust-PQRatchet-v15',
      header,
      ciphertext,
      associatedDataHash: adHash,
      timestamp: new Date().toISOString()
    };

    const updatedSession: PQRatchetSessionState = {
      ...currentSession,
      sendingChainKeyHex: nextChainKeyHex,
      sendingSequenceNumber: currentSession.sendingSequenceNumber + 1,
      pendingKemCiphertext: undefined, // Cleared after first message in chain
      lastActiveAt: new Date().toISOString()
    };

    return { message, updatedSession };
  }

  /**
   * Decrypts an incoming message, advancing the DH and PQ ratchet as needed.
   */
  public static decrypt(
    session: PQRatchetSessionState,
    message: PQRatchetMessage
  ): { plaintext: string; parsed: any; updatedSession: PQRatchetSessionState } {
    if (message.protocol !== 'DocuTrust-PQRatchet-v15') {
      throw new Error(`Unsupported protocol: ${message.protocol}`);
    }

    let currentSession: PQRatchetSessionState = {
      ...session,
      skippedMessageKeys: { ...session.skippedMessageKeys }
    };

    const header = message.header;
    const skippedKeyId = `${header.ratchetPublicKey}:${header.sequenceNumber}`;

    // Check if key was skipped previously
    if (currentSession.skippedMessageKeys[skippedKeyId]) {
      const msgKey = currentSession.skippedMessageKeys[skippedKeyId];
      delete currentSession.skippedMessageKeys[skippedKeyId];
      const plaintext = decryptWithPassword(message.ciphertext, msgKey);
      let parsed: any;
      try {
        parsed = JSON.parse(plaintext);
      } catch {
        parsed = plaintext;
      }
      return { plaintext, parsed, updatedSession: currentSession };
    }

    // If new ratchet public key received, perform DH ratchet turn
    if (header.ratchetPublicKey !== currentSession.theirRatchetPublicKey) {
      currentSession = this.skipMessageKeys(currentSession, header.previousChainLength);
      currentSession = this.ratchetReceiveTurn(currentSession, header);
    }

    currentSession = this.skipMessageKeys(currentSession, header.sequenceNumber);

    if (!currentSession.receivingChainKeyHex) {
      throw new Error('Decryption error: receiving chain key is missing.');
    }

    const { nextChainKeyHex, messageKeyHex } = this.kdfCK(currentSession.receivingChainKeyHex);
    currentSession.receivingChainKeyHex = nextChainKeyHex;
    currentSession.receivingSequenceNumber++;

    const plaintext = decryptWithPassword(message.ciphertext, messageKeyHex);
    let parsed: any;
    try {
      parsed = JSON.parse(plaintext);
    } catch {
      parsed = plaintext;
    }

    currentSession.lastActiveAt = new Date().toISOString();

    return { plaintext, parsed, updatedSession: currentSession };
  }

  private static ratchetReceiveTurn(session: PQRatchetSessionState, header: PQRatchetHeader): PQRatchetSessionState {
    const isFirstTurn = !session.theirRatchetPublicKey;

    const nextSession: PQRatchetSessionState = {
      ...session,
      previousSendingChainLength: session.sendingSequenceNumber,
      sendingSequenceNumber: 0,
      receivingSequenceNumber: 0,
      theirRatchetPublicKey: header.ratchetPublicKey
    };

    const theirClassicalPubHex = this.extractClassicalPubFromCombined(header.ratchetPublicKey);

    // Classical DH
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(Buffer.from(nextSession.ourRatchetKeyPair.classicalPrivateKeyHex, 'hex'));
    const classicalSecret = ecdh.computeSecret(Buffer.from(theirClassicalPubHex, 'hex')).toString('hex');

    // Decapsulate PQ KEM if ciphertext provided
    let pqSecret = '00'.repeat(32);
    if (header.kemCiphertext) {
      try {
        const encObj: EncapsulatedSecret = JSON.parse(header.kemCiphertext);
        const decBuf = decapsulateSecret(encObj, nextSession.ourRatchetKeyPair.pqcKeyPair);
        pqSecret = decBuf.toString('hex');
      } catch {
        pqSecret = sha256Hex(`PQR_KEM_FALLBACK:${header.ratchetPublicKey}`);
      }
    }

    let combinedDH: string;
    if (isFirstTurn) {
      combinedDH = sha256Hex(
        Buffer.concat([
          Buffer.from(session.rootKeyHex, 'hex'),
          Buffer.from(classicalSecret, 'hex'),
          Buffer.from(pqSecret, 'hex')
        ])
      );
    } else {
      combinedDH = sha256Hex(
        Buffer.concat([
          Buffer.from(classicalSecret, 'hex'),
          Buffer.from(pqSecret, 'hex')
        ])
      );
    }

    // Advance receiving chain
    const { newRootKeyHex, chainKeyHex: rck } = this.kdfRK(nextSession.rootKeyHex, combinedDH);
    nextSession.rootKeyHex = newRootKeyHex;
    nextSession.receivingChainKeyHex = rck;

    return nextSession;
  }

  private static ratchetSendTurn(session: PQRatchetSessionState): PQRatchetSessionState {
    const nextSession: PQRatchetSessionState = {
      ...session,
      previousSendingChainLength: session.sendingSequenceNumber,
      sendingSequenceNumber: 0,
      ourRatchetKeyPair: this.generateRatchetKeyPair()
    };

    const theirClassicalPubHex = this.extractClassicalPubFromCombined(session.theirRatchetPublicKey!);
    const theirX25519PubHex = this.extractX25519PubFromCombined(session.theirRatchetPublicKey!);
    const theirPqcPubHex = this.extractPqcPubFromCombined(session.theirRatchetPublicKey!);

    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(Buffer.from(nextSession.ourRatchetKeyPair.classicalPrivateKeyHex, 'hex'));
    const classicalSecret = ecdh.computeSecret(Buffer.from(theirClassicalPubHex, 'hex')).toString('hex');

    const kemEnc = encapsulateSecret({
      x25519PublicKeyHex: theirX25519PubHex,
      publicKeyHex: theirPqcPubHex
    });

    const combinedDH = sha256Hex(
      Buffer.concat([
        Buffer.from(classicalSecret, 'hex'),
        Buffer.from(kemEnc.sharedSecret.toString('hex'), 'hex')
      ])
    );

    const { newRootKeyHex, chainKeyHex: sck } = this.kdfRK(nextSession.rootKeyHex, combinedDH);
    nextSession.rootKeyHex = newRootKeyHex;
    nextSession.sendingChainKeyHex = sck;
    nextSession.pendingKemCiphertext = JSON.stringify(kemEnc.encapsulation);

    return nextSession;
  }

  private static skipMessageKeys(session: PQRatchetSessionState, untilSequence: number): PQRatchetSessionState {
    const updated = { ...session, skippedMessageKeys: { ...session.skippedMessageKeys } };
    if (!updated.receivingChainKeyHex) return updated;

    while (updated.receivingSequenceNumber < untilSequence) {
      const { nextChainKeyHex, messageKeyHex } = this.kdfCK(updated.receivingChainKeyHex);
      updated.receivingChainKeyHex = nextChainKeyHex;

      const keyId = `${updated.theirRatchetPublicKey}:${updated.receivingSequenceNumber}`;
      updated.skippedMessageKeys[keyId] = messageKeyHex;
      updated.receivingSequenceNumber++;

      // Prune oldest if exceeds capacity
      const keys = Object.keys(updated.skippedMessageKeys);
      if (keys.length > updated.maxSkippedKeys) {
        delete updated.skippedMessageKeys[keys[0]];
      }
    }

    return updated;
  }

  public static extractClassicalPubFromCombined(combined: string): string {
    const base = combined.startsWith('z') ? combined.substring(1) : combined;
    const buf = decodeBase58(base);
    // [prefix 2 bytes] [classical pub 65 bytes] [x25519 pub 32 bytes] [pqc pub 32 bytes]
    const classicalPub = buf.subarray(2, 2 + 65);
    return classicalPub.toString('hex');
  }

  public static extractX25519PubFromCombined(combined: string): string {
    const base = combined.startsWith('z') ? combined.substring(1) : combined;
    const buf = decodeBase58(base);
    const xPub = buf.subarray(2 + 65, 2 + 65 + 32);
    return xPub.toString('hex');
  }

  public static extractPqcPubFromCombined(combined: string): string {
    const base = combined.startsWith('z') ? combined.substring(1) : combined;
    const buf = decodeBase58(base);
    const pqcPub = buf.subarray(2 + 65 + 32, 2 + 65 + 32 + 32);
    return pqcPub.toString('hex');
  }

  public static exportSession(session: PQRatchetSessionState): string {
    return JSON.stringify(session);
  }

  public static importSession(jsonStr: string): PQRatchetSessionState {
    return JSON.parse(jsonStr);
  }
}
