/**
 * @file packages/core/src/webauthn/index.ts
 * @description WebAuthn / FIDO2 Passkey & Hardware Security Key Attestation Engine (DocuTrust v11.0.0)
 * Verifies hardware-bound biometric passkeys, YubiKeys, and Apple Secure Enclaves
 * using NIST P-256 (secp256r1 / ES256) ECDSA digital signatures over W3C clientDataJSON and authenticatorData.
 */

import * as crypto from 'crypto';
import { sha256Hex, encodeBase58, decodeBase58, canonicalizeJson } from '../crypto/index.js';

export interface WebAuthnKeyPair {
  algorithm: 'ES256';
  curve: 'P-256';
  publicKeyHex: string; // Uncompressed P-256 public key (65 bytes hex starting with 04)
  privateKeyHex?: string;
  publicKeyPem?: string;
  privateKeyPem?: string;
  credentialId: string; // Base64url credential identifier
  did: string; // did:webauthn:z...
  keyId: string;
  rpId: string;
}

export interface WebAuthnAssertion {
  credentialId: string;
  clientDataJSON: string; // Base64 or JSON string
  authenticatorData: string; // Hex or Base64 authenticator binary data
  signatureHex: string; // DER or R||S hex signature
  userHandle?: string;
}

export interface ParsedAuthenticatorData {
  rpIdHashHex: string;
  flags: {
    userPresent: boolean;
    userVerified: boolean;
    attestedCredentialData: boolean;
    extensionDataIncluded: boolean;
    rawFlags: number;
  };
  signCount: number;
}

export interface WebAuthnVerificationResult {
  valid: boolean;
  userPresent: boolean;
  userVerified: boolean;
  signCount: number;
  rpIdMatch: boolean;
  challengeMatch: boolean;
  errors: string[];
}

export class WebAuthnAttestationEngine {
  /**
   * Generates a WebAuthn P-256 (secp256r1) keypair for passkey emulation and hardware testing.
   */
  public static generateKeyPair(rpId: string = 'localhost'): WebAuthnKeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });

    const pubDer = publicKey.export({ type: 'spki', format: 'der' });
    const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });

    const rawPub = pubDer.subarray(pubDer.length - 65);
    const publicKeyHex = rawPub.toString('hex');
    const privateKeyHex = privDer.subarray(privDer.length - 32).toString('hex');
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

    const credentialId = crypto.randomBytes(32).toString('base64url');

    // multicodec 0x1200 for P-256 WebAuthn
    const multicodec = Buffer.concat([
      Buffer.from([0x12, 0x00]),
      rawPub
    ]);
    const did = `did:webauthn:z${encodeBase58(multicodec)}`;
    const keyId = `${did}#passkey-1`;

    return {
      algorithm: 'ES256',
      curve: 'P-256',
      publicKeyHex,
      privateKeyHex,
      publicKeyPem,
      privateKeyPem,
      credentialId,
      did,
      keyId,
      rpId
    };
  }

  /**
   * Parses binary authenticatorData into structured flags and counters.
   */
  public static parseAuthenticatorData(authData: Buffer | string): ParsedAuthenticatorData {
    const buf = typeof authData === 'string'
      ? Buffer.from(authData.replace(/^0x/, ''), /^[0-9a-fA-F]+$/.test(authData) ? 'hex' : 'base64')
      : authData;

    if (buf.length < 37) {
      throw new Error(`Invalid authenticatorData length: ${buf.length} bytes (minimum 37 bytes required).`);
    }

    const rpIdHashHex = buf.subarray(0, 32).toString('hex');
    const flagsByte = buf[32];
    const signCount = buf.readUInt32BE(33);

    return {
      rpIdHashHex,
      flags: {
        userPresent: Boolean(flagsByte & 0x01),
        userVerified: Boolean(flagsByte & 0x04),
        attestedCredentialData: Boolean(flagsByte & 0x40),
        extensionDataIncluded: Boolean(flagsByte & 0x80),
        rawFlags: flagsByte
      },
      signCount
    };
  }

  /**
   * Creates a mock signed WebAuthn assertion for testing and automated issuance flows.
   */
  public static createAssertion(
    challenge: string,
    keyPair: WebAuthnKeyPair,
    options: {
      rpId?: string;
      origin?: string;
      userPresent?: boolean;
      userVerified?: boolean;
      signCount?: number;
    } = {}
  ): WebAuthnAssertion {
    const rpId = options.rpId || keyPair.rpId || 'localhost';
    const origin = options.origin || `https://${rpId}`;
    const userPresent = options.userPresent !== undefined ? options.userPresent : true;
    const userVerified = options.userVerified !== undefined ? options.userVerified : true;
    const signCount = options.signCount || 1;

    // 1. Build clientDataJSON
    const clientDataObj = {
      type: 'webauthn.get',
      challenge,
      origin,
      crossOrigin: false
    };
    const clientDataJSON = Buffer.from(JSON.stringify(clientDataObj), 'utf-8').toString('base64');
    const clientDataHash = crypto.createHash('sha256').update(Buffer.from(clientDataJSON, 'base64')).digest();

    // 2. Build authenticatorData
    const rpIdHash = crypto.createHash('sha256').update(rpId, 'utf-8').digest();
    let flags = 0;
    if (userPresent) flags |= 0x01;
    if (userVerified) flags |= 0x04;

    const countBuf = Buffer.alloc(4);
    countBuf.writeUInt32BE(signCount, 0);

    const authDataBuf = Buffer.concat([rpIdHash, Buffer.from([flags]), countBuf]);
    const authenticatorData = authDataBuf.toString('hex');

    // 3. Sign authData || clientDataHash with P-256 private key
    const signPayload = Buffer.concat([authDataBuf, clientDataHash]);

    const signer = crypto.createSign('SHA256');
    signer.update(signPayload);

    let keyObject: crypto.KeyObject;
    if (keyPair.privateKeyPem) {
      keyObject = crypto.createPrivateKey(keyPair.privateKeyPem);
    } else if (keyPair.privateKeyHex) {
      const privKeyDer = Buffer.concat([
        Buffer.from('30770201010420', 'hex'),
        Buffer.from(keyPair.privateKeyHex, 'hex'),
        Buffer.from('a00a06082a8648ce3d030107a144034200', 'hex'),
        Buffer.from(keyPair.publicKeyHex, 'hex')
      ]);
      keyObject = crypto.createPrivateKey({ key: privKeyDer, format: 'der', type: 'pkcs8' });
    } else {
      throw new Error('Private key required to create assertion signature.');
    }

    const signatureDer = signer.sign({
      key: keyObject,
      dsaEncoding: 'der'
    });

    return {
      credentialId: keyPair.credentialId,
      clientDataJSON,
      authenticatorData,
      signatureHex: signatureDer.toString('hex')
    };
  }

  /**
   * Verifies a WebAuthn / Passkey assertion against a public key and expected challenge.
   */
  public static verifyAssertion(
    assertion: WebAuthnAssertion,
    expectedChallenge: string,
    publicKey: string | WebAuthnKeyPair,
    options: {
      expectedRpId?: string;
      requireUserVerification?: boolean;
    } = {}
  ): WebAuthnVerificationResult {
    const errors: string[] = [];
    let userPresent = false;
    let userVerified = false;
    let signCount = 0;
    let rpIdMatch = true;
    let challengeMatch = false;

    try {
      let publicKeyHex = '';
      if (typeof publicKey === 'object' && publicKey.publicKeyHex) {
        publicKeyHex = publicKey.publicKeyHex;
      } else if (typeof publicKey === 'string') {
        if (publicKey.startsWith('did:webauthn:z')) {
          const multibase = publicKey.replace('did:webauthn:z', '').split('#')[0];
          const decoded = decodeBase58(multibase);
          publicKeyHex = decoded.subarray(2).toString('hex');
        } else {
          publicKeyHex = publicKey.replace(/^0x/, '');
        }
      }

      if (!publicKeyHex) {
        return {
          valid: false,
          userPresent: false,
          userVerified: false,
          signCount: 0,
          rpIdMatch: false,
          challengeMatch: false,
          errors: ['Missing or unresolvable WebAuthn public key.']
        };
      }

      // 1. Decode and verify clientDataJSON
      const clientDataRaw = Buffer.from(assertion.clientDataJSON, 'base64').toString('utf-8');
      const clientDataObj = JSON.parse(clientDataRaw);

      if (clientDataObj.type !== 'webauthn.get') {
        errors.push(`Invalid clientDataJSON type: ${clientDataObj.type}. Expected 'webauthn.get'.`);
      }

      if (clientDataObj.challenge === expectedChallenge) {
        challengeMatch = true;
      } else {
        errors.push(`Challenge mismatch: expected ${expectedChallenge}, received ${clientDataObj.challenge}`);
      }

      const clientDataHash = crypto.createHash('sha256').update(Buffer.from(assertion.clientDataJSON, 'base64')).digest();

      // 2. Parse authenticatorData
      const parsedAuth = this.parseAuthenticatorData(assertion.authenticatorData);
      userPresent = parsedAuth.flags.userPresent;
      userVerified = parsedAuth.flags.userVerified;
      signCount = parsedAuth.signCount;

      if (!userPresent) {
        errors.push('User Present flag (UP) is not set in authenticatorData.');
      }

      if (options.requireUserVerification && !userVerified) {
        errors.push('User Verified flag (UV) is required but not set.');
      }

      if (options.expectedRpId) {
        const expectedRpIdHash = crypto.createHash('sha256').update(options.expectedRpId, 'utf-8').digest('hex');
        if (parsedAuth.rpIdHashHex.toLowerCase() !== expectedRpIdHash.toLowerCase()) {
          rpIdMatch = false;
          errors.push(`RP ID hash mismatch for expected RP: ${options.expectedRpId}`);
        }
      }

      // 3. Verify P-256 ECDSA Signature
      const authDataBuf = Buffer.from(
        assertion.authenticatorData.replace(/^0x/, ''),
        /^[0-9a-fA-F]+$/.test(assertion.authenticatorData) ? 'hex' : 'base64'
      );
      const signPayload = Buffer.concat([authDataBuf, clientDataHash]);

      // SPKI header for P-256 (id-ecPublicKey, secp256r1)
      const spkiHeader = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
      const pubDer = Buffer.concat([spkiHeader, Buffer.from(publicKeyHex, 'hex')]);
      const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${pubDer.toString('base64')}\n-----END PUBLIC KEY-----`;

      const verifier = crypto.createVerify('SHA256');
      verifier.update(signPayload);

      const sigBuf = Buffer.from(
        assertion.signatureHex.replace(/^0x/, ''),
        /^[0-9a-fA-F]+$/.test(assertion.signatureHex) ? 'hex' : 'base64'
      );

      const signatureValid = verifier.verify(
        { key: publicKeyPem, dsaEncoding: 'der' },
        sigBuf
      );

      if (!signatureValid) {
        errors.push('Hardware P-256 ECDSA assertion signature verification failed.');
      }

      const valid = errors.length === 0 && signatureValid;

      return {
        valid,
        userPresent,
        userVerified,
        signCount,
        rpIdMatch,
        challengeMatch,
        errors
      };
    } catch (err: any) {
      return {
        valid: false,
        userPresent,
        userVerified,
        signCount,
        rpIdMatch,
        challengeMatch,
        errors: [...errors, `WebAuthn verification exception: ${err.message}`]
      };
    }
  }
}
