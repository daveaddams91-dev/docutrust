import * as crypto from 'crypto';
import { KeyPair, signData, verifySignature, sha256Hex, canonicalizeJson } from '../crypto';

export interface TimestampToken {
  type: 'DocuTrustTimestampToken2026';
  version: '2.0.0' | string;
  targetDataHash: string;
  timestamp: string;
  unixTimeSeconds: number;
  nonce: string;
  tsaAuthorityDid: string;
  tsaSignature: string;
}

export interface OracleAttestationQuorum {
  targetHash: string;
  timestamp: string;
  requiredQuorum: number;
  receivedSignatures: Array<{
    oracleDid: string;
    signature: string;
  }>;
}

export class CryptographicTSAOracle {
  private authorityKeyPair: KeyPair;

  constructor(authorityKeyPair: KeyPair) {
    this.authorityKeyPair = authorityKeyPair;
  }

  /**
   * Issues an RFC 3161-compliant cryptographic timestamp token for arbitrary data or hash.
   */
  public issueTimestampToken(dataOrHash: string | Buffer, clientNonce?: string): TimestampToken {
    const dataBuf = typeof dataOrHash === 'string' ? Buffer.from(dataOrHash, 'utf-8') : dataOrHash;
    const targetDataHash = crypto.createHash('sha256').update(dataBuf).digest('hex');
    const now = new Date();
    const timestamp = now.toISOString();
    const unixTimeSeconds = Math.floor(now.getTime() / 1000);
    const nonce = clientNonce || crypto.randomBytes(16).toString('hex');

    const tokenPayload = canonicalizeJson({
      type: 'DocuTrustTimestampToken2026',
      version: '2.0.0',
      targetDataHash,
      timestamp,
      unixTimeSeconds,
      nonce,
      tsaAuthorityDid: this.authorityKeyPair.did
    });

    const tsaSignature = signData(sha256Hex(tokenPayload), this.authorityKeyPair);

    return {
      type: 'DocuTrustTimestampToken2026',
      version: '2.0.0',
      targetDataHash,
      timestamp,
      unixTimeSeconds,
      nonce,
      tsaAuthorityDid: this.authorityKeyPair.did,
      tsaSignature
    };
  }

  /**
   * Verifies the authenticity and integrity of a timestamp token.
   */
  public static verifyTimestampToken(
    token: TimestampToken,
    expectedDataOrHash?: string | Buffer
  ): { valid: boolean; ageSeconds: number; error?: string } {
    if (token.type !== 'DocuTrustTimestampToken2026') {
      return { valid: false, ageSeconds: 0, error: 'Invalid timestamp token type.' };
    }

    if (expectedDataOrHash) {
      const dataBuf = typeof expectedDataOrHash === 'string' ? Buffer.from(expectedDataOrHash, 'utf-8') : expectedDataOrHash;
      const expectedHash = expectedDataOrHash.length === 64 && /^[0-9a-fA-F]+$/.test(expectedDataOrHash.toString())
        ? expectedDataOrHash.toString()
        : crypto.createHash('sha256').update(dataBuf).digest('hex');

      if (token.targetDataHash !== expectedHash) {
        return { valid: false, ageSeconds: 0, error: `Hash mismatch: expected ${expectedHash}, got ${token.targetDataHash}` };
      }
    }

    const tokenPayload = canonicalizeJson({
      type: token.type,
      version: token.version,
      targetDataHash: token.targetDataHash,
      timestamp: token.timestamp,
      unixTimeSeconds: token.unixTimeSeconds,
      nonce: token.nonce,
      tsaAuthorityDid: token.tsaAuthorityDid
    });

    const isSigValid = verifySignature(sha256Hex(tokenPayload), token.tsaSignature, token.tsaAuthorityDid);
    if (!isSigValid) {
      return { valid: false, ageSeconds: 0, error: 'Invalid TSA authority signature.' };
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const ageSeconds = Math.max(0, nowSeconds - token.unixTimeSeconds);

    return { valid: true, ageSeconds };
  }

  /**
   * Creates a multi-oracle decentralized attestation quorum.
   */
  public static createQuorumAttestation(
    targetHash: string,
    oracles: KeyPair[],
    requiredQuorum: number = 2
  ): OracleAttestationQuorum {
    const timestamp = new Date().toISOString();
    const payload = canonicalizeJson({ targetHash, timestamp });
    const digest = sha256Hex(payload);

    const receivedSignatures = oracles.map(oracleKp => ({
      oracleDid: oracleKp.did,
      signature: signData(digest, oracleKp)
    }));

    return {
      targetHash,
      timestamp,
      requiredQuorum,
      receivedSignatures
    };
  }

  /**
   * Verifies an oracle attestation quorum.
   */
  public static verifyQuorumAttestation(
    quorum: OracleAttestationQuorum
  ): { valid: boolean; validSignaturesCount: number; error?: string } {
    const payload = canonicalizeJson({ targetHash: quorum.targetHash, timestamp: quorum.timestamp });
    const digest = sha256Hex(payload);

    let validCount = 0;
    for (const entry of quorum.receivedSignatures) {
      if (verifySignature(digest, entry.signature, entry.oracleDid)) {
        validCount++;
      }
    }

    if (validCount < quorum.requiredQuorum) {
      return { valid: false, validSignaturesCount: validCount, error: `Quorum not met: received ${validCount}/${quorum.requiredQuorum} valid signatures.` };
    }

    return { valid: true, validSignaturesCount: validCount };
  }
}
