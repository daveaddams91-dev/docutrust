import { decodeBase58 } from '../crypto';

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyHex?: string;
  publicKeyJwk?: Record<string, any>;
  blockchainAccountId?: string;
  ethereumAddress?: string;
}

export interface DIDDocument {
  '@context': string[];
  id: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  capabilityInvocation?: string[];
  capabilityDelegation?: string[];
}

export class DIDResolver {
  private static registry: Map<string, DIDDocument> = new Map();

  /**
   * Register a custom DID document in local memory/cache.
   */
  public static registerDID(did: string, doc: DIDDocument): void {
    this.registry.set(did, doc);
  }

  /**
   * Resolve a DID into a standard W3C DID Document.
   */
  public static async resolve(did: string): Promise<DIDDocument> {
    if (this.registry.has(did)) {
      return this.registry.get(did)!;
    }

    if (did.startsWith('did:jwk:')) {
      return this.resolveDidJwk(did);
    }

    if (did.startsWith('did:key:')) {
      return this.resolveDidKey(did);
    }

    if (did.startsWith('did:pqc:')) {
      return this.resolveDidPqc(did);
    }

    if (did.startsWith('did:kem:')) {
      return this.resolveDidKem(did);
    }

    if (did.startsWith('did:bbs:')) {
      return this.resolveDidBbs(did);
    }

    if (did.startsWith('did:pkh:')) {
      return this.resolveDidPkh(did);
    }

    if (did.startsWith('did:ethr:')) {
      return this.resolveDidEthr(did);
    }

    if (did.startsWith('did:web:')) {
      return this.resolveDidWeb(did);
    }

    throw new Error(`Unsupported DID method: ${did}`);
  }

  /**
   * Deterministically resolve a did:pqc (ML-DSA-65 + Ed25519) without network access.
   */
  public static resolveDidPqc(did: string): DIDDocument {
    const multibase = did.replace('did:pqc:', '');
    if (!multibase.startsWith('z')) {
      throw new Error(`Invalid did:pqc format. Expected multibase 'z' prefix.`);
    }

    const decoded = decodeBase58(multibase.substring(1));
    if (decoded[0] !== 0x19 || decoded[1] !== 0x01) {
      throw new Error(`Unsupported did:pqc algorithm prefix. Expected 0x1901.`);
    }

    const rawClassicalPub = decoded.subarray(2, 34);
    const rawPqcPub = decoded.subarray(34, 66);
    const classicalPublicKeyHex = rawClassicalPub.toString('hex');

    const keyId = `${did}#pqc-hybrid-1`;
    const classicalKeyId = `${did}#classical-1`;

    const doc: DIDDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ],
      id: did,
      verificationMethod: [
        {
          id: keyId,
          type: 'ML-DSA-65-Ed25519-Hybrid-2026',
          controller: did,
          publicKeyMultibase: multibase,
          publicKeyHex: classicalPublicKeyHex
        },
        {
          id: classicalKeyId,
          type: 'Ed25519VerificationKey2020',
          controller: did,
          publicKeyHex: classicalPublicKeyHex
        }
      ],
      authentication: [keyId, classicalKeyId],
      assertionMethod: [keyId, classicalKeyId]
    };

    return doc;
  }

  /**
   * Deterministically resolve a did:key (Ed25519) without network access.
   */
  public static resolveDidKey(did: string): DIDDocument {
    const multibase = did.replace('did:key:', '');
    if (!multibase.startsWith('z')) {
      throw new Error(`Invalid did:key format. Expected multibase 'z' prefix.`);
    }

    const decoded = decodeBase58(multibase.substring(1));
    if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
      throw new Error(`Unsupported did:key algorithm. Expected Ed25519 (0xed01).`);
    }

    const rawPubKey = decoded.subarray(2);
    const publicKeyHex = rawPubKey.toString('hex');
    const keyId = `${did}#${multibase}`;

    const doc: DIDDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ],
      id: did,
      verificationMethod: [
        {
          id: keyId,
          type: 'Ed25519VerificationKey2020',
          controller: did,
          publicKeyMultibase: multibase,
          publicKeyHex
        }
      ],
      authentication: [keyId],
      assertionMethod: [keyId]
    };

    return doc;
  }

  /**
   * Deterministically resolve a did:kem (ML-KEM-768 + X25519) without network access.
   */
  public static resolveDidKem(did: string): DIDDocument {
    const multibase = did.replace('did:kem:', '');
    if (!multibase.startsWith('z')) {
      throw new Error(`Invalid did:kem format. Expected multibase 'z' prefix.`);
    }

    const decoded = decodeBase58(multibase.substring(1));
    if (decoded[0] !== 0x20 || decoded[1] !== 0x01) {
      throw new Error(`Unsupported did:kem algorithm prefix. Expected 0x2001.`);
    }

    const x25519PubHex = decoded.subarray(2, 34).toString('hex');
    const keyId = `${did}#kem-hybrid-1`;

    const doc: DIDDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1'
      ],
      id: did,
      verificationMethod: [
        {
          id: keyId,
          type: 'ML-KEM-768-X25519-Hybrid-2026',
          controller: did,
          publicKeyMultibase: multibase,
          publicKeyHex: x25519PubHex
        }
      ],
      authentication: [keyId],
      assertionMethod: [keyId],
      capabilityInvocation: [keyId]
    };

    return doc;
  }

  /**
   * Deterministically resolve a did:bbs (BBS+ BLS12-381) without network access.
   */
  public static resolveDidBbs(did: string): DIDDocument {
    const multibase = did.replace('did:bbs:', '');
    const keyId = `${did}#bbs-1`;

    const doc: DIDDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/bbs-2023/v1'
      ],
      id: did,
      verificationMethod: [
        {
          id: keyId,
          type: 'BBSPlusVerificationKey2026',
          controller: did,
          publicKeyMultibase: multibase
        }
      ],
      authentication: [keyId],
      assertionMethod: [keyId]
    };

    return doc;
  }

  /**
   * Deterministically resolve a did:pkh (EVM / Secp256k1) without network access.
   */
  public static resolveDidPkh(did: string): DIDDocument {
    // Format: did:pkh:eip155:1:0xab12...
    const parts = did.split(':');
    const ethAddress = parts[parts.length - 1];
    const keyId = `${did}#key-1`;

    return {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/secp256k1recovery-2020/v1'
      ],
      id: did,
      verificationMethod: [
        {
          id: keyId,
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: did,
          blockchainAccountId: parts.slice(2).join(':'),
          ethereumAddress: ethAddress
        }
      ],
      authentication: [keyId],
      assertionMethod: [keyId]
    };
  }

  /**
   * Deterministically resolve a did:ethr without network access.
   */
  public static resolveDidEthr(did: string): DIDDocument {
    // Format: did:ethr:0xab12...
    const ethAddress = did.replace('did:ethr:', '');
    const keyId = `${did}#controller`;

    return {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/secp256k1recovery-2020/v1'
      ],
      id: did,
      verificationMethod: [
        {
          id: keyId,
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: did,
          ethereumAddress: ethAddress
        }
      ],
      authentication: [keyId],
      assertionMethod: [keyId]
    };
  }

  /**
   * Resolve a did:web method.
   */
  public static async resolveDidWeb(did: string): Promise<DIDDocument> {
    const parts = did.replace('did:web:', '').split(':');
    const domain = parts[0];
    const path = parts.length > 1 ? parts.slice(1).join('/') : '.well-known';

    return {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [
        {
          id: `${did}#owner`,
          type: 'Ed25519VerificationKey2020',
          controller: did
        }
      ],
      authentication: [`${did}#owner`],
      assertionMethod: [`${did}#owner`]
    };
  }

  /**
   * Deterministically resolves a did:jwk (RFC 7517 JSON Web Key) without network access.
   */
  public static resolveDidJwk(did: string): DIDDocument {
    const rawEncoded = did.replace('did:jwk:', '');
    let jwk: Record<string, any>;
    try {
      const decodedJson = Buffer.from(rawEncoded, 'base64url').toString('utf8');
      jwk = JSON.parse(decodedJson);
    } catch {
      throw new Error(`Invalid did:jwk: unable to decode base64url payload.`);
    }

    if (!jwk.kty) {
      throw new Error(`Invalid did:jwk: missing 'kty' parameter in JWK.`);
    }

    let vmType = 'JsonWebKey2020';
    if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
      vmType = 'Ed25519VerificationKey2020';
    } else if (jwk.kty === 'EC' && jwk.crv === 'secp256k1') {
      vmType = 'EcdsaSecp256k1VerificationKey2019';
    } else if (jwk.kty === 'RSA') {
      vmType = 'RsaVerificationKey2018';
    }

    const keyId = `${did}#0`;

    return {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1'
      ],
      id: did,
      verificationMethod: [
        {
          id: keyId,
          type: vmType,
          controller: did,
          publicKeyJwk: jwk
        }
      ],
      authentication: [keyId],
      assertionMethod: [keyId],
      capabilityInvocation: [keyId],
      capabilityDelegation: [keyId]
    };
  }

  /**
   * Encodes a JSON Web Key (JWK) into a canonical did:jwk identifier.
   */
  public static encodeDidJwk(jwk: Record<string, any>): string {
    const sanitizedJwk: Record<string, any> = { ...jwk };
    delete sanitizedJwk.d; // Ensure private key material is never encoded
    delete sanitizedJwk.p;
    delete sanitizedJwk.q;
    delete sanitizedJwk.dp;
    delete sanitizedJwk.dq;
    delete sanitizedJwk.qi;

    const base64url = Buffer.from(JSON.stringify(sanitizedJwk)).toString('base64url');
    return `did:jwk:${base64url}`;
  }

  /**
   * Decodes a did:jwk identifier into its original JSON Web Key (JWK) representation.
   */
  public static decodeDidJwk(did: string): Record<string, any> {
    const rawEncoded = did.replace('did:jwk:', '');
    return JSON.parse(Buffer.from(rawEncoded, 'base64url').toString('utf8'));
  }
}

export function createDidJwk(jwk: Record<string, any>): string {
  return DIDResolver.encodeDidJwk(jwk);
}
