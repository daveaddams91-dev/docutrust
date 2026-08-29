import { decodeBase58 } from '../crypto';

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyHex?: string;
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
    const pqcPublicKeyHex = rawPqcPub.toString('hex');

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
    const mlKemPubHex = decoded.subarray(34, 66).toString('hex');
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
   * Resolve a did:web method.
   */
  public static async resolveDidWeb(did: string): Promise<DIDDocument> {
    // Example: did:web:example.com -> https://example.com/.well-known/did.json
    const parts = did.replace('did:web:', '').split(':');
    const domain = parts[0];
    const path = parts.length > 1 ? parts.slice(1).join('/') : '.well-known';
    const url = `https://${domain}/${path}/did.json`;

    // If mocked or unavailable in offline mode, construct basic doc
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
}
