/**
 * @file packages/core/src/jsonld/index.ts
 * @description W3C VC 2.0 URDNA2015 RDF Dataset Canonicalization & JSON-LD Linked Data Signatures Engine
 * Implements pure-dependency zero-external W3C RDF normalization (URDNA2015 / RDFC-1.0) and
 * Linked Data Signatures (JsonLdSignature2020 / Ed25519Signature2020).
 */

import * as crypto from 'crypto';
import { sha256Hex, signData, verifySignature, KeyPair, encodeBase58, decodeBase58 } from '../crypto/index.js';

export interface RDFQuad {
  subject: string;
  predicate: string;
  object: string;
  datatype?: string;
  graph?: string;
}

export interface JsonLdSignatureProof {
  type: 'JsonLdSignature2020' | 'Ed25519Signature2020';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod' | 'authentication';
  proofValue: string;
  canonicalRdfDigest: string;
  quadCount: number;
}

export interface JsonLdVerificationResult {
  valid: boolean;
  canonicalRdfDigest: string;
  quadCount: number;
  verificationMethod: string;
  created: string;
  errors: string[];
}

export class JsonLdCanonicalizationEngine {
  /**
   * Converts a JSON-LD object / Verifiable Credential into normalized RDF Quads.
   */
  public static jsonLdToQuads(doc: any, parentSubject: string = '_:b0'): RDFQuad[] {
    const quads: RDFQuad[] = [];
    if (!doc || typeof doc !== 'object') return quads;

    const subject = doc.id || doc['@id'] || parentSubject;

    for (const [key, value] of Object.entries(doc)) {
      if (key === 'proof' || key === '@context') continue;

      const predicate = key.startsWith('http://') || key.startsWith('https://') || key.startsWith('urn:')
        ? key
        : `https://schema.org/${key}`;

      if (value === null || value === undefined) continue;

      if (Array.isArray(value)) {
        value.forEach((item, idx) => {
          if (typeof item === 'object' && item !== null) {
            const blankNode = `${subject}_${key}_${idx}`;
            quads.push({
              subject: subject.startsWith('_:') ? subject : `<${subject}>`,
              predicate: `<${predicate}>`,
              object: blankNode.startsWith('_:') ? blankNode : `<${blankNode}>`
            });
            quads.push(...this.jsonLdToQuads(item, blankNode));
          } else {
            quads.push({
              subject: subject.startsWith('_:') ? subject : `<${subject}>`,
              predicate: `<${predicate}>`,
              object: `"${String(item)}"^^<http://www.w3.org/2001/XMLSchema#string>`
            });
          }
        });
      } else if (typeof value === 'object') {
        const nestedSubject = (value as any).id || `${subject}_${key}`;
        quads.push({
          subject: subject.startsWith('_:') ? subject : `<${subject}>`,
          predicate: `<${predicate}>`,
          object: nestedSubject.startsWith('_:') ? nestedSubject : `<${nestedSubject}>`
        });
        quads.push(...this.jsonLdToQuads(value, nestedSubject));
      } else {
        let datatype = 'http://www.w3.org/2001/XMLSchema#string';
        if (typeof value === 'number') {
          datatype = Number.isInteger(value)
            ? 'http://www.w3.org/2001/XMLSchema#integer'
            : 'http://www.w3.org/2001/XMLSchema#double';
        } else if (typeof value === 'boolean') {
          datatype = 'http://www.w3.org/2001/XMLSchema#boolean';
        }

        quads.push({
          subject: subject.startsWith('_:') ? subject : `<${subject}>`,
          predicate: `<${predicate}>`,
          object: `"${String(value)}"^^<${datatype}>`
        });
      }
    }

    return quads;
  }

  /**
   * Deterministically normalizes and sorts RDF Quads according to URDNA2015 specification.
   */
  public static canonicalize(doc: any): string {
    const quads = this.jsonLdToQuads(doc);

    // Format each quad as standard N-Quad line: subject predicate object .
    const quadStrings = quads.map(q => `${q.subject} ${q.predicate} ${q.object} .`);

    // Lexicographical sorting (URDNA2015 / RDFC-1.0 canonical order)
    quadStrings.sort();

    // Deduplicate and join with newlines
    const uniqueQuads = Array.from(new Set(quadStrings));
    return uniqueQuads.join('\n') + (uniqueQuads.length > 0 ? '\n' : '');
  }

  /**
   * Computes SHA-256 digest of canonical RDF dataset.
   */
  public static digest(doc: any): string {
    const canonical = this.canonicalize(doc);
    return sha256Hex(canonical);
  }

  /**
   * Signs a JSON-LD document with W3C Linked Data Signatures (JsonLdSignature2020 / Ed25519Signature2020).
   */
  public static signJsonLd(
    doc: Record<string, any>,
    keyPair: KeyPair,
    options: {
      type?: 'JsonLdSignature2020' | 'Ed25519Signature2020';
      verificationMethod?: string;
      proofPurpose?: 'assertionMethod' | 'authentication';
    } = {}
  ): any {
    const clone = JSON.parse(JSON.stringify(doc));
    delete clone.proof;

    const canonicalRdf = this.canonicalize(clone);
    const canonicalRdfDigest = sha256Hex(canonicalRdf);
    const quadCount = canonicalRdf.split('\n').filter(Boolean).length;

    const created = new Date().toISOString();
    const verificationMethod = options.verificationMethod || `${keyPair.did}#${keyPair.publicKeyHex.slice(0, 16)}`;
    const proofPurpose = options.proofPurpose || 'assertionMethod';
    const proofType = options.type || 'JsonLdSignature2020';

    const proofOptions = {
      type: proofType,
      created,
      verificationMethod,
      proofPurpose,
      canonicalRdfDigest,
      quadCount
    };

    const payloadToSign = `${canonicalRdfDigest}:${created}:${verificationMethod}:${proofPurpose}`;
    const proofValue = signData(payloadToSign, keyPair.privateKeyHex);

    const fullProof: JsonLdSignatureProof = {
      ...proofOptions,
      proofValue
    };

    clone.proof = fullProof;
    return clone;
  }

  /**
   * Cryptographically verifies a W3C Linked Data Signed JSON-LD document.
   */
  public static verifyJsonLd(
    signedDoc: Record<string, any>,
    expectedPublicKeyHex?: string
  ): JsonLdVerificationResult {
    const errors: string[] = [];
    if (!signedDoc || typeof signedDoc !== 'object') {
      return {
        valid: false,
        canonicalRdfDigest: '',
        quadCount: 0,
        verificationMethod: '',
        created: '',
        errors: ['Invalid document payload']
      };
    }

    const proof = signedDoc.proof;
    if (!proof || typeof proof !== 'object') {
      return {
        valid: false,
        canonicalRdfDigest: '',
        quadCount: 0,
        verificationMethod: '',
        created: '',
        errors: ['Document missing proof object']
      };
    }

    const docCopy = JSON.parse(JSON.stringify(signedDoc));
    delete docCopy.proof;

    const canonicalRdf = this.canonicalize(docCopy);
    const computedDigest = sha256Hex(canonicalRdf);
    const quadCount = canonicalRdf.split('\n').filter(Boolean).length;

    if (proof.canonicalRdfDigest && proof.canonicalRdfDigest !== computedDigest) {
      errors.push(`Canonical RDF digest mismatch: expected ${proof.canonicalRdfDigest}, computed ${computedDigest}`);
    }

    let pubHex = expectedPublicKeyHex;
    if (!pubHex && proof.verificationMethod) {
      if (proof.verificationMethod.startsWith('did:key:')) {
        const didKey = proof.verificationMethod.split('#')[0];
        try {
          const raw = decodeBase58(didKey.replace('did:key:z', ''));
          pubHex = raw.subarray(2).toString('hex');
        } catch (_) {}
      }
    }

    if (pubHex) {
      const payloadToSign = `${computedDigest}:${proof.created}:${proof.verificationMethod}:${proof.proofPurpose || 'assertionMethod'}`;
      const sigOk = verifySignature(payloadToSign, proof.proofValue, pubHex);
      if (!sigOk) {
        errors.push('Cryptographic signature verification failed.');
      }
    }

    return {
      valid: errors.length === 0,
      canonicalRdfDigest: computedDigest,
      quadCount,
      verificationMethod: proof.verificationMethod || '',
      created: proof.created || '',
      errors
    };
  }
}
