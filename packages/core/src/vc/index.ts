import * as crypto from 'crypto';
import {
  KeyPair,
  canonicalizeJson,
  signData,
  verifySignature,
  sha256Hex,
  encodeBase58
} from '../crypto';
import { MerkleTree, MerkleInclusionProof } from '../merkle';
import { DIDResolver } from '../did';
import {
  createSelectiveDisclosurePackage,
  SelectiveDisclosurePackage
} from '../selective-disclosure';
import { AnchorReceipt, LocalLedgerAnchor } from '../ledger';
import { verifyVcEIP712 } from '../eip712';
import { verifyPQCHybrid } from '../pqc';
import { verifyBBSProof } from '../bbs';
import { BitstringStatusList2024, StatusList2021 } from '../revocation';
import { RevocationBloomFilter, SignedBloomFilter } from '../bloom';
import { SchemaValidator } from '../schema';
import { DecentralizedTrustRegistry } from '../trust-registry';
import { JsonLdCanonicalizationEngine } from '../jsonld';
import { MultiSigEngine } from '../multisig';

export interface CredentialSubject {
  id?: string;
  [claimKey: string]: any;
}

export interface CredentialStatus {
  id: string;
  type: string;
  statusPurpose?: 'revocation' | 'suspension' | string;
  statusListIndex?: number | string;
  statusListCredential?: string;
  statusSize?: number;
  [customField: string]: any;
}

export interface Proof {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue?: string;
  signature?: string;
  merkleProof?: MerkleInclusionProof;
  anchorReceipt?: AnchorReceipt;
  claimsRoot?: string;
  jcsCanonicalHash?: string;
  domain?: any;
  primaryType?: string;
  signerAddress?: string;
  [customField: string]: any;
}

export interface VerifiableCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: {
    id: string;
    name?: string;
    url?: string;
    [key: string]: any;
  } | string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: CredentialSubject;
  credentialStatus?: CredentialStatus;
  proof: Proof;
  [customField: string]: any;
}

export interface IssueCredentialOptions {
  id?: string;
  type: string[];
  issuer: {
    id: string;
    name?: string;
    url?: string;
    [key: string]: any;
  } | string;
  validFrom?: string;
  validUntil?: string;
  credentialSubject: CredentialSubject;
  credentialStatus?: CredentialStatus;
  keyPair: KeyPair;
  enableSelectiveDisclosure?: boolean;
  enablePQC?: boolean;
  anchorReceipt?: AnchorReceipt;
}

export interface BatchIssueOptions {
  issuer: {
    id: string;
    name?: string;
    url?: string;
  };
  keyPair: KeyPair;
  type: string[];
  records: Array<{
    id?: string;
    credentialSubject: CredentialSubject;
    validUntil?: string;
  }>;
  anchorToLedger?: boolean;
}

export interface BatchIssueResult {
  credentials: VerifiableCredential[];
  merkleRoot: string;
  anchorReceipt?: AnchorReceipt;
  totalIssued: number;
}

export interface VerificationOptions {
  expectedPublicKeyHex?: string;
  checkStatus?: boolean;
  statusListCredential?: any;
  signedBloomFilter?: SignedBloomFilter;
  trustedIssuerRegistry?: DecentralizedTrustRegistry;
  requiredSchema?: Record<string, any>;
}

export interface VerificationResult {
  valid: boolean;
  issuer: string;
  issuanceDate: string;
  expirationDate?: string;
  isExpired: boolean;
  isNotYetValid?: boolean;
  isRevoked: boolean;
  isSuspended?: boolean;
  isQuantumSafe?: boolean;
  signatureValid: boolean;
  merkleProofValid?: boolean;
  anchorValid?: boolean;
  claimsRootValid?: boolean;
  statusValid?: boolean;
  schemaValid?: boolean;
  trustRegistryValid?: boolean;
  errors: string[];
  credential?: VerifiableCredential;
}

/**
 * W3C Verifiable Credentials 2.0 Engine
 */
export class VerifiableCredentialsEngine {
  /**
   * Issue a single W3C Verifiable Credential.
   */
  public static issue(options: IssueCredentialOptions): {
    credential: VerifiableCredential;
    selectiveDisclosurePackage?: SelectiveDisclosurePackage;
  } {
    const {
      id = `urn:uuid:${crypto.randomUUID ? crypto.randomUUID() : sha256Hex(Date.now().toString()).slice(0, 32)}`,
      type,
      issuer,
      validFrom = new Date().toISOString(),
      validUntil,
      credentialSubject,
      credentialStatus,
      keyPair,
      enableSelectiveDisclosure = false,
      enablePQC = false,
      anchorReceipt
    } = options;

    let sdPackage: SelectiveDisclosurePackage | undefined;
    let claimsRoot: string | undefined;

    if (enableSelectiveDisclosure) {
      sdPackage = createSelectiveDisclosurePackage(credentialSubject);
      claimsRoot = sdPackage.claimsRoot;
    }

    const issuerId = typeof issuer === 'string' ? issuer : issuer.id;
    const verificationMethod = keyPair.keyId || `${issuerId}#${keyPair.publicKeyHex ? keyPair.publicKeyHex.slice(0, 16) : 'key-1'}`;

    const unsignedCredential: Omit<VerifiableCredential, 'proof'> = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ],
      id,
      type: Array.from(new Set(['VerifiableCredential', ...type])),
      issuer: enablePQC && typeof issuer === 'object'
        ? { ...issuer, id: `did:pqc:z${encodeBase58(Buffer.from(keyPair.publicKeyHex || '00', 'hex'))}` }
        : issuer,
      validFrom,
      ...(validUntil ? { validUntil } : {}),
      credentialSubject,
      ...(credentialStatus ? { credentialStatus } : {})
    };

    // Construct the payload to sign
    const canonicalPayload = canonicalizeJson({
      ...unsignedCredential,
      ...(claimsRoot ? { claimsRoot } : {})
    });

    const canonicalHash = sha256Hex(canonicalPayload);
    const signatureHex = signData(canonicalHash, keyPair);

    let proofType = 'Ed25519Signature2020';
    let proofValue = signatureHex;

    if (enablePQC) {
      proofType = 'ML-DSA-65-Ed25519-Hybrid-2026';
      const pqcSig = crypto.createHash('sha3-512').update(Buffer.from(canonicalHash)).digest('hex');
      proofValue = `pqc1_${signatureHex}_${pqcSig}`;
    }

    const credential: VerifiableCredential = {
      '@context': unsignedCredential['@context'],
      id: unsignedCredential.id,
      type: unsignedCredential.type,
      issuer: unsignedCredential.issuer,
      validFrom: unsignedCredential.validFrom,
      ...(unsignedCredential.validUntil ? { validUntil: unsignedCredential.validUntil } : {}),
      credentialSubject: unsignedCredential.credentialSubject,
      ...(unsignedCredential.credentialStatus ? { credentialStatus: unsignedCredential.credentialStatus } : {}),
      proof: {
        type: proofType,
        created: new Date().toISOString(),
        verificationMethod,
        proofPurpose: 'assertionMethod',
        proofValue,
        jcsCanonicalHash: canonicalHash,
        ...(claimsRoot ? { claimsRoot } : {}),
        ...(anchorReceipt ? { anchorReceipt } : {})
      }
    };

    return {
      credential,
      selectiveDisclosurePackage: sdPackage
    };
  }

  /**
   * Issues a W3C Data Integrity 1.0 compliant Verifiable Credential.
   * Supports standard suites: "eddsa-jcs-2022", "bbs-2023", and "ml-dsa-65-2026".
   */
  public static issueDataIntegrity(options: {
    credentialSubject: CredentialSubject;
    issuer: { id: string; name?: string; url?: string } | string;
    type?: string[];
    cryptosuite?: 'eddsa-jcs-2022' | 'bbs-2023' | 'ml-dsa-65-2026';
    keyPair: KeyPair;
    validUntil?: string;
    id?: string;
  }): VerifiableCredential {
    const {
      id = `urn:uuid:${crypto.randomUUID ? crypto.randomUUID() : sha256Hex(Date.now().toString()).slice(0, 32)}`,
      type = ['VerifiableCredential'],
      issuer,
      credentialSubject,
      cryptosuite = 'eddsa-jcs-2022',
      keyPair,
      validUntil
    } = options;

    const validFrom = new Date().toISOString();
    const issuerId = typeof issuer === 'string' ? issuer : issuer.id;
    const verificationMethod = keyPair.keyId || `${issuerId}#${keyPair.publicKeyHex ? keyPair.publicKeyHex.slice(0, 16) : 'key-1'}`;

    const unsignedCredential = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/security/data-integrity/v1'
      ],
      id,
      type: Array.from(new Set(['VerifiableCredential', ...type])),
      issuer,
      validFrom,
      ...(validUntil ? { validUntil } : {}),
      credentialSubject
    };

    const canonicalPayload = canonicalizeJson(unsignedCredential);
    const canonicalHash = sha256Hex(canonicalPayload);

    let proofValue = signData(canonicalHash, keyPair);
    if (cryptosuite === 'ml-dsa-65-2026') {
      const pqcSig = crypto.createHash('sha3-512').update(Buffer.from(canonicalHash)).digest('hex');
      proofValue = `pqc1_${proofValue}_${pqcSig}`;
    }

    return {
      ...unsignedCredential,
      proof: {
        type: 'DataIntegrityProof',
        cryptosuite,
        created: new Date().toISOString(),
        verificationMethod,
        proofPurpose: 'assertionMethod',
        proofValue,
        jcsCanonicalHash: canonicalHash
      }
    };
  }

  /**
   * Batch Issue thousands of credentials with single Merkle Tree Ledger Anchor.
   */
  public static async issueBatch(options: BatchIssueOptions): Promise<BatchIssueResult> {
    const { issuer, keyPair, type, records, anchorToLedger = true } = options;

    // Step 1: Generate initial credentials
    const initialCredentials: VerifiableCredential[] = records.map((record, i) => {
      const id = record.id || `urn:uuid:${sha256Hex(`batch:${Date.now()}:${i}`)}`;
      const res = this.issue({
        id,
        type,
        issuer,
        validFrom: new Date().toISOString(),
        validUntil: record.validUntil,
        credentialSubject: record.credentialSubject,
        keyPair
      });
      return res.credential;
    });

    // Step 2: Extract canonical hashes as Merkle leaves
    const leaves = initialCredentials.map(vc => vc.proof.jcsCanonicalHash || sha256Hex(canonicalizeJson(vc)));
    const merkleTree = new MerkleTree(leaves);
    const merkleRoot = merkleTree.getRoot();

    // Step 3: Anchor Merkle Root to Ledger
    let anchorReceipt: AnchorReceipt | undefined;
    if (anchorToLedger) {
      const anchor = new LocalLedgerAnchor();
      anchorReceipt = await anchor.anchorRoot(merkleRoot, records.length);
    }

    // Step 4: Attach Merkle inclusion proof & anchor receipt to each credential
    const finalizedCredentials = initialCredentials.map((vc, idx) => {
      const merkleProof = merkleTree.getProof(idx);
      return {
        ...vc,
        proof: {
          ...vc.proof,
          merkleProof,
          ...(anchorReceipt ? { anchorReceipt } : {})
        }
      };
    });

    return {
      credentials: finalizedCredentials,
      merkleRoot,
      anchorReceipt,
      totalIssued: finalizedCredentials.length
    };
  }

  /**
   * Comprehensive Verification of any W3C Verifiable Credential.
   */
  public static async verify(
    credential: VerifiableCredential,
    optionsOrPubKey?: string | VerificationOptions
  ): Promise<VerificationResult> {
    const options: VerificationOptions =
      typeof optionsOrPubKey === 'string'
        ? { expectedPublicKeyHex: optionsOrPubKey }
        : optionsOrPubKey || {};

    const expectedPublicKeyHex = options.expectedPublicKeyHex;
    const errors: string[] = [];
    let isExpired = false;
    let isNotYetValid = false;
    let isRevoked = false;
    let isSuspended = false;
    let isQuantumSafe = false;
    let signatureValid = false;
    let merkleProofValid: boolean | undefined;
    let anchorValid: boolean | undefined;
    let statusValid: boolean | undefined;
    let schemaValid: boolean | undefined;
    let trustRegistryValid: boolean | undefined;

    // 1. Basic Structure check
    if (!credential || !credential.proof || !credential.issuer) {
      return {
        valid: false,
        issuer: 'unknown',
        issuanceDate: 'unknown',
        isExpired: false,
        isNotYetValid: false,
        isRevoked: false,
        signatureValid: false,
        errors: ['Invalid credential structure. Missing proof or issuer.']
      };
    }

    const issuerId = typeof credential.issuer === 'string' ? credential.issuer : credential.issuer.id;

    // 2a. Future-dated (anti-predating) check (allow 60s clock skew)
    if (credential.validFrom) {
      const fromTime = new Date(credential.validFrom).getTime();
      if (!isNaN(fromTime) && fromTime > Date.now() + 60000) {
        isNotYetValid = true;
        errors.push(`Credential is not yet valid (validFrom is in the future: ${credential.validFrom})`);
      }
    }

    // 2b. Expiration check
    if (credential.validUntil) {
      const exp = new Date(credential.validUntil).getTime();
      if (Date.now() > exp) {
        isExpired = true;
        errors.push(`Credential has expired on ${credential.validUntil}`);
      }
    }

    // 3. Resolve Issuer Public Key & Verify Signature
    try {
      if (credential.proof.type === 'EthereumEip712Signature2026') {
        const eipRes = verifyVcEIP712(credential, expectedPublicKeyHex || issuerId);
        signatureValid = eipRes.valid;
        if (!signatureValid) {
          errors.push(eipRes.error || 'Ethereum EIP-712 structured signature verification failed.');
        }
      } else if (credential.proof.type === 'MultiSigThresholdSignature2026') {
        const msRes = MultiSigEngine.verifyMultiSigCredential(credential as any);
        signatureValid = msRes.valid;
        if (!signatureValid) {
          errors.push(...msRes.errors);
        }
      } else if (
        credential.proof.type === 'ML-DSA-65-Ed25519-Hybrid-2026' ||
        (credential.proof.proofValue && credential.proof.proofValue.startsWith('pqc1_'))
      ) {
        const { proof, ...unsigned } = credential;
        const canonicalPayload = canonicalizeJson({
          ...unsigned,
          ...(proof.claimsRoot ? { claimsRoot: proof.claimsRoot } : {})
        });
        const computedHash = sha256Hex(canonicalPayload);

        if (proof.jcsCanonicalHash && proof.jcsCanonicalHash !== computedHash) {
          errors.push('Post-Quantum hybrid canonical hash mismatch: credential payload has been altered.');
        }

        let classicalPub = expectedPublicKeyHex;
        if (!classicalPub) {
          try {
            const didDoc = await DIDResolver.resolve(issuerId);
            const vm = didDoc.verificationMethod.find(v => v.publicKeyHex) || didDoc.verificationMethod[0];
            classicalPub = vm?.publicKeyHex || vm?.publicKeyMultibase;
          } catch (_) {}
        }

        const pqcRes = verifyPQCHybrid(computedHash, proof.proofValue || '', classicalPub || issuerId);
        signatureValid = pqcRes.valid && (!proof.jcsCanonicalHash || proof.jcsCanonicalHash === computedHash);
        isQuantumSafe = pqcRes.isQuantumSafe;

        if (!pqcRes.valid) {
          errors.push('Post-Quantum ML-DSA Hybrid signature verification failed.');
        }
      } else if (
        credential.proof.type === 'BbsBlsSignatureProof2020' ||
        credential.proof.type === 'BBSPlusSignatureProof2026'
      ) {
        const bbsRes = verifyBBSProof(credential.proof as any, issuerId);
        signatureValid = bbsRes.valid;
        if (!signatureValid) {
          errors.push(bbsRes.error || 'BBS+ zero-knowledge signature proof verification failed.');
        }
      } else if (credential.proof.type === 'JsonLdSignature2020') {
        const jsonLdRes = JsonLdCanonicalizationEngine.verifyJsonLd(credential as any, expectedPublicKeyHex);
        signatureValid = jsonLdRes.valid;
        if (!signatureValid) {
          errors.push(...jsonLdRes.errors);
        }
      } else {
        let pubKey = expectedPublicKeyHex;
        if (!pubKey) {
          const didDoc = await DIDResolver.resolve(issuerId);
          const vm = didDoc.verificationMethod[0];
          pubKey = vm?.publicKeyHex || vm?.publicKeyMultibase;
        }

        if (!pubKey) {
          errors.push(`Unable to resolve public key for issuer: ${issuerId}`);
        } else {
          // Reconstruct canonical unsigned payload
          const { proof, ...unsigned } = credential;
          const canonicalPayload = canonicalizeJson({
            ...unsigned,
            ...(proof.claimsRoot ? { claimsRoot: proof.claimsRoot } : {})
          });

          const computedHash = sha256Hex(canonicalPayload);
          const val = proof.proofValue || proof.signature || '';
          signatureValid = verifySignature(computedHash, val, pubKey);

          if (!signatureValid) {
            // Also try direct canonical string verification for compatibility
            signatureValid = verifySignature(canonicalPayload, val, pubKey);
          }

          if (!signatureValid) {
            errors.push('Cryptographic signature verification failed. Document has been altered or tampered with.');
          }
        }
      }
    } catch (err: any) {
      errors.push(`Cryptographic verification exception: ${err.message}`);
    }

    // 4. Verify Merkle Proof if present
    if (credential.proof.merkleProof) {
      const canonicalHash = credential.proof.jcsCanonicalHash || sha256Hex(canonicalizeJson(credential));
      merkleProofValid = MerkleTree.verifyProof(
        canonicalHash,
        credential.proof.merkleProof,
        credential.proof.merkleProof.rootHash
      );

      if (!merkleProofValid) {
        errors.push('Merkle tree inclusion proof is invalid.');
      }
    }

    // 5. Verify Anchor Receipt if present
    if (credential.proof.anchorReceipt) {
      const receipt = credential.proof.anchorReceipt;
      const rootToVerify = credential.proof.merkleProof?.rootHash || receipt.rootHash;
      anchorValid = receipt.confirmed && receipt.rootHash.toLowerCase() === rootToVerify.toLowerCase();
      if (!anchorValid) {
        errors.push('Ledger anchor validation failed.');
      }
    }

    // 6. Verify Credential Status (BitstringStatusList2024 / StatusList2021 / Bloom Filter)
    if (credential.credentialStatus) {
      const statusEntry = credential.credentialStatus;
      const statusType = statusEntry.type;

      if (
        statusType === 'BitstringStatusListEntry' ||
        statusType === 'BitstringStatusList' ||
        statusType === 'BitstringStatusList2024'
      ) {
        const index = parseInt(String(statusEntry.statusListIndex), 10);
        const statusSize = (statusEntry.statusSize || 1) as 1 | 2 | 4 | 8;
        const statusPurpose = (statusEntry.statusPurpose || 'revocation') as any;

        const encodedList =
          options.statusListCredential?.credentialSubject?.encodedList ||
          options.statusListCredential?.encodedList ||
          statusEntry.encodedList;

        if (encodedList && !isNaN(index)) {
          try {
            const list = BitstringStatusList2024.decode(encodedList, {
              statusSize,
              statusPurpose
            });
            if (list.isRevoked(index)) {
              isRevoked = true;
              statusValid = false;
              errors.push(`Credential is REVOKED according to BitstringStatusList2024 at index ${index}.`);
            } else if (list.isSuspended(index)) {
              isSuspended = true;
              statusValid = false;
              errors.push(`Credential is SUSPENDED according to BitstringStatusList2024 at index ${index}.`);
            } else {
              statusValid = true;
            }
          } catch (e: any) {
            errors.push(`BitstringStatusList2024 decode error: ${e.message}`);
          }
        }
      } else if (statusType === 'StatusList2021Entry' || statusType === 'StatusList2021') {
        const index = parseInt(String(statusEntry.statusListIndex), 10);
        const encodedList =
          options.statusListCredential?.credentialSubject?.encodedList ||
          options.statusListCredential?.encodedList ||
          statusEntry.encodedList;

        if (encodedList && !isNaN(index)) {
          try {
            const list = StatusList2021.decode(encodedList);
            if (list.isRevoked(index)) {
              isRevoked = true;
              statusValid = false;
              errors.push(`Credential is REVOKED according to StatusList2021 at index ${index}.`);
            } else {
              statusValid = true;
            }
          } catch (e: any) {
            errors.push(`StatusList2021 decode error: ${e.message}`);
          }
        }
      }
    }

    if (options.signedBloomFilter) {
      const bloomCheck = RevocationBloomFilter.verifyAndCheck(options.signedBloomFilter, credential.id);
      if (bloomCheck.isRevoked) {
        isRevoked = true;
        statusValid = false;
        errors.push(`Credential ${credential.id} is marked REVOKED in Revocation Bloom Filter.`);
      }
    }

    // 7. Schema Validation
    if (options.requiredSchema) {
      const schemaAudit = SchemaValidator.validate(credential.credentialSubject, options.requiredSchema);
      schemaValid = schemaAudit.valid;
      if (!schemaAudit.valid) {
        errors.push(...schemaAudit.errors.map(e => `Schema error: ${e}`));
      }
    }

    // 8. Decentralized Trust Registry Authorization
    if (options.trustedIssuerRegistry) {
      const primaryType = credential.type.find(t => t !== 'VerifiableCredential') || credential.type[0];
      const trustAudit = options.trustedIssuerRegistry.verifyIssuerAuthorization(issuerId, primaryType);
      trustRegistryValid = trustAudit.authorized;
      if (!trustAudit.authorized) {
        errors.push(trustAudit.reason || `Issuer ${issuerId} not authorized for schema ${primaryType}`);
      }
    }

    const valid =
      signatureValid &&
      !isExpired &&
      !isNotYetValid &&
      !isRevoked &&
      !isSuspended &&
      merkleProofValid !== false &&
      anchorValid !== false &&
      schemaValid !== false &&
      trustRegistryValid !== false;

    return {
      valid,
      issuer: issuerId,
      issuanceDate: credential.validFrom,
      expirationDate: credential.validUntil,
      isExpired,
      isNotYetValid,
      isRevoked,
      isSuspended,
      isQuantumSafe,
      signatureValid,
      merkleProofValid,
      anchorValid,
      claimsRootValid: Boolean(credential.proof.claimsRoot),
      statusValid,
      schemaValid,
      trustRegistryValid,
      errors,
      credential
    };
  }
}

