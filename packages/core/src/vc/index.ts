import * as crypto from 'crypto';
import {
  KeyPair,
  canonicalizeJson,
  signData,
  verifySignature,
  sha256Hex
} from '../crypto';
import { MerkleTree, MerkleInclusionProof } from '../merkle';
import { DIDResolver } from '../did';
import {
  createSelectiveDisclosurePackage,
  SelectiveDisclosurePackage
} from '../selective-disclosure';
import { AnchorReceipt, LocalLedgerAnchor } from '../ledger';
import { verifyVcEIP712 } from '../eip712';

export interface CredentialSubject {
  id?: string;
  [claimKey: string]: any;
}

export interface CredentialStatus {
  id: string;
  type: string;
  statusPurpose: 'revocation' | 'suspension';
  statusListIndex: number;
  statusListCredential?: string;
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

export interface VerificationResult {
  valid: boolean;
  issuer: string;
  issuanceDate: string;
  expirationDate?: string;
  isExpired: boolean;
  isNotYetValid?: boolean;
  isRevoked: boolean;
  signatureValid: boolean;
  merkleProofValid?: boolean;
  anchorValid?: boolean;
  claimsRootValid?: boolean;
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
      anchorReceipt
    } = options;

    let sdPackage: SelectiveDisclosurePackage | undefined;
    let claimsRoot: string | undefined;

    if (enableSelectiveDisclosure) {
      sdPackage = createSelectiveDisclosurePackage(credentialSubject);
      claimsRoot = sdPackage.claimsRoot;
    }

    const issuerId = typeof issuer === 'string' ? issuer : issuer.id;
    const verificationMethod = keyPair.keyId || `${issuerId}#${keyPair.publicKeyHex.slice(0, 16)}`;

    const unsignedCredential: Omit<VerifiableCredential, 'proof'> = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ],
      id,
      type: Array.from(new Set(['VerifiableCredential', ...type])),
      issuer,
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
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod,
        proofPurpose: 'assertionMethod',
        proofValue: signatureHex,
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
    expectedPublicKeyHex?: string
  ): Promise<VerificationResult> {
    const errors: string[] = [];
    let isExpired = false;
    let isNotYetValid = false;
    let isRevoked = false;
    let signatureValid = false;
    let merkleProofValid: boolean | undefined;
    let anchorValid: boolean | undefined;

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
        const multiProof = credential.proof as any;
        const signatures = multiProof.signatures || [];
        const required = multiProof.threshold?.required || 1;
        const { proof, ...unsigned } = credential;
        const canonicalPayload = canonicalizeJson({
          ...unsigned,
          ...(proof.claimsRoot ? { claimsRoot: proof.claimsRoot } : {})
        });
        const computedHash = multiProof.jcsCanonicalHash || sha256Hex(canonicalPayload);

        let validSigCount = 0;
        for (const sigEntry of signatures) {
          try {
            const didDoc = await DIDResolver.resolve(sigEntry.signerDid);
            const vm = didDoc.verificationMethod[0];
            const sigPubKey = vm?.publicKeyHex || vm?.publicKeyMultibase;
            if (sigPubKey && verifySignature(computedHash, sigEntry.signature, sigPubKey)) {
              validSigCount++;
            }
          } catch (_) {}
        }
        signatureValid = validSigCount >= required;
        if (!signatureValid) {
          errors.push(`MultiSig threshold not met: verified ${validSigCount} of ${required} required signatures.`);
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

    const valid = signatureValid && !isExpired && !isNotYetValid && !isRevoked && (merkleProofValid !== false) && (anchorValid !== false);

    return {
      valid,
      issuer: issuerId,
      issuanceDate: credential.validFrom,
      expirationDate: credential.validUntil,
      isExpired,
      isNotYetValid,
      isRevoked,
      signatureValid,
      merkleProofValid,
      anchorValid,
      claimsRootValid: Boolean(credential.proof.claimsRoot),
      errors,
      credential
    };
  }
}
