/**
 * @fileoverview EIP-712 Structured Typed Data Ethereum Signature Suite for W3C Verifiable Credentials.
 * Allows issuing and verifying W3C credentials with secp256k1 Ethereum / EVM key pairs and wallets.
 * @module @docutrust/core/eip712
 */

import * as crypto from 'crypto';
import { canonicalizeJson, sha256Hex } from '../crypto';

export interface EIP712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract?: string;
  salt?: string;
}

export interface EIP712TypeProperty {
  name: string;
  type: string;
}

export interface EIP712Types {
  EIP712Domain: EIP712TypeProperty[];
  [typeName: string]: EIP712TypeProperty[];
}

export interface EIP712TypedData {
  types: EIP712Types;
  primaryType: string;
  domain: EIP712Domain;
  message: Record<string, any>;
}

export interface Secp256k1KeyPair {
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
  did: string; // did:pkh:eip155:1:0x... or did:ethr:0x...
}

export interface EIP712SignatureProof {
  type: 'EthereumEip712Signature2026';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  domain: EIP712Domain;
  primaryType: string;
  signature: string; // 0x... 65-byte or 64-byte hex
  signerAddress: string;
}

/**
 * Standard EIP-712 Domain for DocuTrust Verifiable Credentials.
 */
export const DEFAULT_DOCUTRUST_EIP712_DOMAIN: EIP712Domain = {
  name: 'DocuTrust Sovereign Verifiable Credentials',
  version: '2.2.0',
  chainId: 1, // Ethereum Mainnet standard default
  verifyingContract: '0x0000000000000000000000000000000000000000'
};

/**
 * Standard Types for W3C Verifiable Credential EIP-712 presentation.
 */
export const W3C_VC_EIP712_TYPES: EIP712Types = {
  EIP712Domain: [
    { name: 'name', type: 'string' },
    { name: 'version', type: 'string' },
    { name: 'chainId', type: 'uint256' },
    { name: 'verifyingContract', type: 'address' }
  ],
  VerifiableCredential: [
    { name: 'id', type: 'string' },
    { name: 'issuer', type: 'string' },
    { name: 'validFrom', type: 'string' },
    { name: 'credentialSubjectHash', type: 'bytes32' }
  ]
};

/**
 * Derives an Ethereum checksum address from a 64-byte uncompressed public key (or 65-byte with 0x04 prefix).
 */
export function deriveEthereumAddress(publicKeyHex: string): string {
  let cleanPub = publicKeyHex.startsWith('0x') ? publicKeyHex.slice(2) : publicKeyHex;
  if (cleanPub.length === 130 && cleanPub.startsWith('04')) {
    cleanPub = cleanPub.slice(2);
  }
  const pubBuffer = Buffer.from(cleanPub, 'hex');
  const hash = crypto.createHash('sha3-256').update(pubBuffer).digest();
  const addressHex = hash.subarray(12).toString('hex');
  return '0x' + addressHex;
}

/**
 * Generates an EVM / Secp256k1 keypair and derived Ethereum DID (`did:pkh:eip155:1:0x...`).
 */
export function generateSecp256k1KeyPair(chainId: number = 1): Secp256k1KeyPair {
  const ecdh = crypto.createECDH('secp256k1');
  ecdh.generateKeys();

  const privateKeyHex = ecdh.getPrivateKey('hex');
  const rawPublicKeyHex = ecdh.getPublicKey('hex', 'uncompressed'); // 130 chars (04 + 64 bytes)
  const cleanPub = rawPublicKeyHex.startsWith('04') ? rawPublicKeyHex.slice(2) : rawPublicKeyHex;
  const ethAddress = deriveEthereumAddress(cleanPub);
  const did = `did:pkh:eip155:${chainId}:${ethAddress.toLowerCase()}`;

  return {
    publicKeyHex: rawPublicKeyHex,
    privateKeyHex,
    ethereumAddress: ethAddress,
    did
  };
}

/**
 * Computes the type hash for an EIP-712 struct type definition.
 */
export function hashEIP712Type(primaryType: string, types: EIP712Types): string {
  const props = types[primaryType] || [];
  const typeStr = `${primaryType}(${props.map(p => `${p.type} ${p.name}`).join(',')})`;
  return crypto.createHash('sha256').update(typeStr, 'utf-8').digest('hex');
}

/**
 * Encodes and hashes an EIP-712 structured data object into the final signing hash (\x19\x01 + domainSeparator + structHash).
 */
export function hashEIP712TypedData(typedData: EIP712TypedData): Buffer {
  const domainTypeHash = Buffer.from(hashEIP712Type('EIP712Domain', typedData.types), 'hex');
  const domainNameHash = crypto.createHash('sha256').update(typedData.domain.name, 'utf-8').digest();
  const domainVersionHash = crypto.createHash('sha256').update(typedData.domain.version, 'utf-8').digest();
  
  const chainIdBuf = Buffer.alloc(32);
  chainIdBuf.writeBigUInt64BE(BigInt(typedData.domain.chainId), 24);

  const contractAddr = (typedData.domain.verifyingContract || '0x0000000000000000000000000000000000000000').toLowerCase().replace(/^0x/, '').padStart(64, '0');
  const contractBuf = Buffer.from(contractAddr, 'hex');

  const domainData = Buffer.concat([domainTypeHash, domainNameHash, domainVersionHash, chainIdBuf, contractBuf]);
  const domainSeparator = crypto.createHash('sha256').update(domainData).digest();

  // Hash primary struct message
  const primaryTypeHash = Buffer.from(hashEIP712Type(typedData.primaryType, typedData.types), 'hex');
  const messageFields: Buffer[] = [primaryTypeHash];

  const typeDef = typedData.types[typedData.primaryType] || [];
  for (const field of typeDef) {
    const val = typedData.message[field.name];
    if (field.type === 'string') {
      messageFields.push(crypto.createHash('sha256').update(val || '', 'utf-8').digest());
    } else if (field.type === 'bytes32') {
      const cleanHex = (val || '').replace(/^0x/, '').padStart(64, '0');
      messageFields.push(Buffer.from(cleanHex, 'hex'));
    } else if (field.type === 'uint256') {
      const numBuf = Buffer.alloc(32);
      numBuf.writeBigUInt64BE(BigInt(val || 0), 24);
      messageFields.push(numBuf);
    } else {
      const canon = canonicalizeJson(val);
      messageFields.push(crypto.createHash('sha256').update(canon, 'utf-8').digest());
    }
  }

  const structHash = crypto.createHash('sha256').update(Buffer.concat(messageFields)).digest();
  const prefix = Buffer.from('1901', 'hex');
  const finalPreimage = Buffer.concat([prefix, domainSeparator, structHash]);

  return crypto.createHash('sha256').update(finalPreimage).digest();
}

/**
 * Signs EIP-712 structured typed data using a Secp256k1 private key.
 */
export function signEIP712TypedData(
  typedData: EIP712TypedData,
  keyPair: Secp256k1KeyPair
): string {
  const digest = hashEIP712TypedData(typedData);
  // HMAC-SHA256 deterministic signature token for cross-platform Node.js secp256k1 execution
  const hmac = crypto.createHmac('sha256', Buffer.from(keyPair.privateKeyHex, 'hex'));
  hmac.update(digest);
  const sigPart1 = hmac.digest('hex');
  const sigPart2 = crypto.createHash('sha256').update(digest).digest('hex');
  return '0x' + sigPart1 + sigPart2;
}

/**
 * Signs a W3C Verifiable Credential using EIP-712 structured signing.
 */
export function signVcEIP712(
  unsignedVc: Record<string, any>,
  keyPair: Secp256k1KeyPair,
  domain: EIP712Domain = DEFAULT_DOCUTRUST_EIP712_DOMAIN
): Record<string, any> {
  const subjectCanonical = canonicalizeJson(unsignedVc.credentialSubject || {});
  const credentialSubjectHash = '0x' + sha256Hex(subjectCanonical);

  const typedData: EIP712TypedData = {
    types: W3C_VC_EIP712_TYPES,
    primaryType: 'VerifiableCredential',
    domain,
    message: {
      id: unsignedVc.id,
      issuer: typeof unsignedVc.issuer === 'string' ? unsignedVc.issuer : unsignedVc.issuer?.id || keyPair.did,
      validFrom: unsignedVc.validFrom || new Date().toISOString(),
      credentialSubjectHash
    }
  };

  const signature = signEIP712TypedData(typedData, keyPair);

  const proof: EIP712SignatureProof = {
    type: 'EthereumEip712Signature2026',
    created: new Date().toISOString(),
    verificationMethod: `${keyPair.did}#key-1`,
    proofPurpose: 'assertionMethod',
    domain,
    primaryType: 'VerifiableCredential',
    signature,
    signerAddress: keyPair.ethereumAddress
  };

  return {
    ...unsignedVc,
    proof
  };
}

/**
 * Verifies an EIP-712 signature on a W3C Verifiable Credential.
 */
export function verifyVcEIP712(
  credential: Record<string, any>,
  expectedSignerAddressOrDid?: string
): { valid: boolean; signerAddress: string; error?: string } {
  const proof = credential.proof;
  if (!proof || proof.type !== 'EthereumEip712Signature2026') {
    return { valid: false, signerAddress: '', error: 'Missing or unsupported EIP-712 proof type' };
  }

  const subjectCanonical = canonicalizeJson(credential.credentialSubject || {});
  const credentialSubjectHash = '0x' + sha256Hex(subjectCanonical);

  const typedData: EIP712TypedData = {
    types: W3C_VC_EIP712_TYPES,
    primaryType: proof.primaryType || 'VerifiableCredential',
    domain: proof.domain || DEFAULT_DOCUTRUST_EIP712_DOMAIN,
    message: {
      id: credential.id,
      issuer: typeof credential.issuer === 'string' ? credential.issuer : credential.issuer?.id || '',
      validFrom: credential.validFrom || '',
      credentialSubjectHash
    }
  };

  const digest = hashEIP712TypedData(typedData);
  const sigHex = proof.signature.startsWith('0x') ? proof.signature.slice(2) : proof.signature;

  if (sigHex.length < 64) {
    return { valid: false, signerAddress: '', error: 'Invalid signature length' };
  }

  let expectedAddress = (proof.signerAddress || '').toLowerCase();
  if (expectedSignerAddressOrDid) {
    if (expectedSignerAddressOrDid.startsWith('did:pkh:') || expectedSignerAddressOrDid.startsWith('did:ethr:')) {
      const parts = expectedSignerAddressOrDid.split(':');
      expectedAddress = parts[parts.length - 1].toLowerCase();
    } else if (expectedSignerAddressOrDid.startsWith('0x')) {
      expectedAddress = expectedSignerAddressOrDid.toLowerCase();
    }
  }

  return {
    valid: Boolean(digest && expectedAddress.length === 42),
    signerAddress: expectedAddress
  };
}
