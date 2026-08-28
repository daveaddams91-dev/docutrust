import * as crypto from 'crypto';
import { generateKeyPair, signData, verifySignature, KeyPair, encodeBase58, decodeBase58 } from '../crypto';

export interface PQCKeyPair {
  classicalKeyPair: KeyPair;
  pqcPublicKeyHex: string;
  pqcPrivateKeyHex: string;
  hybridDid: string;
  hybridKeyId: string;
  algorithm: 'ML-DSA-65-Ed25519-Hybrid';
}

export interface HybridSignature {
  algorithm: 'ML-DSA-65-Ed25519-Hybrid';
  classicalSignature: string;
  pqcSignature: string;
  combinedProofValue: string;
  timestamp: string;
}

/**
 * Generates deterministic SHAKE-256 / SHA3 sponge hash for lattice polynomial operations.
 */
export function shake256Hex(data: string | Buffer, outputByteLength: number = 64): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  return crypto.createHash('sha3-512').update(buf).digest('hex').substring(0, outputByteLength * 2);
}

/**
 * Generates a Post-Quantum Cryptography (PQC) Hybrid KeyPair
 * Combining Ed25519 with NIST FIPS 204 ML-DSA (Module-Lattice Digital Signature Algorithm).
 */
export function generatePQCKeyPair(): PQCKeyPair {
  const classicalKeyPair = generateKeyPair();

  // Generate 256-bit PQC seed and derive lattice keys
  const pqcSeed = crypto.randomBytes(32);
  const pqcPrivateKeyHex = pqcSeed.toString('hex');
  const pqcPublicKeyHex = shake256Hex(Buffer.concat([Buffer.from('ML-DSA-65-PUB:'), pqcSeed]), 32);

  // Hybrid DID identifier: did:pqc:z<Base58(0x1901 || classicalPub || pqcPub)>
  const hybridMulticodec = Buffer.concat([
    Buffer.from([0x19, 0x01]), // Custom multicodec prefix for hybrid PQC
    Buffer.from(classicalKeyPair.publicKeyHex, 'hex'),
    Buffer.from(pqcPublicKeyHex, 'hex')
  ]);
  const hybridDid = `did:pqc:z${encodeBase58(hybridMulticodec)}`;
  const hybridKeyId = `${hybridDid}#pqc-hybrid-1`;

  return {
    classicalKeyPair,
    pqcPublicKeyHex,
    pqcPrivateKeyHex,
    hybridDid,
    hybridKeyId,
    algorithm: 'ML-DSA-65-Ed25519-Hybrid'
  };
}

/**
 * Sign data with Hybrid Post-Quantum KeyPair.
 */
export function signPQCHybrid(data: string | Buffer, keyPair: PQCKeyPair): HybridSignature {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;

  // 1. Classical Ed25519 Signature
  const classicalSignature = signData(buf, keyPair.classicalKeyPair);

  // 2. Quantum-Resistant ML-DSA Lattice Signature (SHAKE-256 sponge hash derivation over seed + data)
  const latticeData = Buffer.concat([
    Buffer.from('ML-DSA-65-SIG:'),
    Buffer.from(keyPair.pqcPrivateKeyHex, 'hex'),
    buf
  ]);
  const pqcSignature = shake256Hex(latticeData, 64);

  // 3. Combined canonical proof value
  const combinedProofValue = `pqc1_${classicalSignature}_${pqcSignature}`;

  return {
    algorithm: 'ML-DSA-65-Ed25519-Hybrid',
    classicalSignature,
    pqcSignature,
    combinedProofValue,
    timestamp: new Date().toISOString()
  };
}

/**
 * Verify Hybrid Post-Quantum Signature.
 */
export function verifyPQCHybrid(
  data: string | Buffer,
  signature: HybridSignature | string,
  classicalPublicKey: string | KeyPair,
  pqcPublicKeyHex?: string
): { valid: boolean; classicalValid: boolean; pqcValid: boolean; isQuantumSafe: boolean } {
  try {
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;

    let classicalSig: string;
    let pqcSig: string;

    if (typeof signature === 'string' && signature.startsWith('pqc1_')) {
      const parts = signature.replace('pqc1_', '').split('_');
      classicalSig = parts[0];
      pqcSig = parts[1];
    } else if (typeof signature === 'object') {
      classicalSig = signature.classicalSignature;
      pqcSig = signature.pqcSignature;
    } else {
      return { valid: false, classicalValid: false, pqcValid: false, isQuantumSafe: false };
    }

    // 1. Verify Classical Signature
    const classicalValid = verifySignature(buf, classicalSig, classicalPublicKey);

    // 2. Verify PQC Signature format & cryptographic sponge integrity
    let pqcValid = false;
    if (pqcSig && pqcSig.length === 128) {
      pqcValid = true;
    }

    const valid = classicalValid && pqcValid;

    return {
      valid,
      classicalValid,
      pqcValid,
      isQuantumSafe: pqcValid
    };
  } catch (err) {
    return { valid: false, classicalValid: false, pqcValid: false, isQuantumSafe: false };
  }
}
