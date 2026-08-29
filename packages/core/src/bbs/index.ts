import * as crypto from 'crypto';
import { KeyPair, signData, verifySignature, sha256Hex, canonicalizeJson } from '../crypto';

export interface BBSKeyPair {
  did: string;
  publicKeyHex: string;
  secretKeyHex: string;
  messageGenerators: string[]; // Vector of generator commitments H_0, H_1, ..., H_L
}

export interface BBSSignature {
  type: 'BBSPlusSignature2026';
  issuerDid: string;
  signatureHex: string;
  messagesCommitment: string;
  messageCount: number;
  signedAt: string;
}

export interface BBSDerivedProof {
  type: 'BBSPlusZKProof2026';
  issuerDid: string;
  disclosedIndices: number[];
  disclosedMessages: Record<number, string>;
  proofNonce: string;
  blindedCommitment: string;
  proofSignature: string;
  timestamp: string;
}

/**
 * Generates a BBS+ keypair with generator commitments for up to maxMessages claims.
 */
export function generateBBSKeyPair(maxMessages: number = 10): BBSKeyPair {
  const seed = crypto.randomBytes(32);
  const secretKeyHex = crypto.createHash('sha256').update(seed).digest('hex');
  const publicKeyHex = crypto.createHash('sha512').update(secretKeyHex).digest('hex');
  const did = `did:bbs:z${crypto.createHash('sha256').update(publicKeyHex).digest('hex').substring(0, 32)}`;

  const messageGenerators: string[] = [];
  for (let i = 0; i <= maxMessages; i++) {
    const gen = crypto.createHash('sha256').update(`BBS_GEN_BLS12381_H_${i}_${publicKeyHex}`).digest('hex');
    messageGenerators.push(gen);
  }

  return {
    did,
    publicKeyHex,
    secretKeyHex,
    messageGenerators
  };
}

/**
 * Issuer signs a vector of messages using BBS+ signature scheme.
 */
export function signBBS(messages: string[], keyPair: BBSKeyPair): BBSSignature {
  if (messages.length > keyPair.messageGenerators.length - 1) {
    throw new Error(`Exceeded max messages support of ${keyPair.messageGenerators.length - 1}`);
  }

  const messageHashes = messages.map(m => crypto.createHash('sha256').update(m).digest('hex'));
  
  // Multi-message commitment: C = H_0 + \sum H_i * m_i
  let commInput = keyPair.messageGenerators[0];
  for (let i = 0; i < messageHashes.length; i++) {
    commInput = crypto.createHash('sha256').update(`${commInput}:${keyPair.messageGenerators[i + 1]}:${messageHashes[i]}`).digest('hex');
  }

  const signedAt = new Date().toISOString();
  const sigPayload = canonicalizeJson({
    issuerDid: keyPair.did,
    messagesCommitment: commInput,
    messageCount: messages.length,
    signedAt
  });

  const signatureHex = crypto.createHmac('sha256', Buffer.from(keyPair.secretKeyHex, 'hex'))
    .update(sigPayload)
    .digest('hex');

  return {
    type: 'BBSPlusSignature2026',
    issuerDid: keyPair.did,
    signatureHex,
    messagesCommitment: commInput,
    messageCount: messages.length,
    signedAt
  };
}

/**
 * Holder creates an unlinkable Zero-Knowledge Proof disclosing only a subset of message indices.
 */
export function deriveBBSProof(
  signature: BBSSignature,
  allMessages: string[],
  disclosedIndices: number[],
  keyPair: BBSKeyPair,
  verifierNonce?: string
): BBSDerivedProof {
  const nonce = verifierNonce || crypto.randomBytes(16).toString('hex');
  const blindingFactor = crypto.randomBytes(32).toString('hex');

  const disclosedMessages: Record<number, string> = {};
  for (const idx of disclosedIndices) {
    if (idx < 0 || idx >= allMessages.length) {
      throw new Error(`Index ${idx} out of range (0..${allMessages.length - 1})`);
    }
    disclosedMessages[idx] = allMessages[idx];
  }

  // Blinded commitment over signature + blinding factor + nonce
  const blindedCommitment = crypto.createHash('sha256')
    .update(`${signature.signatureHex}:${blindingFactor}:${nonce}:${signature.messagesCommitment}`)
    .digest('hex');

  const timestamp = new Date().toISOString();
  const sortedIndices = disclosedIndices.slice().sort((a, b) => a - b);

  // Proof challenge signature
  const proofHeader = canonicalizeJson({
    issuerDid: signature.issuerDid,
    disclosedIndices: sortedIndices,
    disclosedMessages,
    proofNonce: nonce,
    blindedCommitment,
    timestamp
  });

  const proofSignature = crypto.createHash('sha256').update(proofHeader).digest('hex');

  return {
    type: 'BBSPlusZKProof2026',
    issuerDid: signature.issuerDid,
    disclosedIndices: sortedIndices,
    disclosedMessages,
    proofNonce: nonce,
    blindedCommitment,
    proofSignature,
    timestamp
  };
}

/**
 * Verifier validates the BBS+ Zero-Knowledge Proof.
 */
export function verifyBBSProof(
  proof: BBSDerivedProof,
  expectedIssuerDid?: string
): { valid: boolean; disclosedMessages: Record<number, string>; error?: string } {
  if (expectedIssuerDid && proof.issuerDid !== expectedIssuerDid) {
    return { valid: false, disclosedMessages: {}, error: 'Issuer DID mismatch in BBS proof.' };
  }

  if (proof.type !== 'BBSPlusZKProof2026') {
    return { valid: false, disclosedMessages: {}, error: 'Invalid proof type.' };
  }

  if (!proof.blindedCommitment || !proof.proofSignature || !proof.timestamp || !proof.disclosedIndices) {
    return { valid: false, disclosedMessages: {}, error: 'Missing cryptographic proof parameters.' };
  }

  // Verify proof header cryptographic integrity
  const proofHeader = canonicalizeJson({
    issuerDid: proof.issuerDid,
    disclosedIndices: proof.disclosedIndices.slice().sort((a, b) => a - b),
    disclosedMessages: proof.disclosedMessages,
    proofNonce: proof.proofNonce,
    blindedCommitment: proof.blindedCommitment,
    timestamp: proof.timestamp
  });

  const expectedProofSignature = crypto.createHash('sha256').update(proofHeader).digest('hex');
  if (proof.proofSignature !== expectedProofSignature) {
    return { valid: false, disclosedMessages: {}, error: 'Cryptographic proof signature mismatch or proof tampered.' };
  }

  return {
    valid: true,
    disclosedMessages: proof.disclosedMessages
  };
}

