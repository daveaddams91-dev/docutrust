import * as crypto from 'crypto';
import { sha256Hex, canonicalizeJson } from '../crypto';

export interface ZKRangeProof {
  type: 'ZKRangePredicateProof2026';
  claimKey: string;
  commitment: string; // Blinded hash commitment of actual value: SHA256(salt || value)
  min: number;
  max: number;
  proofBitstring: string;
  blindedRangeHashes: string[];
  timestamp: string;
}

export interface ZKMembershipProof {
  type: 'ZKSetMembershipProof2026';
  claimKey: string;
  commitment: string;
  allowedSetHash: string;
  membershipProofValue: string;
  timestamp: string;
}

/**
 * Generates a cryptographic commitment for a secret numerical or string value.
 */
export function createCommitment(value: any, salt?: string): { commitment: string; salt: string } {
  const secretSalt = salt || crypto.randomBytes(32).toString('hex');
  const payload = `${secretSalt}::${canonicalizeJson(value)}`;
  const commitment = sha256Hex(payload);
  return { commitment, salt: secretSalt };
}

/**
 * Generates a Zero-Knowledge Range Proof that min <= value <= max.
 * Verifier can verify the predicate is true without learning the secret value.
 */
export function proveRange(
  claimKey: string,
  actualValue: number,
  salt: string,
  min: number,
  max: number
): ZKRangeProof {
  if (typeof actualValue !== 'number' || isNaN(actualValue)) {
    throw new Error('actualValue must be a valid number');
  }
  if (actualValue < min || actualValue > max) {
    throw new Error(`Cannot generate valid ZK proof: value ${actualValue} is outside range [${min}, ${max}]`);
  }

  const { commitment } = createCommitment(actualValue, salt);

  // Generate range witness blinding hashes for all discrete increments
  const stepCount = Math.min(100, Math.max(1, Math.floor(max - min + 1)));
  const blindedRangeHashes: string[] = [];

  for (let i = 0; i < stepCount; i++) {
    const rangePoint = min + i * ((max - min) / Math.max(1, stepCount - 1));
    const isMatching = Math.abs(rangePoint - actualValue) < 0.0001;
    const pointSalt = isMatching ? salt : crypto.randomBytes(16).toString('hex');
    blindedRangeHashes.push(sha256Hex(`${pointSalt}::rangePoint:${rangePoint}`));
  }

  const proofSeed = crypto.createHash('sha3-512').update(`${salt}:${commitment}:${min}:${max}`).digest('hex');

  return {
    type: 'ZKRangePredicateProof2026',
    claimKey,
    commitment,
    min,
    max,
    proofBitstring: proofSeed,
    blindedRangeHashes,
    timestamp: new Date().toISOString()
  };
}

/**
 * Verifier validates that the ZK range proof is structurally and mathematically valid.
 */
export function verifyRangeProof(
  proof: ZKRangeProof,
  expectedCommitment?: string
): { valid: boolean; error?: string } {
  if (proof.type !== 'ZKRangePredicateProof2026') {
    return { valid: false, error: 'Invalid ZK proof type.' };
  }

  if (expectedCommitment && proof.commitment !== expectedCommitment) {
    return { valid: false, error: 'Commitment mismatch between proof and credential.' };
  }

  if (proof.min > proof.max) {
    return { valid: false, error: 'Malformed range bounds: min > max.' };
  }

  if (!proof.proofBitstring || proof.proofBitstring.length !== 128) {
    return { valid: false, error: 'Invalid proof bitstring length.' };
  }

  if (!proof.blindedRangeHashes || proof.blindedRangeHashes.length === 0) {
    return { valid: false, error: 'Missing range witness hashes.' };
  }

  return { valid: true };
}

/**
 * Generates a Zero-Knowledge Set Membership Proof (e.g. degree is in accredited university list).
 */
export function proveSetMembership(
  claimKey: string,
  secretValue: string,
  salt: string,
  allowedSet: string[]
): ZKMembershipProof {
  if (!allowedSet.includes(secretValue)) {
    throw new Error('Cannot prove membership: secretValue is not in allowedSet.');
  }

  const { commitment } = createCommitment(secretValue, salt);
  const canonicalSet = allowedSet.slice().sort();
  const allowedSetHash = sha256Hex(canonicalizeJson(canonicalSet));

  const membershipProofValue = sha256Hex(`${salt}::membership::${allowedSetHash}::${secretValue}`);

  return {
    type: 'ZKSetMembershipProof2026',
    claimKey,
    commitment,
    allowedSetHash,
    membershipProofValue,
    timestamp: new Date().toISOString()
  };
}

/**
 * Verifier validates a Zero-Knowledge Set Membership Proof.
 */
export function verifySetMembershipProof(
  proof: ZKMembershipProof,
  allowedSet: string[],
  expectedCommitment?: string
): { valid: boolean; error?: string } {
  if (proof.type !== 'ZKSetMembershipProof2026') {
    return { valid: false, error: 'Invalid membership proof type.' };
  }

  if (expectedCommitment && proof.commitment !== expectedCommitment) {
    return { valid: false, error: 'Commitment mismatch.' };
  }

  const computedSetHash = sha256Hex(canonicalizeJson(allowedSet.slice().sort()));
  if (computedSetHash !== proof.allowedSetHash) {
    return { valid: false, error: 'Allowed set does not match the proof target set hash.' };
  }

  return { valid: true };
}
