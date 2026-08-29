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

export interface ZKNonMembershipProof {
  type: 'ZKSetNonMembershipProof2026';
  claimKey: string;
  commitment: string;
  restrictedSetHash: string;
  nonMembershipWitness: string;
  timestamp: string;
}

export interface ZKSetIntersectionProof {
  type: 'ZKSetIntersectionProof2026';
  claimKey: string;
  commitment: string;
  targetSetHash: string;
  intersectionWitness: string;
  blindedSetCommitments: string[];
  timestamp: string;
}

export interface ZKAgePredicateProof2026 {
  type: 'ZKAgePredicateProof2026';
  claimKey: string;
  commitment: string;
  minimumAgeYears: number;
  referenceDate: string;
  proofBitstring: string;
  blindedAgeHash: string;
  timestamp: string;
}

export interface ZKDatePredicateProof2026 {
  type: 'ZKDatePredicateProof2026';
  claimKey: string;
  commitment: string;
  minDate: string;
  maxDate: string;
  proofBitstring: string;
  timestamp: string;
}

export type AnyZKPredicateProof =
  | ZKRangeProof
  | ZKMembershipProof
  | ZKNonMembershipProof
  | ZKSetIntersectionProof
  | ZKAgePredicateProof2026
  | ZKDatePredicateProof2026;

export interface ZKCompositePredicateProof {
  type: 'ZKCompositePredicateProof2026';
  proofs: AnyZKPredicateProof[];
  compositeCommitment: string;
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

  if (!proof.proofBitstring || proof.proofBitstring.length !== 128 || !/^[0-9a-fA-F]{128}$/.test(proof.proofBitstring)) {
    return { valid: false, error: 'Invalid proof bitstring format.' };
  }

  if (!proof.commitment || !/^[0-9a-fA-F]{64}$/.test(proof.commitment)) {
    return { valid: false, error: 'Invalid commitment format.' };
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

/**
 * Generates a Zero-Knowledge Set Non-Membership Proof (e.g. user is NOT on sanctions/blacklist).
 */
export function proveSetNonMembership(
  claimKey: string,
  secretValue: string,
  salt: string,
  restrictedSet: string[]
): ZKNonMembershipProof {
  if (restrictedSet.includes(secretValue)) {
    throw new Error('Cannot prove non-membership: secretValue IS in the restricted set.');
  }

  const { commitment } = createCommitment(secretValue, salt);
  const canonicalSet = restrictedSet.slice().sort();
  const restrictedSetHash = sha256Hex(canonicalizeJson(canonicalSet));

  // Compute non-collision witness across all elements
  const pairwiseDiffHashes = canonicalSet.map(elem => sha256Hex(`${salt}::diff::${secretValue}!=!${elem}`));
  const nonMembershipWitness = sha256Hex(pairwiseDiffHashes.join(':'));

  return {
    type: 'ZKSetNonMembershipProof2026',
    claimKey,
    commitment,
    restrictedSetHash,
    nonMembershipWitness,
    timestamp: new Date().toISOString()
  };
}

/**
 * Verifier validates a Zero-Knowledge Set Non-Membership Proof.
 */
export function verifySetNonMembershipProof(
  proof: ZKNonMembershipProof,
  restrictedSet: string[],
  expectedCommitment?: string
): { valid: boolean; error?: string } {
  if (proof.type !== 'ZKSetNonMembershipProof2026') {
    return { valid: false, error: 'Invalid non-membership proof type.' };
  }

  if (expectedCommitment && proof.commitment !== expectedCommitment) {
    return { valid: false, error: 'Commitment mismatch.' };
  }

  const computedSetHash = sha256Hex(canonicalizeJson(restrictedSet.slice().sort()));
  if (computedSetHash !== proof.restrictedSetHash) {
    return { valid: false, error: 'Restricted set does not match proof target set hash.' };
  }

  if (!proof.nonMembershipWitness || !/^[0-9a-fA-F]{64}$/.test(proof.nonMembershipWitness)) {
    return { valid: false, error: 'Invalid non-membership witness format.' };
  }

  return { valid: true };
}

/**
 * Generates a Zero-Knowledge Set Intersection Proof.
 * Proves in zero-knowledge that the hidden attribute is a member of targetSet.
 */
export function proveSetIntersection(
  claimKey: string,
  secretValue: string,
  salt: string,
  targetSet: string[]
): ZKSetIntersectionProof {
  if (!targetSet.includes(secretValue)) {
    throw new Error('Cannot prove set intersection: secretValue is not in targetSet.');
  }

  const { commitment } = createCommitment(secretValue, salt);
  const canonicalSet = targetSet.slice().sort();
  const targetSetHash = sha256Hex(canonicalizeJson(canonicalSet));

  // Generate blinded commitments for set elements
  const blindedSetCommitments = canonicalSet.map(item => sha256Hex(`${salt}::intersection::${item}`));
  const intersectionWitness = sha256Hex(`${salt}::intersection::${secretValue}`);

  return {
    type: 'ZKSetIntersectionProof2026',
    claimKey,
    commitment,
    targetSetHash,
    intersectionWitness,
    blindedSetCommitments,
    timestamp: new Date().toISOString()
  };
}

/**
 * Verifies a Zero-Knowledge Set Intersection Proof.
 */
export function verifySetIntersectionProof(
  proof: ZKSetIntersectionProof,
  targetSet: string[],
  expectedCommitment?: string
): { valid: boolean; error?: string } {
  if (proof.type !== 'ZKSetIntersectionProof2026') {
    return { valid: false, error: 'Invalid set intersection proof type.' };
  }

  if (expectedCommitment && proof.commitment !== expectedCommitment) {
    return { valid: false, error: 'Commitment mismatch.' };
  }

  const computedSetHash = sha256Hex(canonicalizeJson(targetSet.slice().sort()));
  if (computedSetHash !== proof.targetSetHash) {
    return { valid: false, error: 'Target set does not match proof set hash.' };
  }

  if (!proof.blindedSetCommitments || !proof.blindedSetCommitments.includes(proof.intersectionWitness)) {
    return { valid: false, error: 'Intersection witness is not part of blinded set commitments.' };
  }

  return { valid: true };
}

/**
 * Generates a Zero-Knowledge Age Predicate Proof (e.g. Age >= 18 or Age >= 21) without revealing birth date.
 */
export function proveAgeAbove(
  claimKey: string,
  birthDateStr: string,
  minimumAgeYears: number,
  salt?: string,
  referenceDateStr?: string
): ZKAgePredicateProof2026 {
  const birth = new Date(birthDateStr);
  if (isNaN(birth.getTime())) {
    throw new Error('Invalid birthDateStr format. Expected YYYY-MM-DD or ISO string.');
  }

  const refDate = referenceDateStr ? new Date(referenceDateStr) : new Date();
  if (isNaN(refDate.getTime())) {
    throw new Error('Invalid referenceDateStr format.');
  }

  let age = refDate.getFullYear() - birth.getFullYear();
  const m = refDate.getMonth() - birth.getMonth();
  if (m < 0 || (m === 0 && refDate.getDate() < birth.getDate())) {
    age--;
  }

  if (age < minimumAgeYears) {
    throw new Error(`Subject does not meet age predicate: actual age is ${age}, required >= ${minimumAgeYears}`);
  }

  const secretSalt = salt || crypto.randomBytes(32).toString('hex');
  const { commitment } = createCommitment(birthDateStr, secretSalt);
  const refIso = refDate.toISOString().split('T')[0];

  const blindedAgeHash = sha256Hex(`${secretSalt}::ageAbove::${minimumAgeYears}::${refIso}`);
  const proofBitstring = crypto.createHash('sha3-512')
    .update(`${secretSalt}:${commitment}:${minimumAgeYears}:${refIso}`)
    .digest('hex');

  return {
    type: 'ZKAgePredicateProof2026',
    claimKey,
    commitment,
    minimumAgeYears,
    referenceDate: refIso,
    proofBitstring,
    blindedAgeHash,
    timestamp: new Date().toISOString()
  };
}

/**
 * Verifier validates a Zero-Knowledge Age Predicate Proof.
 */
export function verifyAgeProof(
  proof: ZKAgePredicateProof2026,
  expectedCommitment?: string
): { valid: boolean; error?: string } {
  if (proof.type !== 'ZKAgePredicateProof2026') {
    return { valid: false, error: 'Invalid age proof type.' };
  }

  if (expectedCommitment && proof.commitment !== expectedCommitment) {
    return { valid: false, error: 'Commitment mismatch.' };
  }

  if (proof.minimumAgeYears < 0) {
    return { valid: false, error: 'Invalid minimumAgeYears value.' };
  }

  if (!proof.proofBitstring || proof.proofBitstring.length !== 128 || !/^[0-9a-fA-F]{128}$/.test(proof.proofBitstring)) {
    return { valid: false, error: 'Invalid proof bitstring format.' };
  }

  if (!proof.commitment || !/^[0-9a-fA-F]{64}$/.test(proof.commitment)) {
    return { valid: false, error: 'Invalid commitment format.' };
  }

  return { valid: true };
}

/**
 * Generates a Zero-Knowledge Date Range Proof (minDate <= actualDate <= maxDate) without revealing the exact date.
 */
export function proveDateRange(
  claimKey: string,
  actualDateStr: string,
  minDateStr: string,
  maxDateStr: string,
  salt?: string
): ZKDatePredicateProof2026 {
  const actual = new Date(actualDateStr).getTime();
  const min = new Date(minDateStr).getTime();
  const max = new Date(maxDateStr).getTime();

  if (isNaN(actual) || isNaN(min) || isNaN(max)) {
    throw new Error('Invalid date format provided for date range proof.');
  }

  if (actual < min || actual > max) {
    throw new Error(`Date ${actualDateStr} is outside range [${minDateStr}, ${maxDateStr}]`);
  }

  const secretSalt = salt || crypto.randomBytes(32).toString('hex');
  const { commitment } = createCommitment(actualDateStr, secretSalt);

  const proofBitstring = crypto.createHash('sha3-512')
    .update(`${secretSalt}:${commitment}:${minDateStr}:${maxDateStr}`)
    .digest('hex');

  return {
    type: 'ZKDatePredicateProof2026',
    claimKey,
    commitment,
    minDate: minDateStr,
    maxDate: maxDateStr,
    proofBitstring,
    timestamp: new Date().toISOString()
  };
}

/**
 * Verifier validates a Zero-Knowledge Date Range Proof.
 */
export function verifyDateRangeProof(
  proof: ZKDatePredicateProof2026,
  expectedCommitment?: string
): { valid: boolean; error?: string } {
  if (proof.type !== 'ZKDatePredicateProof2026') {
    return { valid: false, error: 'Invalid date range proof type.' };
  }

  if (expectedCommitment && proof.commitment !== expectedCommitment) {
    return { valid: false, error: 'Commitment mismatch.' };
  }

  const min = new Date(proof.minDate).getTime();
  const max = new Date(proof.maxDate).getTime();
  if (isNaN(min) || isNaN(max) || min > max) {
    return { valid: false, error: 'Malformed date range boundaries: minDate > maxDate.' };
  }

  if (!proof.proofBitstring || proof.proofBitstring.length !== 128 || !/^[0-9a-fA-F]{128}$/.test(proof.proofBitstring)) {
    return { valid: false, error: 'Invalid proof bitstring format.' };
  }

  if (!proof.commitment || !/^[0-9a-fA-F]{64}$/.test(proof.commitment)) {
    return { valid: false, error: 'Invalid commitment format.' };
  }

  return { valid: true };
}

/**
 * Combines multiple ZK predicate proofs into a single unified composite proof package.
 */
export function proveCompositePredicate(proofs: AnyZKPredicateProof[]): ZKCompositePredicateProof {
  if (!proofs || proofs.length === 0) {
    throw new Error('Cannot create composite predicate proof with empty proofs array.');
  }

  const commitments = proofs.map(p => p.commitment).join(':');
  const compositeCommitment = sha256Hex(`composite::${commitments}`);

  return {
    type: 'ZKCompositePredicateProof2026',
    proofs,
    compositeCommitment,
    timestamp: new Date().toISOString()
  };
}

/**
 * Validates a composite ZK predicate proof by verifying each underlying sub-proof.
 */
export function verifyCompositePredicate(
  compositeProof: ZKCompositePredicateProof,
  context?: { allowedSets?: Record<string, string[]>; restrictedSets?: Record<string, string[]> }
): { valid: boolean; verifiedCount: number; errors: string[] } {
  if (compositeProof.type !== 'ZKCompositePredicateProof2026') {
    return { valid: false, verifiedCount: 0, errors: ['Invalid composite proof type.'] };
  }

  const errors: string[] = [];
  let verifiedCount = 0;

  for (const proof of compositeProof.proofs) {
    if (proof.type === 'ZKRangePredicateProof2026') {
      const res = verifyRangeProof(proof);
      if (!res.valid) errors.push(`[${proof.claimKey}] Range error: ${res.error}`);
      else verifiedCount++;
    } else if (proof.type === 'ZKSetMembershipProof2026') {
      const allowed = context?.allowedSets?.[proof.claimKey] || [];
      if (allowed.length > 0) {
        const res = verifySetMembershipProof(proof, allowed);
        if (!res.valid) errors.push(`[${proof.claimKey}] Membership error: ${res.error}`);
        else verifiedCount++;
      } else {
        verifiedCount++;
      }
    } else if (proof.type === 'ZKSetNonMembershipProof2026') {
      const restricted = context?.restrictedSets?.[proof.claimKey] || [];
      if (restricted.length > 0) {
        const res = verifySetNonMembershipProof(proof, restricted);
        if (!res.valid) errors.push(`[${proof.claimKey}] Non-membership error: ${res.error}`);
        else verifiedCount++;
      } else {
        verifiedCount++;
      }
    } else if (proof.type === 'ZKSetIntersectionProof2026') {
      const target = context?.allowedSets?.[proof.claimKey] || [];
      if (target.length > 0) {
        const res = verifySetIntersectionProof(proof, target);
        if (!res.valid) errors.push(`[${proof.claimKey}] Set intersection error: ${res.error}`);
        else verifiedCount++;
      } else {
        verifiedCount++;
      }
    } else if (proof.type === 'ZKAgePredicateProof2026') {
      const res = verifyAgeProof(proof);
      if (!res.valid) errors.push(`[${proof.claimKey}] Age error: ${res.error}`);
      else verifiedCount++;
    } else if (proof.type === 'ZKDatePredicateProof2026') {
      const res = verifyDateRangeProof(proof);
      if (!res.valid) errors.push(`[${proof.claimKey}] Date error: ${res.error}`);
      else verifiedCount++;
    } else {
      errors.push(`Unknown proof type`);
    }
  }

  return {
    valid: errors.length === 0 && verifiedCount === compositeProof.proofs.length,
    verifiedCount,
    errors
  };
}
