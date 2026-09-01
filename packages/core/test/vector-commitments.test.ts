import { describe, it, expect } from 'vitest';
import { VectorCommitmentEngine } from '../src/vector-commitments';

describe('VectorCommitmentEngine (v19.0.0)', () => {
  const vector = [
    { attribute: 'jurisdiction', value: 'US-CA' },
    { attribute: 'minimum_age', value: 21 },
    { attribute: 'clearance_level', value: 'SECRET' },
    { attribute: 'authorized_spend_limit', value: 500000 },
    { attribute: 'kyc_tier', value: 'ENTERPRISE_3' }
  ];

  it('should compute constant-size vector commitment', () => {
    const commitment = VectorCommitmentEngine.commit(vector);
    expect(commitment.commitmentHex).toBeDefined();
    expect(commitment.dimension).toBe(vector.length);
    expect(commitment.commitmentHex.startsWith('0x')).toBe(true);
  });

  it('should generate and verify single-position opening proofs', () => {
    const commitment = VectorCommitmentEngine.commit(vector);
    const proof = VectorCommitmentEngine.provePosition(vector, 2);
    expect(proof.index).toBe(2);

    const verification = VectorCommitmentEngine.verifyPosition(commitment.commitmentHex, proof);
    expect(verification.valid).toBe(true);

    // Tampered value must fail verification
    const tamperedProof = { ...proof, valueElementHex: '0x1234567890abcdef' };
    const tamperedVerify = VectorCommitmentEngine.verifyPosition(commitment.commitmentHex, tamperedProof);
    expect(tamperedVerify.valid).toBe(false);
  });

  it('should generate and verify aggregated batch subvector opening proofs', () => {
    const commitment = VectorCommitmentEngine.commit(vector);
    const indices = [0, 2, 4];
    const subProof = VectorCommitmentEngine.proveSubvector(vector, indices);
    expect(subProof.indices).toEqual(indices);

    const verification = VectorCommitmentEngine.verifySubvector(commitment.commitmentHex, subProof);
    expect(verification.valid).toBe(true);

    // Tampered subvector must fail
    const tamperedSubProof = { ...subProof, indices: [0, 1, 4] };
    const tamperedVerify = VectorCommitmentEngine.verifySubvector(commitment.commitmentHex, tamperedSubProof);
    expect(tamperedVerify.valid).toBe(false);
  });
});
