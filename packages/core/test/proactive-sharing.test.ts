import { describe, it, expect } from 'vitest';
import { ProactiveSecretSharingEngine } from '../src/proactive-sharing';

describe('ProactiveSecretSharingEngine (v19.0.0)', () => {
  const masterSecret = '0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0';
  const threshold = 3;
  const total = 5;

  it('should initialize committee and split secret into valid Feldman shares', () => {
    const res = ProactiveSecretSharingEngine.setupCommittee(masterSecret, threshold, total);
    expect(res.committee.threshold).toBe(threshold);
    expect(res.committee.totalParticipants).toBe(total);
    expect(res.committee.epoch).toBe(0);
    expect(res.shares.length).toBe(total);
    expect(res.committee.publicCommitments.length).toBe(threshold);

    // Verify initial reconstruction from shares 1, 2, 3
    const initialReconstructed = ProactiveSecretSharingEngine.reconstructSecret(res.shares.slice(0, 3), threshold);
    expect(initialReconstructed.valid).toBe(true);
    expect(initialReconstructed.secretHex.toLowerCase()).toBe(res.reconstructionCheckHex.toLowerCase());
  });

  it('should execute proactive share renewal across epochs and preserve master secret reconstruction', () => {
    const setup = ProactiveSecretSharingEngine.setupCommittee(masterSecret, threshold, total);
    const initialShares = setup.shares;

    // Simulate each participant generating zero-constant renewal polynomials
    const allPackets: any[] = [];
    const allCoeffs: bigint[][] = [];

    for (let i = 1; i <= total; i++) {
      const renewal = ProactiveSecretSharingEngine.generateRenewalSubShares(i, threshold, total, 0);
      allPackets.push(...renewal.subSharePackets);
      allCoeffs.push(renewal.zeroCoefficients.map(c => BigInt('0x' + c)));
    }

    // Each participant applies received packets
    const epoch1Shares = initialShares.map(share => {
      const received = allPackets.filter(p => p.toParticipant === share.participantId);
      return ProactiveSecretSharingEngine.applyRenewal(share, received, setup.committee);
    });

    const { updatedCommittee, receipt } = ProactiveSecretSharingEngine.finalizeResharingRound(
      setup.committee,
      allCoeffs,
      epoch1Shares
    );

    expect(updatedCommittee.epoch).toBe(1);
    expect(receipt.newEpoch).toBe(1);
    expect(epoch1Shares[0].epoch).toBe(1);

    // Shares in epoch 1 must differ from epoch 0
    expect(epoch1Shares[0].shareHex).not.toBe(initialShares[0].shareHex);

    // Any 3 shares from epoch 1 must reconstruct the EXACT same master secret
    const recon1 = ProactiveSecretSharingEngine.reconstructSecret(epoch1Shares.slice(1, 4), threshold);
    expect(recon1.valid).toBe(true);
    expect(recon1.secretHex.toLowerCase()).toBe(setup.reconstructionCheckHex.toLowerCase());
  });
});
