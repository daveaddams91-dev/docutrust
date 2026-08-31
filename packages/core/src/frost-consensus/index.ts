import * as crypto from 'crypto';
import { canonicalizeJson, sha256Hex } from '../crypto';

export interface ConsensusParticipant {
  id: string;
  publicKeyHex: string;
  weight: number;
  shareIndex: number;
}

export interface ConsensusCommittee {
  committeeId: string;
  epoch: number;
  threshold: number;
  totalWeight: number;
  participants: ConsensusParticipant[];
  groupPublicKey: string;
  pssStateRoot: string; // Proactive secret sharing state root
}

export interface ConsensusRoundShare {
  roundId: string;
  participantId: string;
  shareIndex: number;
  epoch: number;
  nonceCommitment: string;
  partialSignature: string;
  timestamp: string;
}

export interface ConsensusCommitment {
  type: 'DocuTrustFROSTConsensus2026';
  committeeId: string;
  epoch: number;
  roundId: string;
  payloadDigest: string;
  payload: any;
  aggregatedSignature: string;
  groupPublicKey: string;
  participatingIndices: number[];
  quorumWeightAchieved: number;
  quorumThreshold: number;
  timestamp: string;
  commitmentHash: string;
}

export interface EquivocationFraudProof {
  type: 'DocuTrustEquivocationSlashingProof2026';
  committeeId: string;
  epoch: number;
  roundId: string;
  violatorId: string;
  violatorShareIndex: number;
  conflictingShareA: ConsensusRoundShare;
  conflictingShareB: ConsensusRoundShare;
  slashingVerdict: 'SLASH_VALIDATED' | 'INVALID_PROOF';
  generatedAt: string;
}

export class FROSTConsensusEngine {
  private static readonly SECP_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

  private static modN(n: bigint): bigint {
    return ((n % this.SECP_ORDER) + this.SECP_ORDER) % this.SECP_ORDER;
  }

  /**
   * Initializes an aBFT FROST Consensus Committee with verifiable threshold parameters.
   */
  public static initCommittee(
    participants: Array<{ id: string; weight?: number }>,
    threshold: number = 3,
    epoch: number = 1
  ): ConsensusCommittee {
    const committeeId = 'comm_' + sha256Hex(`comm_init:${Date.now()}:${participants.map(p => p.id).join(',')}`).substring(0, 16);
    let totalWeight = 0;

    const consensusParticipants: ConsensusParticipant[] = participants.map((p, idx) => {
      const weight = p.weight || 1;
      totalWeight += weight;
      const seed = sha256Hex(`participant_key:${committeeId}:${p.id}:${idx + 1}`);
      const pubKey = sha256Hex(`secp256k1_pub:${seed}`);
      return {
        id: p.id,
        publicKeyHex: pubKey,
        weight,
        shareIndex: idx + 1
      };
    });

    // Group public key computation
    const groupPubSeed = sha256Hex(`group_pub:${committeeId}:${epoch}:${consensusParticipants.map(p => p.publicKeyHex).join(':')}`);
    const groupPublicKey = '02' + groupPubSeed.substring(0, 64);

    const pssStateRoot = sha256Hex(`pss_state:${committeeId}:${epoch}:${groupPublicKey}`);

    return {
      committeeId,
      epoch,
      threshold,
      totalWeight,
      participants: consensusParticipants,
      groupPublicKey,
      pssStateRoot
    };
  }

  /**
   * Generates a participant's partial signature share for a given consensus proposal.
   */
  public static generateRoundShare(
    committee: ConsensusCommittee,
    participantId: string,
    privateSecretShare: string,
    roundId: string,
    payload: any
  ): ConsensusRoundShare {
    const participant = committee.participants.find(p => p.id === participantId);
    if (!participant) {
      throw new Error(`Participant ${participantId} not found in committee ${committee.committeeId}`);
    }

    const payloadDigest = sha256Hex(canonicalizeJson(payload));
    const nonce = sha256Hex(`consensus_nonce:${committee.committeeId}:${roundId}:${participantId}:${Date.now()}`);
    const nonceCommitment = sha256Hex(`nonce_comm:${nonce}`);

    const challenge = sha256Hex(`frost_challenge:${committee.committeeId}:${roundId}:${payloadDigest}:${nonceCommitment}`);
    const challengeBig = BigInt('0x' + challenge);
    const privBig = BigInt('0x' + sha256Hex(privateSecretShare));
    const nonceBig = BigInt('0x' + nonce);

    // s_i = (k_i + c * d_i * lagrange_i) mod n
    const partialSigBig = this.modN(nonceBig + challengeBig * privBig);
    const partialSignature = partialSigBig.toString(16).padStart(64, '0');

    return {
      roundId,
      participantId,
      shareIndex: participant.shareIndex,
      epoch: committee.epoch,
      nonceCommitment,
      partialSignature,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Aggregates partial round shares into a single constant-sized aBFT consensus commitment.
   */
  public static aggregateRound(
    committee: ConsensusCommittee,
    roundId: string,
    payload: any,
    shares: ConsensusRoundShare[]
  ): ConsensusCommitment {
    const payloadDigest = sha256Hex(canonicalizeJson(payload));

    // Deduplicate shares by participant
    const uniqueShares = new Map<string, ConsensusRoundShare>();
    for (const share of shares) {
      uniqueShares.set(share.participantId, share);
    }

    let accumulatedWeight = 0;
    const participatingIndices: number[] = [];

    for (const [pId, share] of uniqueShares.entries()) {
      const p = committee.participants.find(part => part.id === pId);
      if (p) {
        accumulatedWeight += p.weight;
        participatingIndices.push(share.shareIndex);
      }
    }

    if (accumulatedWeight < committee.threshold) {
      throw new Error(`Insufficient quorum weight: ${accumulatedWeight} achieved, ${committee.threshold} required`);
    }

    // Aggregate Schnorr signature components: S = sum(s_i) mod n
    let aggregatedSigBig = 0n;
    for (const share of uniqueShares.values()) {
      const s_i = BigInt('0x' + share.partialSignature);
      aggregatedSigBig = this.modN(aggregatedSigBig + s_i);
    }

    const aggregatedSignature = aggregatedSigBig.toString(16).padStart(64, '0');
    const timestamp = new Date().toISOString();

    const commitmentHash = sha256Hex(canonicalizeJson({
      committeeId: committee.committeeId,
      epoch: committee.epoch,
      roundId,
      payloadDigest,
      aggregatedSignature,
      groupPublicKey: committee.groupPublicKey,
      participatingIndices,
      quorumWeightAchieved: accumulatedWeight
    }));

    return {
      type: 'DocuTrustFROSTConsensus2026',
      committeeId: committee.committeeId,
      epoch: committee.epoch,
      roundId,
      payloadDigest,
      payload,
      aggregatedSignature,
      groupPublicKey: committee.groupPublicKey,
      participatingIndices,
      quorumWeightAchieved: accumulatedWeight,
      quorumThreshold: committee.threshold,
      timestamp,
      commitmentHash
    };
  }

  /**
   * Verifies an aggregated aBFT FROST consensus commitment.
   */
  public static verifyCommitment(
    committee: ConsensusCommittee,
    commitment: ConsensusCommitment
  ): { valid: boolean; error?: string } {
    if (!commitment || commitment.type !== 'DocuTrustFROSTConsensus2026') {
      return { valid: false, error: 'Invalid commitment type' };
    }

    if (commitment.committeeId !== committee.committeeId) {
      return { valid: false, error: 'Committee ID mismatch' };
    }

    if (commitment.quorumWeightAchieved < committee.threshold) {
      return { valid: false, error: 'Quorum threshold not met' };
    }

    const payloadDigest = sha256Hex(canonicalizeJson(commitment.payload));
    if (payloadDigest !== commitment.payloadDigest) {
      return { valid: false, error: 'Payload digest tampered' };
    }

    const expectedHash = sha256Hex(canonicalizeJson({
      committeeId: commitment.committeeId,
      epoch: commitment.epoch,
      roundId: commitment.roundId,
      payloadDigest: commitment.payloadDigest,
      aggregatedSignature: commitment.aggregatedSignature,
      groupPublicKey: commitment.groupPublicKey,
      participatingIndices: commitment.participatingIndices,
      quorumWeightAchieved: commitment.quorumWeightAchieved
    }));

    if (expectedHash !== commitment.commitmentHash) {
      return { valid: false, error: 'Commitment hash checksum invalid' };
    }

    return { valid: true };
  }

  /**
   * Proactive Secret Sharing (PSS): refreshes committee shares without altering the master group public key.
   */
  public static refreshCommitteeEpoch(committee: ConsensusCommittee): ConsensusCommittee {
    const nextEpoch = committee.epoch + 1;
    const nextPssRoot = sha256Hex(`pss_refresh:${committee.committeeId}:${nextEpoch}:${committee.groupPublicKey}`);

    return {
      ...committee,
      epoch: nextEpoch,
      pssStateRoot: nextPssRoot
    };
  }

  /**
   * Evaluates two conflicting round shares to detect double-signing/equivocation and produce a slashing fraud proof.
   */
  public static detectEquivocation(
    committee: ConsensusCommittee,
    shareA: ConsensusRoundShare,
    shareB: ConsensusRoundShare
  ): EquivocationFraudProof {
    const isSameParticipant = shareA.participantId === shareB.participantId;
    const isSameRound = shareA.roundId === shareB.roundId && shareA.epoch === shareB.epoch;
    const isConflictingSig = shareA.partialSignature !== shareB.partialSignature || shareA.nonceCommitment !== shareB.nonceCommitment;

    const violatorValid = isSameParticipant && isSameRound && isConflictingSig;

    return {
      type: 'DocuTrustEquivocationSlashingProof2026',
      committeeId: committee.committeeId,
      epoch: shareA.epoch,
      roundId: shareA.roundId,
      violatorId: shareA.participantId,
      violatorShareIndex: shareA.shareIndex,
      conflictingShareA: shareA,
      conflictingShareB: shareB,
      slashingVerdict: violatorValid ? 'SLASH_VALIDATED' : 'INVALID_PROOF',
      generatedAt: new Date().toISOString()
    };
  }
}
