import * as crypto from 'crypto';
import { canonicalizeJson, sha256Hex, generateKeyPair, signData, verifySignature } from '../crypto';

export interface SwarmAgentMember {
  agentDid: string;
  publicKeyHex: string;
  role: string;
  reputationWeight: number; // e.g. 1 to 100
  registeredEpoch: number;
}

export interface SwarmIntentProposal {
  proposalId: string;
  swarmId: string;
  proposerDid: string;
  intentAction: string;
  targetPayload: Record<string, any>;
  requiredQuorumWeight: number;
  expiryTimestamp: string;
  proposalDigest: string;
}

export interface AgentVoteAttestation {
  voteId: string;
  proposalId: string;
  agentDid: string;
  decision: 'APPROVE' | 'REJECT' | 'ABSTAIN';
  agentWeight: number;
  reasonDigest?: string;
  signatureHex: string;
  timestamp: string;
}

export interface SwarmIntentProof {
  type: 'DocuTrustSwarmIntentProof2026';
  swarmId: string;
  proposalId: string;
  intentAction: string;
  targetPayload: Record<string, any>;
  proposalDigest: string;
  totalSwarmWeight: number;
  achievedQuorumWeight: number;
  requiredQuorumWeight: number;
  consensusOutcome: 'CONSENSUS_REACHED' | 'QUORUM_FAILED';
  participatingAgentDids: string[];
  aggregatedVotes: AgentVoteAttestation[];
  swarmConsensusSignature: string;
  timestamp: string;
  proofHash: string;
}

export class SwarmConsensusEngine {
  /**
   * Initializes a multi-agent swarm cluster with registered agent identities.
   */
  public static createSwarmCluster(
    swarmName: string,
    agents: Array<{ did?: string; agentDid?: string; pubKey?: string; publicKeyHex?: string; role?: string; weight?: number; reputationWeight?: number }>
  ): { swarmId: string; members: SwarmAgentMember[]; totalWeight: number } {
    let totalWeight = 0;
    const members: SwarmAgentMember[] = agents.map((a, idx) => {
      const weight = a.weight || a.reputationWeight || 10;
      totalWeight += weight;
      return {
        agentDid: a.did || a.agentDid || `did:docutrust:agent_${idx}`,
        publicKeyHex: a.pubKey || a.publicKeyHex || '',
        role: a.role || 'executor',
        reputationWeight: weight,
        registeredEpoch: 1
      };
    });

    const swarmId = 'swarm_' + sha256Hex(`swarm:${swarmName}:${Date.now()}`).substring(0, 16);
    return { swarmId, members, totalWeight };
  }

  /**
   * Proposes an intent action for collective swarm voting.
   */
  public static proposeIntent(
    swarmId: string,
    proposerDid: string,
    intentAction: string,
    targetPayload: Record<string, any>,
    requiredQuorumWeight: number,
    durationMinutes: number = 60
  ): SwarmIntentProposal {
    const proposalId = 'prop_' + sha256Hex(`prop:${swarmId}:${intentAction}:${Date.now()}`).substring(0, 16);
    const expiryTimestamp = new Date(Date.now() + durationMinutes * 60 * 1000).toISOString();
    const proposalDigest = sha256Hex(canonicalizeJson({
      proposalId,
      swarmId,
      proposerDid,
      intentAction,
      targetPayload,
      requiredQuorumWeight,
      expiryTimestamp
    }));

    return {
      proposalId,
      swarmId,
      proposerDid,
      intentAction,
      targetPayload,
      requiredQuorumWeight,
      expiryTimestamp,
      proposalDigest
    };
  }

  /**
   * Generates a signed vote attestation from an agent member.
   */
  public static signVote(
    proposal: SwarmIntentProposal,
    agent: SwarmAgentMember,
    agentPrivateKeyHex: string,
    decision: 'APPROVE' | 'REJECT' | 'ABSTAIN',
    reason?: string
  ): AgentVoteAttestation {
    const voteId = 'vote_' + sha256Hex(`vote:${proposal.proposalId}:${agent.agentDid}:${Date.now()}`).substring(0, 16);
    const timestamp = new Date().toISOString();
    const reasonDigest = reason ? sha256Hex(reason) : undefined;

    const votePayload = canonicalizeJson({
      voteId,
      proposalId: proposal.proposalId,
      agentDid: agent.agentDid,
      decision,
      agentWeight: agent.reputationWeight,
      reasonDigest,
      timestamp
    });

    const signatureHex = signData(votePayload, agentPrivateKeyHex);

    return {
      voteId,
      proposalId: proposal.proposalId,
      agentDid: agent.agentDid,
      decision,
      agentWeight: agent.reputationWeight,
      reasonDigest,
      signatureHex,
      timestamp
    };
  }

  /**
   * Aggregates member votes and produces a verifiable Swarm Intent Consensus Proof.
   */
  public static aggregateSwarmQuorum(
    proposal: SwarmIntentProposal,
    members: SwarmAgentMember[],
    votes: AgentVoteAttestation[]
  ): SwarmIntentProof {
    const memberMap = new Map<string, SwarmAgentMember>(members.map(m => [m.agentDid, m]));
    let totalSwarmWeight = 0;
    members.forEach(m => { totalSwarmWeight += m.reputationWeight; });

    let achievedQuorumWeight = 0;
    const validVotes: AgentVoteAttestation[] = [];
    const participatingAgentDids: string[] = [];

    for (const v of votes) {
      const mem = memberMap.get(v.agentDid);
      if (!mem) continue;

      // Verify individual vote signature
      const votePayload = canonicalizeJson({
        voteId: v.voteId,
        proposalId: v.proposalId,
        agentDid: v.agentDid,
        decision: v.decision,
        agentWeight: mem.reputationWeight,
        reasonDigest: v.reasonDigest,
        timestamp: v.timestamp
      });

      const validSig = verifySignature(votePayload, v.signatureHex, mem.publicKeyHex);
      if (validSig) {
        validVotes.push(v);
        participatingAgentDids.push(v.agentDid);
        if (v.decision === 'APPROVE') {
          achievedQuorumWeight += mem.reputationWeight;
        }
      }
    }

    const consensusOutcome = achievedQuorumWeight >= proposal.requiredQuorumWeight
      ? 'CONSENSUS_REACHED'
      : 'QUORUM_FAILED';

    const timestamp = new Date().toISOString();
    const swarmConsensusSignature = sha256Hex(`swarm_consensus_sig:${proposal.proposalDigest}:${achievedQuorumWeight}:${timestamp}`);

    const proofPayload = {
      swarmId: proposal.swarmId,
      proposalId: proposal.proposalId,
      intentAction: proposal.intentAction,
      targetPayload: proposal.targetPayload,
      proposalDigest: proposal.proposalDigest,
      totalSwarmWeight,
      achievedQuorumWeight,
      requiredQuorumWeight: proposal.requiredQuorumWeight,
      consensusOutcome,
      participatingAgentDids,
      aggregatedVotes: validVotes,
      swarmConsensusSignature,
      timestamp
    };
    const proofHash = sha256Hex(canonicalizeJson(proofPayload));

    return {
      type: 'DocuTrustSwarmIntentProof2026',
      swarmId: proposal.swarmId,
      proposalId: proposal.proposalId,
      intentAction: proposal.intentAction,
      targetPayload: proposal.targetPayload,
      proposalDigest: proposal.proposalDigest,
      totalSwarmWeight,
      achievedQuorumWeight,
      requiredQuorumWeight: proposal.requiredQuorumWeight,
      consensusOutcome,
      participatingAgentDids,
      aggregatedVotes: validVotes,
      swarmConsensusSignature,
      timestamp,
      proofHash
    };
  }

  /**
   * Verifies a Swarm Intent Consensus Proof.
   */
  public static verifySwarmProof(
    proof: SwarmIntentProof,
    members: SwarmAgentMember[]
  ): { valid: boolean; error?: string } {
    if (!proof || proof.type !== 'DocuTrustSwarmIntentProof2026') {
      return { valid: false, error: 'Invalid swarm intent proof payload' };
    }

    if (proof.consensusOutcome !== 'CONSENSUS_REACHED') {
      return { valid: false, error: 'Swarm consensus quorum was not reached' };
    }

    if (proof.achievedQuorumWeight < proof.requiredQuorumWeight) {
      return { valid: false, error: 'Achieved quorum weight is below threshold' };
    }

    const computedHash = sha256Hex(canonicalizeJson({
      swarmId: proof.swarmId,
      proposalId: proof.proposalId,
      intentAction: proof.intentAction,
      targetPayload: proof.targetPayload,
      proposalDigest: proof.proposalDigest,
      totalSwarmWeight: proof.totalSwarmWeight,
      achievedQuorumWeight: proof.achievedQuorumWeight,
      requiredQuorumWeight: proof.requiredQuorumWeight,
      consensusOutcome: proof.consensusOutcome,
      participatingAgentDids: proof.participatingAgentDids,
      aggregatedVotes: proof.aggregatedVotes,
      swarmConsensusSignature: proof.swarmConsensusSignature,
      timestamp: proof.timestamp
    }));

    if (computedHash !== proof.proofHash) {
      return { valid: false, error: 'Cryptographic proof hash mismatch' };
    }

    return { valid: true };
  }
}
