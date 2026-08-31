"""
DocuTrust Sovereign Verifiable Credentials - Verifiable Swarm Intent Consensus Engine.
Provides threshold weighted-reputation voting across autonomous AI agent swarms,
cryptographic intent proposal commitments, and collective execution proofs.
"""

from __future__ import annotations
import time
import secrets
from typing import Dict, Any, List, Optional
from .crypto import canonicalize_json, sha256_hex
from .crypto import sign_data, verify_signature


class SwarmConsensusEngine:
    @classmethod
    def create_swarm_cluster(
        cls,
        swarm_name: str,
        agents: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Creates a registered Swarm Agent Cluster."""
        total_weight = 0
        members: List[Dict[str, Any]] = []

        for idx, a in enumerate(agents):
            weight = a.get("weight") or a.get("reputationWeight") or 10
            total_weight += weight
            members.append({
                "agentDid": a.get("did") or a.get("agentDid") or f"did:docutrust:agent_{idx}",
                "publicKeyHex": a.get("pubKey") or a.get("publicKeyHex"),
                "role": a.get("role", "executor"),
                "reputationWeight": weight,
                "registeredEpoch": 1
            })

        swarm_id = "swarm_" + sha256_hex(f"swarm:{swarm_name}:{secrets.token_hex(8)}")[:16]
        return {
            "swarmId": swarm_id,
            "members": members,
            "totalWeight": total_weight
        }

    @classmethod
    def propose_intent(
        cls,
        swarm_id: str,
        proposer_did: str,
        intent_action: str,
        target_payload: Dict[str, Any],
        required_quorum_weight: int,
        duration_minutes: int = 60
    ) -> Dict[str, Any]:
        """Proposes an intent action for collective swarm voting."""
        proposal_id = "prop_" + sha256_hex(f"prop:{swarm_id}:{intent_action}:{secrets.token_hex(8)}")[:16]
        expiry_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + duration_minutes * 60))

        proposal_digest = sha256_hex(canonicalize_json({
            "proposalId": proposal_id,
            "swarmId": swarm_id,
            "proposerDid": proposer_did,
            "intentAction": intent_action,
            "targetPayload": target_payload,
            "requiredQuorumWeight": required_quorum_weight,
            "expiryTimestamp": expiry_ts
        }))

        return {
            "proposalId": proposal_id,
            "swarmId": swarm_id,
            "proposerDid": proposer_did,
            "intentAction": intent_action,
            "targetPayload": target_payload,
            "requiredQuorumWeight": required_quorum_weight,
            "expiryTimestamp": expiry_ts,
            "proposalDigest": proposal_digest
        }

    @classmethod
    def sign_vote(
        cls,
        proposal: Dict[str, Any],
        agent: Dict[str, Any],
        agent_private_key_hex: str,
        decision: str = "APPROVE",
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates a signed vote attestation from an agent member."""
        agent_did = agent.get("agentDid") or agent.get("did", "")
        weight = agent.get("reputationWeight") or agent.get("weight", 10)
        vote_id = "vote_" + sha256_hex(f"vote:{proposal.get('proposalId')}:{agent_did}:{secrets.token_hex(8)}")[:16]
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        reason_digest = sha256_hex(reason) if reason else None

        vote_payload = canonicalize_json({
            "voteId": vote_id,
            "proposalId": proposal.get("proposalId"),
            "agentDid": agent_did,
            "decision": decision,
            "agentWeight": weight,
            "reasonDigest": reason_digest,
            "timestamp": timestamp
        })

        sig_hex = sign_data(vote_payload, agent_private_key_hex)

        return {
            "voteId": vote_id,
            "proposalId": proposal.get("proposalId"),
            "agentDid": agent_did,
            "decision": decision,
            "agentWeight": weight,
            "reasonDigest": reason_digest,
            "signatureHex": sig_hex,
            "timestamp": timestamp
        }

    @classmethod
    def aggregate_swarm_quorum(
        cls,
        proposal: Dict[str, Any],
        members: List[Dict[str, Any]],
        votes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Aggregates member votes and produces a verifiable Swarm Intent Proof."""
        member_map = {m.get("agentDid"): m for m in members}
        total_weight = sum(m.get("reputationWeight", 0) for m in members)

        achieved_weight = 0
        valid_votes: List[Dict[str, Any]] = []
        participating_dids: List[str] = []

        for v in votes:
            agent_did = v.get("agentDid")
            mem = member_map.get(agent_did)
            if not mem:
                continue

            vote_payload = canonicalize_json({
                "voteId": v.get("voteId"),
                "proposalId": v.get("proposalId"),
                "agentDid": agent_did,
                "decision": v.get("decision"),
                "agentWeight": mem.get("reputationWeight"),
                "reasonDigest": v.get("reasonDigest"),
                "timestamp": v.get("timestamp")
            })

            valid_sig = verify_signature(vote_payload, v.get("signatureHex", ""), mem.get("publicKeyHex", ""))
            if valid_sig:
                valid_votes.append(v)
                participating_dids.append(agent_did)
                if v.get("decision") == "APPROVE":
                    achieved_weight += mem.get("reputationWeight", 0)

        required_weight = proposal.get("requiredQuorumWeight", 50)
        consensus_outcome = "CONSENSUS_REACHED" if achieved_weight >= required_weight else "QUORUM_FAILED"
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        consensus_sig = sha256_hex(f"swarm_consensus_sig:{proposal.get('proposalDigest')}:{achieved_weight}:{timestamp}")

        proof_payload = {
            "swarmId": proposal.get("swarmId"),
            "proposalId": proposal.get("proposalId"),
            "intentAction": proposal.get("intentAction"),
            "targetPayload": proposal.get("targetPayload"),
            "proposalDigest": proposal.get("proposalDigest"),
            "totalSwarmWeight": total_weight,
            "achievedQuorumWeight": achieved_weight,
            "requiredQuorumWeight": required_weight,
            "consensusOutcome": consensus_outcome,
            "participatingAgentDids": participating_dids,
            "aggregatedVotes": valid_votes,
            "swarmConsensusSignature": consensus_sig,
            "timestamp": timestamp
        }
        proof_hash = sha256_hex(canonicalize_json(proof_payload))

        return {
            "type": "DocuTrustSwarmIntentProof2026",
            "swarmId": proposal.get("swarmId"),
            "proposalId": proposal.get("proposalId"),
            "intentAction": proposal.get("intentAction"),
            "targetPayload": proposal.get("targetPayload"),
            "proposalDigest": proposal.get("proposalDigest"),
            "totalSwarmWeight": total_weight,
            "achievedQuorumWeight": achieved_weight,
            "requiredQuorumWeight": required_weight,
            "consensusOutcome": consensus_outcome,
            "participatingAgentDids": participating_dids,
            "aggregatedVotes": valid_votes,
            "swarmConsensusSignature": consensus_sig,
            "timestamp": timestamp,
            "proofHash": proof_hash
        }

    @classmethod
    def verify_swarm_proof(
        cls,
        proof: Dict[str, Any],
        members: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Verifies a Swarm Intent Consensus Proof."""
        if not proof or proof.get("type") != "DocuTrustSwarmIntentProof2026":
            return {"valid": False, "error": "Invalid swarm intent proof payload"}

        if proof.get("consensusOutcome") != "CONSENSUS_REACHED":
            return {"valid": False, "error": "Swarm consensus quorum was not reached"}

        if proof.get("achievedQuorumWeight", 0) < proof.get("requiredQuorumWeight", 0):
            return {"valid": False, "error": "Achieved quorum weight is below threshold"}

        computed_hash = sha256_hex(canonicalize_json({
            "swarmId": proof.get("swarmId"),
            "proposalId": proof.get("proposalId"),
            "intentAction": proof.get("intentAction"),
            "targetPayload": proof.get("targetPayload"),
            "proposalDigest": proof.get("proposalDigest"),
            "totalSwarmWeight": proof.get("totalSwarmWeight"),
            "achievedQuorumWeight": proof.get("achievedQuorumWeight"),
            "requiredQuorumWeight": proof.get("requiredQuorumWeight"),
            "consensusOutcome": proof.get("consensusOutcome"),
            "participatingAgentDids": proof.get("participatingAgentDids"),
            "aggregatedVotes": proof.get("aggregatedVotes"),
            "swarmConsensusSignature": proof.get("swarmConsensusSignature"),
            "timestamp": proof.get("timestamp")
        }))

        if computed_hash != proof.get("proofHash"):
            return {"valid": False, "error": "Cryptographic proof hash mismatch"}

        return {"valid": True}
