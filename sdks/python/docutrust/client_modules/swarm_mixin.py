from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class SwarmMixin:

    def swarm_create_cluster(
        self,
        swarm_name: str,
        agents: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Creates a registered Swarm Agent Cluster."""
        from .swarm_consensus import SwarmConsensusEngine
        return SwarmConsensusEngine.create_swarm_cluster(swarm_name, agents)

    def swarm_propose_intent(
        self,
        swarm_id: str,
        proposer_did: str,
        intent_action: str,
        target_payload: Dict[str, Any],
        required_quorum_weight: int = 50,
        duration_minutes: int = 60
    ) -> Dict[str, Any]:
        """Proposes an intent action for collective swarm voting."""
        from .swarm_consensus import SwarmConsensusEngine
        return SwarmConsensusEngine.propose_intent(
            swarm_id, proposer_did, intent_action, target_payload, required_quorum_weight, duration_minutes
        )

    def swarm_sign_vote(
        self,
        proposal: Dict[str, Any],
        agent: Dict[str, Any],
        agent_private_key_hex: str,
        decision: str = "APPROVE",
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates a signed vote attestation from an agent member."""
        from .swarm_consensus import SwarmConsensusEngine
        return SwarmConsensusEngine.sign_vote(proposal, agent, agent_private_key_hex, decision, reason)

    def swarm_aggregate_quorum(
        self,
        proposal: Dict[str, Any],
        members: List[Dict[str, Any]],
        votes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Aggregates member votes and produces a verifiable Swarm Intent Proof."""
        from .swarm_consensus import SwarmConsensusEngine
        return SwarmConsensusEngine.aggregate_swarm_quorum(proposal, members, votes)

    def swarm_verify_proof(
        self,
        proof: Dict[str, Any],
        members: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Verifies a Swarm Intent Consensus Proof."""
        from .swarm_consensus import SwarmConsensusEngine
        return SwarmConsensusEngine.verify_swarm_proof(proof, members)
