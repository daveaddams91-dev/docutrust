from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class AgentMixin:

    def agent_memory_commit(
        self,
        agent_did: str,
        memory_nodes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Creates a cryptographic Merkle commitment over an agent's memory graph."""
        from .agent_memory import AgentMemoryEngine
        return AgentMemoryEngine.commit_memory_graph(agent_did, memory_nodes)

    def agent_memory_prove_similarity(
        self,
        query_embedding: List[float],
        target_node: Dict[str, Any],
        node_index: int = 0,
        graph_commitment: Optional[Dict[str, Any]] = None,
        min_cosine_threshold: float = 0.75
    ) -> Dict[str, Any]:
        """Generates a ZK Cosine Similarity bounds proof for a memory retrieval."""
        from .agent_memory import AgentMemoryEngine
        return AgentMemoryEngine.generate_similarity_proof(
            query_embedding, target_node, node_index, graph_commitment, min_cosine_threshold
        )

    def agent_memory_verify_similarity(
        self,
        graph_commitment: Dict[str, Any],
        proof: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verifies a ZK embedding similarity proof."""
        from .agent_memory import AgentMemoryEngine
        return AgentMemoryEngine.verify_similarity_proof(graph_commitment, proof)

    def agent_memory_audit(
        self,
        graph: Dict[str, Any],
        incoming_content: str,
        incoming_embedding: List[float]
    ) -> Dict[str, Any]:
        """Audits incoming memory for prompt injection or poisoning anomalies."""
        from .agent_memory import AgentMemoryEngine
        return AgentMemoryEngine.audit_memory_poisoning(graph, incoming_content, incoming_embedding)

    def agent_contract_create(
        self,
        principal_did: str,
        agent_did: str,
        task_spec: Dict[str, Any],
        bounty_amount: int = 1000,
        agent_stake_amount: int = 500,
        challenge_window_seconds: int = 3600
    ) -> Dict[str, Any]:
        """Creates an escrow smart contract for an autonomous AI agent."""
        from .agent_contract import AgentContractEngine
        return AgentContractEngine.create_contract(
            principal_did, agent_did, task_spec, bounty_amount, agent_stake_amount, challenge_window_seconds
        )

    def agent_contract_submit_execution(
        self,
        contract: Dict[str, Any],
        output_payload: Dict[str, Any],
        execution_steps: Optional[List[Any]] = None
    ) -> Dict[str, Any]:
        """Submits agent execution traces and output to the contract."""
        from .agent_contract import AgentContractEngine
        return AgentContractEngine.submit_execution(contract, output_payload, execution_steps)

    def agent_contract_verify_and_slash(
        self,
        contract: Dict[str, Any],
        receipt: Dict[str, Any],
        dispute: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluates a fraud proof and slashes agent collateral if invalid execution is proven."""
        from .agent_contract import AgentContractEngine
        return AgentContractEngine.verify_and_slash(contract, receipt, dispute)

    def agent_contract_settle(
        self,
        contract: Dict[str, Any],
        receipt: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Settles contract and releases bounty upon challenge window expiration."""
        from .agent_contract import AgentContractEngine
        return AgentContractEngine.settle_contract(contract, receipt)

    def agent_auction_create(
        self,
        auctioneer_did: str,
        task_spec: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Initializes a new sealed-bid capability auction."""
        from .agent_auction import AgentAuctionEngine
        return AgentAuctionEngine.create_auction(auctioneer_did, task_spec)

    def agent_auction_commit_bid(
        self,
        auction: Dict[str, Any],
        agent_did: str,
        bid_amount: int,
        stake_amount: int,
        salt: str
    ) -> Dict[str, Any]:
        """Submits a cryptographic commitment hiding the bid amount and stake."""
        from .agent_auction import AgentAuctionEngine
        return AgentAuctionEngine.commit_bid(auction, agent_did, bid_amount, stake_amount, salt)

    def agent_auction_reveal_bid(
        self,
        auction: Dict[str, Any],
        commitment_id: str,
        agent_did: str,
        bid_amount: int,
        stake_amount: int,
        salt: str,
        quality_metric: Optional[float] = 1.0
    ) -> Dict[str, Any]:
        """Reveals the sealed bid values and verifies against the commitment hash."""
        from .agent_auction import AgentAuctionEngine
        return AgentAuctionEngine.reveal_bid(auction, commitment_id, agent_did, bid_amount, stake_amount, salt, quality_metric)

    def agent_auction_clear(
        self,
        auction: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Clears the auction using Vickrey second-price procurement logic."""
        from .agent_auction import AgentAuctionEngine
        return AgentAuctionEngine.clear_auction(auction)

    def agent_auction_settle(
        self,
        auction: Dict[str, Any],
        clearing_result: Dict[str, Any],
        execution_receipt_id: str
    ) -> Dict[str, Any]:
        """Settles escrow payout upon verified task execution."""
        from .agent_auction import AgentAuctionEngine
        return AgentAuctionEngine.settle_auction(auction, clearing_result, execution_receipt_id)

    def agent_auction_slash(
        self,
        auction: Dict[str, Any],
        dispute_proof: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Slashes malicious or defaulted winning agent stake upon fraud proof."""
        from .agent_auction import AgentAuctionEngine
        return AgentAuctionEngine.slash_agent(auction, dispute_proof)

    def agent_federation_generate_identity(
        self,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Creates a sovereign AI Agent Identity document with cryptographic public key and epistemic vector."""
        from .agent_federation import AgentFederationEngine
        return AgentFederationEngine.generate_agent_identity(options)

    def agent_federation_issue_delegation(
        self,
        issuer_key_pair: Dict[str, str],
        subject_did: str,
        delegated_capabilities: List[str],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Issues an attenuated multi-hop delegation token authorizing capability execution."""
        from .agent_federation import AgentFederationEngine
        return AgentFederationEngine.issue_delegation_token(issuer_key_pair, subject_did, delegated_capabilities, options)

    def agent_federation_verify_path(
        self,
        delegation_chain: List[Dict[str, Any]],
        root_authority: Dict[str, Any],
        requested_capability: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validates capability attenuation and cryptographic provenance across a multi-hop delegation chain."""
        from .agent_federation import AgentFederationEngine
        return AgentFederationEngine.verify_transitive_trust_path(delegation_chain, root_authority, requested_capability)

    def agent_federation_init_handshake(
        self,
        initiator_key_pair: Dict[str, str],
        responder_did: str
    ) -> Dict[str, Any]:
        """Initiates mutual Zero-Knowledge Agent Handshake session."""
        from .agent_federation import AgentFederationEngine
        return AgentFederationEngine.initiate_agent_handshake(initiator_key_pair, responder_did)

    def agent_federation_respond_handshake(
        self,
        responder_key_pair: Dict[str, str],
        handshake_init: Dict[str, Any],
        initiator_public_key_hex: str
    ) -> Dict[str, Any]:
        """Processes handshake initiation and generates mutual authentication response."""
        from .agent_federation import AgentFederationEngine
        return AgentFederationEngine.respond_agent_handshake(responder_key_pair, handshake_init, initiator_public_key_hex)

    def agent_federation_complete_handshake(
        self,
        ephemeral_secret: str,
        handshake_init: Dict[str, Any],
        handshake_response: Dict[str, Any],
        responder_public_key_hex: str
    ) -> Dict[str, Any]:
        """Finalizes mutual ZK handshake verification on initiator side."""
        from .agent_federation import AgentFederationEngine
        return AgentFederationEngine.complete_agent_handshake(ephemeral_secret, handshake_init, handshake_response, responder_public_key_hex)
