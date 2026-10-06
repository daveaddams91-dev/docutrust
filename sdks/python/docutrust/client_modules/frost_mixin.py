from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class FrostMixin:

    def frost_generate_dkg_key_shares(self, threshold: int, total_signers: int) -> Dict[str, Any]:
        """Generates FROST distributed key shares for t-of-n signers."""
        from .frost_threshold import FROSTEngine
        return FROSTEngine.generate_dkg_key_shares(threshold, total_signers)

    def frost_round1_commitment(self, signer_id: int) -> Dict[str, Any]:
        """Generates Round 1 hiding and binding nonces and commitments."""
        from .frost_threshold import FROSTEngine
        return FROSTEngine.round1_commitment(signer_id)

    def frost_round2_sign(
        self,
        message: str,
        signer_id: int,
        secret_share_hex: str,
        nonces: Dict[str, Any],
        commitment_list: List[Dict[str, Any]],
        group_public_key: str
    ) -> Dict[str, Any]:
        """Performs Round 2 partial signing."""
        from .frost_threshold import FROSTEngine
        return FROSTEngine.round2_sign(
            message, signer_id, secret_share_hex, nonces, commitment_list, group_public_key
        )

    def frost_aggregate_signatures(
        self,
        message: str,
        signature_shares: List[Dict[str, Any]],
        commitment_list: List[Dict[str, Any]],
        group_public_key: str,
        threshold: int
    ) -> Dict[str, Any]:
        """Aggregates partial signature shares into a valid FROST threshold signature."""
        from .frost_threshold import FROSTEngine
        return FROSTEngine.aggregate_signatures(
            message, signature_shares, commitment_list, group_public_key, threshold
        )

    def frost_verify_threshold_signature(
        self,
        message: str,
        signature: Dict[str, Any],
        expected_group_public_key: str
    ) -> Dict[str, Any]:
        """Verifies a FROST threshold signature."""
        from .frost_threshold import FROSTEngine
        return FROSTEngine.verify_threshold_signature(message, signature, expected_group_public_key)

    def frost_issue_threshold_credential(
        self,
        credential_subject: Dict[str, Any],
        threshold_signature: Dict[str, Any],
        issuer_did: str
    ) -> Dict[str, Any]:
        """Issues a Verifiable Credential signed with FROST threshold signature."""
        from .frost_threshold import FROSTEngine
        return FROSTEngine.issue_threshold_credential(credential_subject, threshold_signature, issuer_did)

    def frost_verify_threshold_credential(
        self,
        credential: Dict[str, Any],
        expected_group_public_key: str
    ) -> Dict[str, Any]:
        """Verifies a FROST threshold signed credential."""
        from .frost_threshold import FROSTEngine
        return FROSTEngine.verify_threshold_credential(credential, expected_group_public_key)

    def frost_consensus_init(
        self,
        participants: List[Dict[str, Any]],
        threshold: int,
        epoch: int = 1
    ) -> Dict[str, Any]:
        """Initializes an aBFT FROST consensus committee."""
        from .frost_consensus import FROSTConsensusEngine
        return FROSTConsensusEngine.init_committee(participants, threshold, epoch)

    def frost_consensus_share(
        self,
        committee: Dict[str, Any],
        participant_id: str,
        secret_share_hex: str,
        round_id: str,
        proposal_payload: Any
    ) -> Dict[str, Any]:
        """Generates a partial round consensus signature share."""
        from .frost_consensus import FROSTConsensusEngine
        return FROSTConsensusEngine.generate_round_share(
            committee, participant_id, secret_share_hex, round_id, proposal_payload
        )

    def frost_consensus_aggregate(
        self,
        committee: Dict[str, Any],
        round_id: str,
        proposal_payload: Any,
        round_shares: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Aggregates round shares into a threshold Schnorr consensus commitment."""
        from .frost_consensus import FROSTConsensusEngine
        return FROSTConsensusEngine.aggregate_consensus(
            committee, round_id, proposal_payload, round_shares
        )

    def frost_consensus_verify(
        self,
        committee: Dict[str, Any],
        commitment: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verifies an aggregated FROST consensus commitment."""
        from .frost_consensus import FROSTConsensusEngine
        return FROSTConsensusEngine.verify_consensus(committee, commitment)

    def frost_consensus_equivocation_proof(
        self,
        committee: Dict[str, Any],
        share1: Dict[str, Any],
        share2: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generates an equivocation slashing fraud proof for double-signing."""
        from .frost_consensus import FROSTConsensusEngine
        return FROSTConsensusEngine.generate_equivocation_fraud_proof(committee, share1, share2)
