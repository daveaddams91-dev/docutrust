from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class PssMixin:

    def pss_setup_committee(
        self,
        secret_hex: str,
        threshold: int,
        total_participants: int,
        participant_dids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Initializes a new PSS validator committee with Feldman VSS."""
        from .proactive_sharing import ProactiveSecretSharingEngine
        return ProactiveSecretSharingEngine.setup_committee(secret_hex, threshold, total_participants, participant_dids)

    def pss_generate_renewal_subshares(
        self,
        participant_id: int,
        threshold: int,
        total_participants: int,
        current_epoch: int
    ) -> Dict[str, Any]:
        """Generates zero-constant renewal sub-shares for proactive share rotation."""
        from .proactive_sharing import ProactiveSecretSharingEngine
        return ProactiveSecretSharingEngine.generate_renewal_subshares(participant_id, threshold, total_participants, current_epoch)

    def pss_apply_renewal(
        self,
        current_share: Dict[str, Any],
        received_packets: List[Dict[str, Any]],
        committee: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Applies received renewal packets to rotate a share for the next epoch."""
        from .proactive_sharing import ProactiveSecretSharingEngine
        return ProactiveSecretSharingEngine.apply_renewal(current_share, received_packets, committee)

    def pss_reconstruct_secret(
        self,
        shares: List[Dict[str, Any]],
        threshold: int
    ) -> Dict[str, Any]:
        """Reconstructs the master secret from any threshold subset of shares."""
        from .proactive_sharing import ProactiveSecretSharingEngine
        return ProactiveSecretSharingEngine.reconstruct_secret(shares, threshold)
