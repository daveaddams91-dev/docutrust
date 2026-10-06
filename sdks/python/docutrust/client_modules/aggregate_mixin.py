from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class AggregateMixin:

    def aggregate_dkg_signatures(
        self,
        group_public_key_hex: str,
        group_did: str,
        threshold: int,
        shares: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Aggregates partial signature shares into a valid group Ed25519 signature."""
        from .dkg import DKGEngine
        return DKGEngine.aggregate_signatures(group_public_key_hex, group_did, threshold, shares)

    def aggregate_groth16_proofs(self, proofs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregates multiple Groth16 proofs into a batched verification payload."""
        from .groth16 import Groth16Engine
        return Groth16Engine.aggregate_proofs(proofs)

    def aggregate_recursive_zk_proofs(
        self,
        sub_proofs: List[Dict[str, Any]],
        aggregator_key_pair: Dict[str, Any],
        depth: int = 1,
        generate_evm_calldata: bool = False
    ) -> Dict[str, Any]:
        """Aggregates multiple heterogeneous ZK sub-proofs via Fiat-Shamir recursive folding."""
        from .zk_recursive import ZKRecursiveEngine
        return ZKRecursiveEngine.aggregate_proofs(sub_proofs, aggregator_key_pair, depth, generate_evm_calldata)
