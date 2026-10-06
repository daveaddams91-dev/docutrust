from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class IbcMixin:

    def ibc_compute_packet_commitment(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Computes deterministic ICS-04 packet commitment hash."""
        from .ibc_relayer import IBCRelayerEngine
        return IBCRelayerEngine.compute_packet_commitment(packet)

    def ibc_generate_merkle_proof(self, key: str, value_hex: str, depth: int = 4) -> Dict[str, Any]:
        """Creates a synthetic Merkle proof for an IBC state key-value pair."""
        from .ibc_relayer import IBCRelayerEngine
        return IBCRelayerEngine.generate_merkle_proof(key, value_hex, depth)

    def ibc_verify_merkle_proof(self, proof: Dict[str, Any], expected_root_app_hash: str) -> bool:
        """Verifies an IBC Merkle state proof against light-client AppHash."""
        from .ibc_relayer import IBCRelayerEngine
        return IBCRelayerEngine.verify_merkle_proof(proof, expected_root_app_hash)

    def ibc_create_light_client(
        self,
        chain_id: str,
        client_type: str,
        initial_height: Dict[str, int],
        initial_app_hash: str
    ) -> Dict[str, Any]:
        """Creates and initializes a light-client tracking state."""
        from .ibc_relayer import IBCRelayerEngine
        return IBCRelayerEngine.create_light_client(chain_id, client_type, initial_height, initial_app_hash)

    def ibc_update_light_client(
        self,
        client: Dict[str, Any],
        new_height: Dict[str, int],
        new_app_hash: str,
        validator_signatures: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Updates light-client state with a new header."""
        from .ibc_relayer import IBCRelayerEngine
        return IBCRelayerEngine.update_light_client(client, new_height, new_app_hash, validator_signatures)

    def ibc_relay_packet(
        self,
        packet: Dict[str, Any],
        proof: Dict[str, Any],
        source_client_on_dest: Dict[str, Any],
        proof_height: Dict[str, int],
        relayer_key_pair: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Relays an IBC packet across heterogeneous chains."""
        from .ibc_relayer import IBCRelayerEngine
        return IBCRelayerEngine.relay_packet(packet, proof, source_client_on_dest, proof_height, relayer_key_pair)
