from __future__ import annotations
import hashlib
import json
import time
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex

class IBCRelayerEngine:
    """
    DocuTrust Inter-Blockchain Communication (IBC) & Light-Client Relayer Mesh (v15.0.0).
    Implements ICS-04 cross-chain packet routing, Merkle multi-store state proofs,
    and heterogeneous blockchain trust relayer bridging.
    """

    @classmethod
    def compute_packet_commitment(cls, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Computes deterministic ICS-04 packet commitment hash."""
        raw_data = packet['data'] if isinstance(packet['data'], str) else canonicalize_json(packet['data'])
        data_hash = sha256_hex(raw_data)

        timeout_h = packet['timeoutHeight']
        timeout_preimage = f"{packet['timeoutTimestamp']}:{timeout_h['revisionNumber']}:{timeout_h['revisionHeight']}:{data_hash}"
        commitment_bytes_hex = sha256_hex(timeout_preimage)

        commitment_path = f"commitments/ports/{packet['sourcePort']}/channels/{packet['sourceChannel']}/sequences/{packet['sequence']}"
        packet_hash = sha256_hex(
            f"IBC_PACKET_V15:{packet['sequence']}:{packet['sourcePort']}:{packet['sourceChannel']}:{packet['destinationPort']}:{packet['destinationChannel']}:{data_hash}"
        )

        return {
            'packet': packet,
            'commitmentBytesHex': commitment_bytes_hex,
            'commitmentPath': commitment_path,
            'packetHash': packet_hash
        }

    @classmethod
    def generate_merkle_proof(cls, key: str, value_hex: str, depth: int = 4) -> Dict[str, Any]:
        """Creates a synthetic Merkle proof for a state key-value pair under a root AppHash."""
        proof_path = []
        current_hash = sha256_hex(f"LEAF:{key}:{value_hex}")

        for i in range(depth):
            sibling_hash = sha256_hex(f"SIBLING_LEVEL_{i}:{key}")
            is_left = (i % 2 == 0)
            proof_path.append({
                'type': 'left' if is_left else 'right',
                'hash': sibling_hash
            })

            if is_left:
                current_hash = sha256_hex(f"NODE:{sibling_hash}:{current_hash}")
            else:
                current_hash = sha256_hex(f"NODE:{current_hash}:{sibling_hash}")

        return {
            'key': key,
            'valueHash': value_hex,
            'proofPath': proof_path,
            'rootAppHash': current_hash
        }

    @classmethod
    def verify_merkle_proof(cls, proof: Dict[str, Any], expected_root_app_hash: str) -> bool:
        """Verifies an IBC Merkle multi-store state proof against a trusted light-client AppHash."""
        current_hash = sha256_hex(f"LEAF:{proof['key']}:{proof['valueHash']}")

        for node in proof['proofPath']:
            if node['type'] == 'left':
                current_hash = sha256_hex(f"NODE:{node['hash']}:{current_hash}")
            else:
                current_hash = sha256_hex(f"NODE:{current_hash}:{node['hash']}")

        return current_hash.lower() == expected_root_app_hash.lower()

    @classmethod
    def create_light_client(
        cls,
        chain_id: str,
        client_type: str,
        initial_height: Dict[str, int],
        initial_app_hash: str,
        trusting_period_seconds: int = 1209600,
        unbonding_period_seconds: int = 1814400
    ) -> Dict[str, Any]:
        """Creates and initializes a light-client tracking state for a connected blockchain."""
        height_key = f"{initial_height['revisionNumber']}-{initial_height['revisionHeight']}"
        consensus_state = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'appHash': initial_app_hash.lower(),
            'nextValidatorsHash': sha256_hex(f"VALIDATORS:{chain_id}:{height_key}")
        }

        return {
            'chainId': chain_id,
            'clientType': client_type,
            'trustingPeriodSeconds': trusting_period_seconds,
            'unbondingPeriodSeconds': unbonding_period_seconds,
            'latestHeight': initial_height,
            'consensusStates': {
                height_key: consensus_state
            }
        }

    @classmethod
    def update_light_client(
        cls,
        client: Dict[str, Any],
        new_height: Dict[str, int],
        new_app_hash: str,
        validator_signatures: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Updates light-client state with a new header and block root."""
        height_key = f"{new_height['revisionNumber']}-{new_height['revisionHeight']}"
        updated_consensus = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'appHash': new_app_hash.lower(),
            'nextValidatorsHash': sha256_hex(f"VALIDATORS:{client['chainId']}:{height_key}"),
            'lightClientSigners': validator_signatures
        }

        updated_client = dict(client)
        updated_client['latestHeight'] = new_height
        updated_client['consensusStates'] = dict(client.get('consensusStates', {}))
        updated_client['consensusStates'][height_key] = updated_consensus
        return updated_client

    @classmethod
    def relay_packet(
        cls,
        packet: Dict[str, Any],
        proof: Dict[str, Any],
        source_client_on_dest: Dict[str, Any],
        proof_height: Dict[str, int],
        relayer_key_pair: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Relays an IBC packet by verifying Merkle inclusion proof against light client."""
        commitment = cls.compute_packet_commitment(packet)
        height_key = f"{proof_height['revisionNumber']}-{proof_height['revisionHeight']}"
        consensus = source_client_on_dest.get('consensusStates', {}).get(height_key)

        if not consensus:
            raise ValueError(f"Consensus state not found on light client for height {height_key}")

        now_epoch = int(time.time())
        if packet.get('timeoutTimestamp', 0) > 0 and now_epoch >= packet['timeoutTimestamp']:
            return {
                'status': 'TIMEOUT',
                'packetSequence': packet['sequence'],
                'sourceChainId': source_client_on_dest['chainId'],
                'destinationChainId': 'destination-mesh',
                'relayerDid': relayer_key_pair.get('did') if relayer_key_pair else 'did:docutrust:relayer:mesh-node',
                'proofAppHash': consensus['appHash'],
                'relayedAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            }

        is_proof_valid = cls.verify_merkle_proof(proof, consensus['appHash'])
        if not is_proof_valid:
            raise ValueError(f"Invalid Merkle state proof: proof does not match light-client root AppHash {consensus['appHash']}")

        ack_payload = {
            'result': 'AQ==',
            'packetHash': commitment['packetHash'],
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }
        ack_hex = sha256_hex(f"IBC_ACK:{canonicalize_json(ack_payload)}")

        return {
            'status': 'RELAYED',
            'packetSequence': packet['sequence'],
            'sourceChainId': source_client_on_dest['chainId'],
            'destinationChainId': 'destination-mesh',
            'relayerDid': relayer_key_pair.get('did') if relayer_key_pair else 'did:docutrust:relayer:mesh-node',
            'acknowledgementHex': ack_hex,
            'proofAppHash': consensus['appHash'],
            'relayedAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }
