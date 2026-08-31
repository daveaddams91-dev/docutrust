from __future__ import annotations
import hashlib
import json
import time
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sign_message, verify_signature

class CrossChainBridgeEngine:
    """Multi-Chain Verifiable Attestation Bridge & Relayer Routing Engine."""

    SUPPORTED_CHAINS = {
        1: 'Ethereum Mainnet',
        10: 'Optimism Mainnet',
        137: 'Polygon Mainnet',
        8453: 'Base Mainnet',
        42161: 'Arbitrum One'
    }

    @staticmethod
    def create_message(
        source_chain_id: int,
        destination_chain_id: int,
        sequence_nonce: int,
        state_root: str,
        payload_hash: str,
        sender_address: str = "0x0000000000000000000000000000000000000001",
        recipient_address: str = "0x0000000000000000000000000000000000000002"
    ) -> Dict[str, Any]:
        normalized_root = '0x' + state_root.replace('0x', '').lower()
        normalized_payload = '0x' + payload_hash.replace('0x', '').lower()

        message_fields = {
            'sourceChainId': source_chain_id,
            'destinationChainId': destination_chain_id,
            'sequenceNonce': sequence_nonce,
            'stateRoot': normalized_root,
            'payloadHash': normalized_payload,
            'senderAddress': sender_address.lower(),
            'recipientAddress': recipient_address.lower()
        }

        canonical_bytes = canonicalize_json(message_fields).encode('utf-8')
        message_id = '0x' + hashlib.sha256(canonical_bytes).hexdigest()

        return {
            'type': 'DocuTrustCrossChainBridgeMessage2026',
            'messageId': message_id,
            **message_fields,
            'timestamp': int(time.time())
        }

    @staticmethod
    def sign_message(message: Dict[str, Any], relayer_key_pair: Dict[str, Any]) -> Dict[str, Any]:
        canonical_str = canonicalize_json(message)
        sig_hex = sign_message(canonical_str, relayer_key_pair['privateKeyHex'])

        return {
            'relayerDid': relayer_key_pair.get('did', ''),
            'relayerPublicKey': relayer_key_pair.get('publicKeyHex', ''),
            'signatureHex': sig_hex,
            'timestamp': int(time.time())
        }

    @staticmethod
    def assemble_attestation(
        message: Dict[str, Any],
        signatures: List[Dict[str, Any]],
        quorum_threshold: int = 1
    ) -> Dict[str, Any]:
        unique_sigs: Dict[str, Dict[str, Any]] = {}
        for sig in signatures:
            pk = sig.get('relayerPublicKey') or sig.get('relayerDid') or ''
            if pk:
                unique_sigs[pk] = sig

        sigs_list = list(unique_sigs.values())
        return {
            'type': 'DocuTrustCrossChainAttestation2026',
            'attestationId': '0x' + hashlib.sha256(canonicalize_json({'message': message, 'signatures': sigs_list}).encode('utf-8')).hexdigest(),
            'message': message,
            'signatures': sigs_list,
            'quorumThreshold': quorum_threshold,
            'assembledAt': int(time.time())
        }

    @staticmethod
    def verify_attestation(
        attestation: Dict[str, Any],
        authorized_relayers: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        errors = []
        message = attestation.get('message')
        signatures = attestation.get('signatures', [])
        required_threshold = attestation.get('quorumThreshold', 1)

        if not message:
            return {'valid': False, 'verifiedSignatures': 0, 'requiredThreshold': required_threshold, 'errors': ['Missing bridge message payload.']}

        canonical_msg = canonicalize_json(message)
        valid_signatures_count = 0
        seen_signers = set()

        for sig in signatures:
            pk = sig.get('relayerPublicKey')
            sig_val = sig.get('signatureHex')

            if not pk or not sig_val:
                continue

            clean_pk = pk.replace('0x', '').lower()
            if clean_pk in seen_signers:
                continue

            if authorized_relayers is not None:
                authorized_clean = [r.replace('0x', '').lower() for r in authorized_relayers]
                if clean_pk not in authorized_clean:
                    errors.append(f"Signer {pk} is not an authorized relayer.")
                    continue

            is_valid = verify_signature(canonical_msg, sig_val, pk)
            if is_valid:
                valid_signatures_count += 1
                seen_signers.add(clean_pk)
            else:
                errors.append(f"Cryptographic signature check failed for relayer {pk}.")

        if valid_signatures_count < required_threshold:
            errors.append(f"Quorum not reached: verified {valid_signatures_count}/{required_threshold} signatures.")

        return {
            'valid': len(errors) == 0 and valid_signatures_count >= required_threshold,
            'verifiedSignatures': valid_signatures_count,
            'requiredThreshold': required_threshold,
            'errors': errors
        }
