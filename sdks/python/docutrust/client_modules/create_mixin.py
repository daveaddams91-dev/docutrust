from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class CreateMixin:

    def create_pop_challenge(self, audience: str = "did:web:docutrust.org") -> Dict[str, Any]:
        """Creates an ephemeral Proof-of-Possession challenge."""
        url = f"{self.api_url}/credentials/pop/challenge"
        res = self.session.post(url, json={"audience": audience})
        res.raise_for_status()
        return res.json()

    def create_bloom_filter(self, revoked_ids: List[str], size_bits: int = 8192, hash_count: int = 5) -> Dict[str, Any]:
        """Creates and signs a revocation Bloom filter."""
        url = f"{self.api_url}/revocation/bloom/create"
        res = self.session.post(url, json={"revokedIds": revoked_ids, "sizeBits": size_bits, "hashCount": hash_count})
        res.raise_for_status()
        return res.json()

    def create_accumulator(
        self,
        accumulator_id: str,
        modulus_hex: Optional[str] = None,
        generator_hex: Optional[str] = None
    ):
        """Creates a dynamic cryptographic accumulator instance."""
        from .accumulator import CryptographicAccumulator
        kwargs = {}
        if modulus_hex:
            kwargs["modulus_hex"] = modulus_hex
        if generator_hex:
            kwargs["generator_hex"] = generator_hex
        return CryptographicAccumulator(accumulator_id, **kwargs)

    def create_accumulator_batch_witness(
        self,
        accumulator: Any,
        elements: List[str]
    ) -> Dict[str, Any]:
        """Generates a constant-size batch membership witness for a subset of elements."""
        return accumulator.create_batch_witness(elements)

    def create_status_list_2024(
        self,
        length: int = 100000,
        status_size: int = 1,
        status_purpose: str = "revocation"
    ):
        """Creates a W3C BitstringStatusList2024 instance."""
        from .status_list import BitstringStatusList2024
        return BitstringStatusList2024(length, status_size, status_purpose)

    def create_presentation_definition(
        self,
        definition_id: str,
        input_descriptors: List[Dict[str, Any]],
        name: Optional[str] = None,
        purpose: Optional[str] = None
    ) -> Dict[str, Any]:
        """Creates a DIF Presentation Exchange 2.0 Presentation Definition."""
        from .presentation_exchange import PresentationExchangeEngine
        opts = {}
        if name:
            opts["name"] = name
        if purpose:
            opts["purpose"] = purpose
        return PresentationExchangeEngine.create_definition(definition_id, input_descriptors, opts)

    def create_presentation_submission(
        self,
        submission_id: str,
        definition_id: str,
        descriptor_map: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Creates a DIF Presentation Exchange 2.0 Presentation Submission."""
        from .presentation_exchange import PresentationExchangeEngine
        return PresentationExchangeEngine.create_submission(submission_id, definition_id, descriptor_map)

    def create_multisig_draft(
        self,
        credential: Dict[str, Any],
        policy: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Creates an unsigned Multi-Signature (M-of-N) Credential draft and canonical hash."""
        from .multisig import MultiSigEngine
        return MultiSigEngine.create_multisig_draft(credential, policy)

    def create_anoncreds_blind_request(
        self,
        schema_id: str,
        issuer_did: str,
        master_secret: Optional[str] = None
    ) -> Dict[str, Any]:
        """Holder creates a blind credential request binding a holder master secret."""
        from .anoncreds import AnonCredsEngine
        secret = master_secret or AnonCredsEngine.generate_holder_master_secret()["masterSecret"]
        return AnonCredsEngine.create_blind_request(secret, schema_id, issuer_did)

    def create_anoncreds_presentation(
        self,
        credential: Dict[str, Any],
        master_secret: str,
        reveal_keys: List[str],
        verifier_nonce: str,
        predicate_proofs: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Holder generates an unlinkable Zero-Knowledge Presentation for a Verifier."""
        from .anoncreds import AnonCredsEngine
        return AnonCredsEngine.create_presentation(credential, master_secret, reveal_keys, verifier_nonce, predicate_proofs)

    def create_audit_bundle(
        self,
        organization: str = "DocuTrust Enterprise Sovereign Trust",
        signer_keypair: Optional[Dict[str, Any]] = None,
        compliance_standards: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Creates a signed cryptographic audit bundle (.dtbundle)."""
        from .bundle import AuditBundleEngine
        return AuditBundleEngine.create_audit_bundle(
            organization=organization,
            signer_keypair=signer_keypair,
            compliance_standards=compliance_standards
        )

    def create_delegation_token(
        self,
        delegator_key_pair: Dict[str, Any],
        delegate_did: str,
        allowed_credential_types: Optional[List[str]] = None,
        max_depth: int = 2,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None
    ) -> Dict[str, Any]:
        """Issues a signed delegation token to a subordinate authority."""
        from .trustchain import TrustChainEngine
        return TrustChainEngine.create_delegation_token(
            delegator_key_pair=delegator_key_pair,
            delegate_did=delegate_did,
            allowed_credential_types=allowed_credential_types,
            max_depth=max_depth,
            valid_from=valid_from,
            valid_until=valid_until
        )

    def create_did_peer_0(self, public_key_hex: str) -> str:
        """Creates a W3C did:peer:0 inception key URI."""
        from .did import create_did_peer_0
        return create_did_peer_0(public_key_hex)

    def create_did_peer_2(
        self,
        verification_key_hex: str,
        encryption_key_hex: Optional[str] = None,
        service_endpoint: Optional[str] = None
    ) -> str:
        """Creates a W3C did:peer:2 multi-key and service endpoint URI."""
        from .did import create_did_peer_2
        return create_did_peer_2(
            verification_key_hex=verification_key_hex,
            encryption_key_hex=encryption_key_hex,
            service_endpoint=service_endpoint
        )

    def create_webauthn_assertion(self, challenge: str, key_pair: Dict[str, Any], options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Creates a signed hardware passkey assertion."""
        from .webauthn import WebAuthnAttestationEngine
        return WebAuthnAttestationEngine.create_assertion(challenge, key_pair, options)

    def create_crosschain_message(
        self,
        source_chain_id: int,
        destination_chain_id: int,
        sequence_nonce: int,
        state_root: str,
        payload_hash: str,
        sender_address: str = "0x0000000000000000000000000000000000000001",
        recipient_address: str = "0x0000000000000000000000000000000000000002"
    ) -> Dict[str, Any]:
        """Constructs a standard cross-chain attestation bridge message."""
        from .crosschain import CrossChainBridgeEngine
        return CrossChainBridgeEngine.create_message(
            source_chain_id, destination_chain_id, sequence_nonce, state_root, payload_hash, sender_address, recipient_address
        )

    def create_vrf_beacon(
        self,
        epoch: int,
        round_num: int,
        previous_beacon_hash: str,
        oracle_key_pairs: List[Dict[str, Any]],
        threshold_required: Optional[int] = None
    ) -> Dict[str, Any]:
        """Creates a multi-oracle threshold randomness beacon round."""
        from .vrf_oracle import VRFOracleEngine
        return VRFOracleEngine.create_beacon(epoch, round_num, previous_beacon_hash, oracle_key_pairs, threshold_required)

    def create_oracle_feed(
        self,
        feed_id: str,
        round_num: int,
        data_payload: Any,
        oracle_key_pairs: List[Dict[str, Any]],
        threshold_required: Optional[int] = None
    ) -> Dict[str, Any]:
        """Issues a signed multi-oracle threshold data feed."""
        from .vrf_oracle import VRFOracleEngine
        return VRFOracleEngine.issue_oracle_feed(feed_id, round_num, data_payload, oracle_key_pairs, threshold_required)

    def create_aibom_receipt(
        self,
        manifest: Dict[str, Any],
        certifier_key_pair: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Computes a weights Merkle root and creates an AI-BOM cryptographic receipt."""
        from .ai_bom import AIBOMRegistryEngine
        return AIBOMRegistryEngine.create_aibom_receipt(manifest, certifier_key_pair)
