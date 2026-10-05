from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class VerifyMixin:

    def verify_credential(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.api_url}/credentials/verify"
        res = self.session.post(url, json={"credential": credential})
        res.raise_for_status()
        return res.json()

    def verify_pdf(self, pdf_bytes_or_base64: Union[bytes, str]) -> Dict[str, Any]:
        """Extracts and verifies embedded W3C Verifiable Credential from a PDF."""
        url = f"{self.api_url}/credentials/verify-pdf"
        if isinstance(pdf_bytes_or_base64, bytes):
            b64 = base64.b64encode(pdf_bytes_or_base64).decode('utf-8')
        else:
            b64 = pdf_bytes_or_base64
        res = self.session.post(url, json={"pdfBase64": b64})
        res.raise_for_status()
        return res.json()

    def verify_zk_predicate(self, proof: Dict[str, Any], expected_commitment: Optional[str] = None) -> Dict[str, Any]:
        """Verifies a Zero-Knowledge Predicate Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/verify"
        res = self.session.post(url, json={"proof": proof, "expectedCommitment": expected_commitment})
        res.raise_for_status()
        return res.json()

    def verify_zk_membership(
        self,
        proof: Dict[str, Any],
        allowed_set: List[str],
        expected_commitment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a Zero-Knowledge Set Membership Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/verify"
        res = self.session.post(url, json={
            "proof": proof,
            "allowedSet": allowed_set,
            "expectedCommitment": expected_commitment
        })
        res.raise_for_status()
        return res.json()

    def verify_zk_age(self, proof: Dict[str, Any], expected_commitment: Optional[str] = None) -> Dict[str, Any]:
        """Verifies a Zero-Knowledge Age Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/verify-age"
        res = self.session.post(url, json={"proof": proof, "expectedCommitment": expected_commitment})
        res.raise_for_status()
        return res.json()

    def verify_zk_date(self, proof: Dict[str, Any], expected_commitment: Optional[str] = None) -> Dict[str, Any]:
        """Verifies a Zero-Knowledge Date Range Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/verify-date"
        res = self.session.post(url, json={"proof": proof, "expectedCommitment": expected_commitment})
        res.raise_for_status()
        return res.json()

    def verify_pop_presentation(self, presentation: Dict[str, Any], expected_audience: Optional[str] = None) -> Dict[str, Any]:
        """Verifies a Proof-of-Possession presentation."""
        url = f"{self.api_url}/credentials/pop/verify"
        payload = {"presentation": presentation}
        if expected_audience:
            payload["expectedAudience"] = expected_audience
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def verify_sd_jwt(self, presentation: str) -> Dict[str, Any]:
        """Verifies an IETF SD-JWT presentation."""
        url = f"{self.api_url}/credentials/sd-jwt/verify"
        res = self.session.post(url, json={"presentation": presentation})
        res.raise_for_status()
        return res.json()

    def verify_trust_issuer(self, issuer_did: str, schema_type: str) -> Dict[str, Any]:
        """Verifies issuer authorization against Decentralized Trust Registry."""
        url = f"{self.api_url}/trust/verify-issuer"
        res = self.session.post(url, json={"issuerDid": issuer_did, "schemaType": schema_type})
        res.raise_for_status()
        return res.json()

    def verify_timestamp_token(self, token: Dict[str, Any], expected_data: Optional[str] = None) -> Dict[str, Any]:
        """Verifies RFC 3161 timestamp token integrity."""
        url = f"{self.api_url}/oracle/verify-timestamp"
        res = self.session.post(url, json={"token": token, "expectedData": expected_data})
        res.raise_for_status()
        return res.json()

    def verify_vc_eip712(
        self,
        credential: Dict[str, Any],
        expected_signer: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies EIP-712 structured signature on W3C Verifiable Credential."""
        from .eip712 import verify_vc_eip712
        return verify_vc_eip712(credential, expected_signer)

    def verify_set_non_membership(
        self,
        proof: Dict[str, Any],
        restricted_set: List[str],
        expected_commitment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies ZK Set Non-Membership proof."""
        from .zk_predicates import verify_set_non_membership_proof
        return verify_set_non_membership_proof(proof, restricted_set, expected_commitment)

    def verify_composite_predicate(
        self,
        composite_proof: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Verifies multi-predicate composite ZK proof."""
        from .zk_predicates import verify_composite_predicate
        return verify_composite_predicate(composite_proof, context)

    def verify_accumulator_batch_witness(
        self,
        witness: Dict[str, Any],
        current_accumulator_hex: str,
        modulus_hex: Optional[str] = None
    ) -> bool:
        """Verifies a constant-size batch membership witness."""
        from .accumulator import CryptographicAccumulator
        if modulus_hex:
            return CryptographicAccumulator.verify_batch_witness(witness, current_accumulator_hex, modulus_hex)
        return CryptographicAccumulator.verify_batch_witness(witness, current_accumulator_hex)

    def verify_set_intersection(
        self,
        proof: Dict[str, Any],
        target_set: List[str],
        expected_commitment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies ZK Set Intersection Proof."""
        from .zk_predicates import verify_set_intersection_proof
        return verify_set_intersection_proof(proof, target_set, expected_commitment)

    def verify_zk_predicate_graph(
        self,
        graph_proof: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Verifies a recursive Zero-Knowledge Predicate Graph Proof."""
        from .zk_predicates import verify_predicate_graph
        return verify_predicate_graph(graph_proof, context)

    def verify_multisig_credential(
        self,
        credential: Dict[str, Any],
        policy: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Cryptographically verifies an M-of-N MultiSig Verifiable Credential against policy."""
        from .multisig import MultiSigEngine
        return MultiSigEngine.verify_multisig_credential(credential, policy)

    def verify_anoncreds_presentation(
        self,
        presentation: Dict[str, Any],
        verifier_nonce: Optional[str] = None,
        issuer_did: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifier validates an AnonCreds Zero-Knowledge Presentation."""
        from .anoncreds import AnonCredsEngine
        return AnonCredsEngine.verify_presentation(presentation, verifier_nonce, issuer_did)

    def verify_dkg_signature(
        self,
        signature: Dict[str, Any],
        message: Union[str, bytes],
        group_public_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies an aggregated FROST threshold signature."""
        from .dkg import DKGEngine
        return DKGEngine.verify_aggregated_signature(signature, message, group_public_key_hex)

    def verify_audit_bundle(
        self,
        bundle: Dict[str, Any],
        expected_signer_public_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a cryptographic audit bundle (.dtbundle)."""
        from .bundle import AuditBundleEngine
        return AuditBundleEngine.verify_audit_bundle(bundle, expected_signer_public_key_hex)

    def verify_data_integrity_credential(
        self,
        credential: Dict[str, Any],
        expected_public_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a W3C DataIntegrityProof credential."""
        from .dataintegrity import DataIntegrityEngine
        return DataIntegrityEngine.verify(credential, expected_public_key_hex)

    def verify_confidential_threshold(self, proof: Dict[str, Any]) -> bool:
        """Verifies a confidential threshold proof."""
        from .confidential import ConfidentialClaimsEngine
        return ConfidentialClaimsEngine.verify_threshold_proof(proof)

    def verify_jsonld(
        self,
        signed_doc: Dict[str, Any],
        expected_public_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a Linked Data Signed JSON-LD document."""
        from .jsonld import JsonLdCanonicalizationEngine
        return JsonLdCanonicalizationEngine.verify_jsonld(signed_doc, expected_public_key_hex)

    def verify_trust_chain(
        self,
        chain: List[Dict[str, Any]],
        credential: Dict[str, Any],
        accredited_root_dids: List[str]
    ) -> Dict[str, Any]:
        """Recursively verifies an end-to-end delegation trust chain."""
        from .trustchain import TrustChainEngine
        return TrustChainEngine.verify_trust_chain(
            chain=chain,
            credential=credential,
            accredited_root_dids=accredited_root_dids
        )

    def verify_badge_svg(self, svg_content: str) -> Dict[str, Any]:
        """Verifies the integrity and authenticity of an SVG badge."""
        from .badge import BadgeEngine
        return BadgeEngine.verify_badge_svg(svg_content)

    def verify_policy_receipt(
        self,
        receipt: Dict[str, Any],
        expected_evaluator_public_key_hex: Optional[str] = None
    ) -> bool:
        """Cryptographically verifies a DocuTrustPolicyReceipt2026."""
        from .policy import PolicyEngine
        return PolicyEngine.verify_receipt(receipt, expected_evaluator_public_key_hex=expected_evaluator_public_key_hex)

    def verify_ring_signature(
        self,
        message: Union[str, bytes, Dict[str, Any]],
        signature: Dict[str, Any],
        used_key_images: Optional[Union[Set[str], List[str]]] = None
    ) -> Dict[str, Any]:
        """Verifies a 1-of-N Linkable Ring Signature and checks for double-voting/double-action."""
        from .ringsig import RingSignatureEngine
        return RingSignatureEngine.verify(
            message=message,
            signature=signature,
            used_key_images=used_key_images
        )

    def verify_smt_proof(self, proof: Dict[str, Any], root: Optional[str] = None) -> Dict[str, Any]:
        """Verifies an SMT proof via REST API or local logic."""
        return self._request("/smt/verify", method="POST", json_data={"proof": proof, "root": root})

    def verify_slhdsa(self, message: Any, signature: Any, public_key: Any) -> bool:
        """Verifies an SLH-DSA post-quantum signature."""
        from .slhdsa import SLHDSAEngine
        return SLHDSAEngine.verify(message, signature, public_key)

    def verify_webauthn_assertion(self, assertion: Dict[str, Any], challenge: str, public_key: Any, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Verifies a WebAuthn passkey assertion."""
        from .webauthn import WebAuthnAttestationEngine
        return WebAuthnAttestationEngine.verify_assertion(assertion, challenge, public_key, options)

    def verify_crosschain_attestation(self, attestation: Dict[str, Any], authorized_relayers: Optional[List[str]] = None) -> Dict[str, Any]:
        """Verifies a multi-relayer cross-chain attestation against quorum threshold."""
        from .crosschain import CrossChainBridgeEngine
        return CrossChainBridgeEngine.verify_attestation(attestation, authorized_relayers)

    def verify_groth16_proof(self, proof: Dict[str, Any], vk: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies a BN254 Groth16 ZK-SNARK proof against a verification key."""
        from .groth16 import Groth16Engine
        return Groth16Engine.verify_proof(proof, vk)

    def verify_trust_score_receipt(self, receipt: Dict[str, Any], evaluator_public_key: str) -> Dict[str, Any]:
        """Cryptographically verifies a signed DocuTrustRiskReceipt2026."""
        from .trust_score import TrustScoreEngine
        return TrustScoreEngine.verify_risk_receipt(receipt, evaluator_public_key)

    def verify_compute_receipt(
        self,
        receipt: Dict[str, Any],
        prover_public_key: str,
        inputs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Verifies an off-chain compute execution receipt."""
        from .verifiable_compute import VerifiableComputeEngine
        return VerifiableComputeEngine.verify_compute_receipt(receipt, prover_public_key, inputs)

    def verify_vanish_token(
        self,
        token: Dict[str, Any],
        ephemeral_key: str,
        issuer_public_key: str,
        current_epoch: Optional[int] = None
    ) -> Dict[str, Any]:
        """Verifies and decrypts an active ephemeral vanish token."""
        from .vanish_cred import VanishCredEngine
        return VanishCredEngine.verify_and_decrypt(token, ephemeral_key, issuer_public_key, current_epoch)

    def verify_state_delta(
        self,
        base_state: Dict[str, Any],
        delta_proof: Dict[str, Any],
        relayer_public_key: str
    ) -> Dict[str, Any]:
        """Reconciles and verifies a cross-ledger delta proof against an initial base state."""
        from .state_sync import StateSyncEngine
        return StateSyncEngine.verify_and_reconcile(base_state, delta_proof, relayer_public_key)

    def verify_recursive_zk_proof(
        self,
        proof: Dict[str, Any],
        aggregator_public_key_hex: str
    ) -> Dict[str, Any]:
        """Verifies a recursive ZK aggregated proof."""
        from .zk_recursive import ZKRecursiveEngine
        return ZKRecursiveEngine.verify_recursive_proof(proof, aggregator_public_key_hex)

    def verify_revocation_lattice_proof(
        self,
        proof: Dict[str, Any],
        issuer_public_key_hex: str,
        expected_lattice_root: Optional[str] = None
    ) -> Dict[str, Any]:
        """Cryptographically verifies a lattice revocation proof."""
        from .revocation_lattice import RevocationLatticeEngine
        return RevocationLatticeEngine.verify_lattice_proof(proof, issuer_public_key_hex, expected_lattice_root)

    def verify_agent_attestation(
        self,
        attestation: Dict[str, Any],
        agent_public_key_hex: str,
        expected_output: Optional[Union[Dict[str, Any], str]] = None
    ) -> Dict[str, Any]:
        """Verifies an AI agent action attestation and guardrail compliance."""
        from .agent_provenance import AgentProvenanceEngine
        return AgentProvenanceEngine.verify_attestation(attestation, agent_public_key_hex, expected_output)

    def verify_vrf(
        self,
        evaluation: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Cryptographically verifies a VRF evaluation and deterministic output."""
        from .vrf_oracle import VRFOracleEngine
        return VRFOracleEngine.verify(evaluation)

    def verify_vrf_beacon(
        self,
        beacon: Dict[str, Any],
        expected_beacon_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a multi-oracle threshold randomness beacon."""
        from .vrf_oracle import VRFOracleEngine
        return VRFOracleEngine.verify_beacon(beacon, expected_beacon_hash)

    def verify_oracle_feed(
        self,
        feed: Dict[str, Any],
        trusted_oracle_public_keys: Optional[Union[List[str], Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """Verifies a multi-oracle threshold consensus data feed."""
        from .vrf_oracle import VRFOracleEngine
        return VRFOracleEngine.verify_oracle_feed(feed, trusted_oracle_public_keys)

    def verify_zk_dsl(
        self,
        proof: Dict[str, Any],
        expression: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a Zero-Knowledge predicate DSL proof."""
        from .zk_dsl import ZKDSLEngine
        return ZKDSLEngine.verify_proof(proof, expression)

    def verify_aibom_receipt(
        self,
        receipt: Dict[str, Any],
        certifier_public_key: str,
        expected_weights_root: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies an AI Bill of Materials (AI-BOM) receipt and weights root."""
        from .ai_bom import AIBOMRegistryEngine
        return AIBOMRegistryEngine.verify_aibom_receipt(receipt, certifier_public_key, expected_weights_root)

    def verify_aibom_layer_proof(
        self,
        proof: Dict[str, Any],
        expected_root: str
    ) -> Dict[str, Any]:
        """Verifies a single layer Merkle inclusion proof against a weights root."""
        from .ai_bom import AIBOMRegistryEngine
        return AIBOMRegistryEngine.verify_layer_proof(proof, expected_root)

    def verify_falcon(
        self,
        message: Any,
        signature_hex: str,
        public_key_hex: str
    ) -> Dict[str, Any]:
        """Verifies a post-quantum Falcon lattice signature."""
        from .pqc_falcon import PQCFalconEngine
        return PQCFalconEngine.verify(message, signature_hex, public_key_hex)
