from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class GenerateMixin:

    def generate_selective_disclosure(
        self,
        credential: Dict[str, Any],
        disclosed_keys: List[str]
    ) -> Dict[str, Any]:
        url = f"{self.api_url}/credentials/selective-disclosure"
        payload = {
            "credential": credential,
            "revealKeys": disclosed_keys
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def generate_secp256k1_keys(self, chain_id: int = 1) -> Dict[str, str]:
        """Generates Ethereum secp256k1 keypair and did:pkh DID."""
        from .eip712 import generate_secp256k1_key_pair
        return generate_secp256k1_key_pair(chain_id)

    def generate_solidity_verifier(
        self,
        contract_name: str = "DocuTrustVerifier",
        solidity_version: str = "^0.8.20",
        owner_address: Optional[str] = None
    ) -> str:
        """Generates production-ready DocuTrustVerifier.sol Solidity source code."""
        from .solidity import SolidityEngine
        return SolidityEngine.generate_verifier_contract(contract_name, solidity_version, owner_address)

    def generate_paillier_key_pair(self, bit_length: int = 512) -> Dict[str, Any]:
        """Generates a Paillier KeyPair for confidential arithmetic."""
        from .confidential import PaillierCryptosystem
        return PaillierCryptosystem.generate_key_pair(bit_length)

    def generate_dual_kem_keys(self) -> Dict[str, Any]:
        """Generates a Dual-KEM Hybrid KeyPair (X25519 + NIST ML-KEM-768)."""
        from .quantum_armor import DualHybridKEMEngine
        return DualHybridKEMEngine.generate_dual_key_pair()

    def generate_solidity_registry(
        self,
        contract_name: str = "DocuTrustRegistry",
        solidity_version: str = "^0.8.20"
    ) -> str:
        """Generates a multi-issuer Sovereign Trust Registry smart contract for on-chain accreditation."""
        from .solidity import SolidityEngine
        return SolidityEngine.generate_registry_contract(
            contract_name=contract_name,
            solidity_version=solidity_version
        )

    def generate_smt_proof(self, key: str, entries: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Generates an SMT inclusion/non-membership proof via REST API."""
        return self._request("/smt/prove", method="POST", json_data={"key": key, "entries": entries or {}})

    def generate_solidity_smt_verifier(
        self,
        contract_name: str = "DocuTrustSMTVerifier",
        solidity_version: str = "^0.8.20"
    ) -> str:
        """Generates production-ready Solidity contract code for verifying 256-bit SMT proofs."""
        from .solidity import SolidityEngine
        return SolidityEngine.generate_smt_verifier_contract(
            contract_name=contract_name,
            solidity_version=solidity_version
        )

    def generate_slhdsa_key_pair(self) -> Dict[str, Any]:
        """Generates a NIST FIPS 205 SLH-DSA keypair."""
        from .slhdsa import SLHDSAEngine
        return SLHDSAEngine.generate_key_pair()

    def generate_webauthn_key_pair(self, rp_id: str = "localhost") -> Dict[str, Any]:
        """Generates a WebAuthn P-256 passkey keypair."""
        from .webauthn import WebAuthnAttestationEngine
        return WebAuthnAttestationEngine.generate_key_pair(rp_id)

    def generate_solidity_bridge_relayer(self, contract_name: str = "DocuTrustBridgeRelayer", solidity_version: str = "^0.8.20") -> str:
        """Generates production-ready Solidity contract for Cross-Chain Bridge Relayer."""
        from .solidity import SolidityEngine
        return SolidityEngine.generate_bridge_relayer_contract(contract_name, solidity_version)

    def generate_solidity_groth16_verifier(self, contract_name: str = "DocuTrustGroth16Verifier", solidity_version: str = "^0.8.20") -> str:
        """Generates production-ready Solidity contract for Groth16 SNARK verification."""
        from .solidity import SolidityEngine
        return SolidityEngine.generate_groth16_verifier_contract(contract_name, solidity_version)

    def generate_state_delta(
        self,
        base_state: Dict[str, Any],
        target_state: Dict[str, Any],
        relayer_key_pair: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generates a compact O(Δ) cross-ledger delta proof between state replicas."""
        from .state_sync import StateSyncEngine
        return StateSyncEngine.generate_delta_proof(base_state, target_state, relayer_key_pair, options)

    def generate_universal_solidity_verifier(
        self,
        contract_name: str = "DocuTrustUniversalVerifier",
        solidity_version: str = "^0.8.20"
    ) -> str:
        """Generates master Solidity contract verifying Merkle, SMT-256, Cross-Chain Bridge, and Groth16."""
        from .solidity import SolidityEngine
        return SolidityEngine.generate_universal_verifier_contract(contract_name, solidity_version)

    def generate_revocation_lattice_proof(
        self,
        state: Dict[str, Any],
        credential_id: str,
        issuer_key_pair: Dict[str, Any],
        target_epoch: Optional[int] = None
    ) -> Dict[str, Any]:
        """Generates an O(1) non-revocation / revocation witness proof across lattice slices."""
        from .revocation_lattice import RevocationLatticeEngine
        return RevocationLatticeEngine.generate_lattice_proof(state, credential_id, issuer_key_pair, target_epoch)

    def generate_aibom_layer_proof(
        self,
        manifest: Dict[str, Any],
        layer_index: int
    ) -> Dict[str, Any]:
        """Generates a Merkle inclusion proof for a single neural network layer."""
        from .ai_bom import AIBOMRegistryEngine
        return AIBOMRegistryEngine.generate_layer_proof(manifest, layer_index)

    def generate_falcon_keypair(
        self,
        mode: str = 'Falcon-512'
    ) -> Dict[str, Any]:
        """Generates a Falcon-512 / Falcon-1024 dual-lattice key pair."""
        from .pqc_falcon import PQCFalconEngine
        return PQCFalconEngine.generate_key_pair(mode)
