from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class TeeMixin:

    def tee_generate_quote(
        self,
        tee_platform: str,
        measurements: Dict[str, Any],
        report_data_payload: Union[str, Dict[str, Any]],
        hardware_key_pair: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generates a hardware-modeled TEE remote attestation quote."""
        from .tee_attestation import TEEAttestationEngine
        return TEEAttestationEngine.generate_attestation_quote(tee_platform, measurements, report_data_payload, hardware_key_pair)

    def tee_verify_quote(
        self,
        quote: Dict[str, Any],
        expected_report_data: Optional[Union[str, Dict[str, Any]]] = None,
        allowed_mr_enclaves: Optional[List[str]] = None,
        allowed_mr_signers: Optional[List[str]] = None,
        min_isv_svn: Optional[int] = None
    ) -> Dict[str, Any]:
        """Validates a TEE remote attestation quote."""
        from .tee_attestation import TEEAttestationEngine
        return TEEAttestationEngine.verify_attestation_quote(
            quote,
            expected_report_data_payload=expected_report_data,
            allowed_mr_enclaves=allowed_mr_enclaves,
            allowed_mr_signers=allowed_mr_signers,
            min_isv_svn=min_isv_svn
        )

    def tee_issue_credential(
        self,
        claims: Dict[str, Any],
        enclave_key_pair: Dict[str, Any],
        quote: Dict[str, Any],
        issuer_key_pair: Dict[str, Any],
        credential_id: Optional[str] = None,
        credential_type: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Issues a W3C Verifiable Credential cryptographically bound to a TEE quote."""
        from .tee_attestation import TEEAttestationEngine
        return TEEAttestationEngine.issue_tee_bound_credential(
            claims, enclave_key_pair, quote, issuer_key_pair, credential_id, credential_type
        )

    def tee_verify_credential(
        self,
        credential: Dict[str, Any],
        issuer_public_key_hex: Optional[str] = None,
        allowed_mr_enclaves: Optional[List[str]] = None,
        allowed_mr_signers: Optional[List[str]] = None,
        min_isv_svn: Optional[int] = None
    ) -> Dict[str, Any]:
        """Verifies a TEE-bound Verifiable Credential."""
        from .tee_attestation import TEEAttestationEngine
        return TEEAttestationEngine.verify_tee_bound_credential(
            credential, issuer_public_key_hex, allowed_mr_enclaves, allowed_mr_signers, min_isv_svn
        )
