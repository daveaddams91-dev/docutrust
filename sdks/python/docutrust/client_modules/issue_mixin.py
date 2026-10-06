from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class IssueMixin:

    def issue_credential(
        self,
        credential_subject: Dict[str, Any],
        credential_type: str = "AchievementCredential",
        valid_until: Optional[str] = None,
        enable_selective_disclosure: bool = False,
        enable_pqc: bool = False
    ) -> Dict[str, Any]:
        url = f"{self.api_url}/credentials/issue"
        payload = {
            "credentialSubject": credential_subject,
            "type": ["VerifiableCredential", credential_type],
            "validUntil": valid_until,
            "enableSelectiveDisclosure": enable_selective_disclosure,
            "enablePQC": enable_pqc
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def issue_sd_jwt(self, claims: Dict[str, Any], subject_did: Optional[str] = None) -> Dict[str, Any]:
        """Issues an IETF SD-JWT package with salted disclosures."""
        url = f"{self.api_url}/credentials/sd-jwt/issue"
        payload = {"claims": claims}
        if subject_did:
            payload["subjectDid"] = subject_did
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def issue_timestamp_token(self, data: str, nonce: Optional[str] = None) -> Dict[str, Any]:
        """Issues RFC 3161 cryptographic timestamp token from TSA Oracle."""
        url = f"{self.api_url}/oracle/timestamp"
        res = self.session.post(url, json={"data": data, "nonce": nonce})
        res.raise_for_status()
        return res.json()

    def issue_anoncreds_blind_credential(
        self,
        request: Dict[str, Any],
        claims: Dict[str, Any],
        issuer_ed_keys: Optional[Dict[str, Any]] = None,
        issuer_keys: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Issuer issues a blinded BBS+ credential bound to holder master secret."""
        from .anoncreds import AnonCredsEngine
        return AnonCredsEngine.issue_blind_credential(request, claims, issuer_keys, issuer_ed_keys)

    def issue_data_integrity_credential(
        self,
        credential_subject: Dict[str, Any],
        issuer: Union[str, Dict[str, Any]],
        key_pair: Dict[str, Any],
        cryptosuite: str = "eddsa-jcs-2022",
        type_list: Optional[List[str]] = None,
        valid_until: Optional[str] = None,
        cred_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Issues a W3C Verifiable Credential secured with DataIntegrityProof."""
        from .dataintegrity import DataIntegrityEngine
        return DataIntegrityEngine.issue(
            credential_subject=credential_subject,
            issuer=issuer,
            key_pair=key_pair,
            cryptosuite=cryptosuite,
            type_list=type_list,
            valid_until=valid_until,
            cred_id=cred_id
        )

    def issue_vanish_token(
        self,
        claims: Dict[str, Any],
        issuer_key_pair: Dict[str, Any],
        subject_did: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Issues an ephemeral forward-secret token with time-decay commitment."""
        from .vanish_cred import VanishCredEngine
        return VanishCredEngine.issue_token(claims, issuer_key_pair, subject_did, options)

    def issue_agent_attestation(
        self,
        payload: Dict[str, Any],
        agent_key_pair: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Issues an autonomous AI agent action attestation with model card fingerprinting and trace commitment."""
        from .agent_provenance import AgentProvenanceEngine
        return AgentProvenanceEngine.issue_attestation(payload, agent_key_pair)
