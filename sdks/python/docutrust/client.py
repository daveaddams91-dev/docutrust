from __future__ import annotations
import requests
import base64
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex, MerkleTree

class DocuTrustClient:
    """Client for DocuTrust Sovereign Trust API v1.1."""
    def __init__(self, api_url: str = "https://api.docutrust.org/api/v1", api_key: Optional[str] = None):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"Authorization": f"Bearer {api_key}"})

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

    def batch_issue(
        self,
        records: List[Dict[str, Any]],
        credential_type: str = "UniversityDegreeCredential",
        anchor_to_ledger: bool = True
    ) -> Dict[str, Any]:
        url = f"{self.api_url}/credentials/issue-batch"
        payload = {
            "records": [{"credentialSubject": r} for r in records],
            "type": ["VerifiableCredential", credential_type],
            "anchorToLedger": anchor_to_ledger
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

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

    def encrypt_data(self, data: Any, passphrase: str) -> Dict[str, Any]:
        """Encrypts data with AES-256-GCM via API vault."""
        url = f"{self.api_url}/vault/encrypt"
        res = self.session.post(url, json={"data": data, "passphrase": passphrase})
        res.raise_for_status()
        return res.json()

    def decrypt_data(self, encrypted_payload: Dict[str, Any], passphrase: str) -> Dict[str, Any]:
        """Decrypts AES-256-GCM payload via API vault."""
        url = f"{self.api_url}/vault/decrypt"
        res = self.session.post(url, json={"encrypted": encrypted_payload, "passphrase": passphrase})
        res.raise_for_status()
        return res.json()

    def prove_zk_range(
        self,
        claim_key: str,
        actual_value: float,
        min_val: float,
        max_val: float,
        salt: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates a Zero-Knowledge Range Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/prove"
        payload = {
            "predicateType": "range",
            "claimKey": claim_key,
            "actualValue": actual_value,
            "salt": salt,
            "min": min_val,
            "max": max_val
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def verify_zk_predicate(self, proof: Dict[str, Any], expected_commitment: Optional[str] = None) -> Dict[str, Any]:
        """Verifies a Zero-Knowledge Predicate Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/verify"
        res = self.session.post(url, json={"proof": proof, "expectedCommitment": expected_commitment})
        res.raise_for_status()
        return res.json()

    def kem_generate_keys(self) -> Dict[str, Any]:
        """Generates Post-Quantum ML-KEM-768 hybrid keys."""
        url = f"{self.api_url}/kem/generate-keys"
        res = self.session.post(url, json={})
        res.raise_for_status()
        return res.json()

    def create_pop_challenge(self, audience: str = "did:web:docutrust.org") -> Dict[str, Any]:
        """Creates an ephemeral Proof-of-Possession challenge."""
        url = f"{self.api_url}/credentials/pop/challenge"
        res = self.session.post(url, json={"audience": audience})
        res.raise_for_status()
        return res.json()

