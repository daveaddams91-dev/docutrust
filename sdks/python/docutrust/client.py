from __future__ import annotations
import requests
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex, MerkleTree

class DocuTrustClient:
    """Client for DocuTrust Sovereign Trust API."""
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
        enable_selective_disclosure: bool = False
    ) -> Dict[str, Any]:
        url = f"{self.api_url}/credentials/issue"
        payload = {
            "credentialSubject": credential_subject,
            "type": ["VerifiableCredential", credential_type],
            "validUntil": valid_until,
            "enableSelectiveDisclosure": enable_selective_disclosure
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
