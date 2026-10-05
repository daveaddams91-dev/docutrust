from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class BbsMixin:

    def bbs_generate_keys(self, max_messages: int = 10) -> Dict[str, Any]:
        """Generates BBS+ keypair with generator commitments."""
        url = f"{self.api_url}/credentials/bbs/generate-keys"
        res = self.session.post(url, json={"maxMessages": max_messages})
        res.raise_for_status()
        return res.json()

    def bbs_issue(self, messages: List[str], keypair: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Issues BBS+ multi-message signature."""
        url = f"{self.api_url}/credentials/bbs/issue"
        payload = {"messages": messages}
        if keypair:
            payload["keyPair"] = keypair
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def bbs_derive_proof(
        self,
        signature: Dict[str, Any],
        all_messages: List[str],
        disclosed_indices: List[int],
        keypair: Optional[Dict[str, Any]] = None,
        nonce: Optional[str] = None
    ) -> Dict[str, Any]:
        """Derives unlinkable BBS+ zero-knowledge proof."""
        url = f"{self.api_url}/credentials/bbs/derive-proof"
        payload = {
            "signature": signature,
            "allMessages": all_messages,
            "disclosedIndices": disclosed_indices,
            "keyPair": keypair,
            "nonce": nonce
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def bbs_verify_proof(self, proof: Dict[str, Any], expected_issuer_did: Optional[str] = None) -> Dict[str, Any]:
        """Verifies BBS+ zero-knowledge proof."""
        url = f"{self.api_url}/credentials/bbs/verify-proof"
        payload = {"proof": proof}
        if expected_issuer_did:
            payload["expectedIssuerDid"] = expected_issuer_did
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()
