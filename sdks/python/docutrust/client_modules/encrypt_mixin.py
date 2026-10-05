from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class EncryptMixin:

    def encrypt_data(self, data: Any, passphrase: str) -> Dict[str, Any]:
        """Encrypts data with AES-256-GCM via API vault."""
        url = f"{self.api_url}/vault/encrypt"
        res = self.session.post(url, json={"data": data, "passphrase": passphrase})
        res.raise_for_status()
        return res.json()

    def encrypt_jwe(
        self,
        payload: Union[str, bytes, Dict[str, Any]],
        recipients: List[Dict[str, Any]],
        custom_protected_header: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Encrypts payload for multiple recipient DIDs in General JWE format."""
        from .jwe import MultiRecipientJWE
        return MultiRecipientJWE.encrypt(payload, recipients, custom_protected_header)

    def encrypt_confidential_claim(self, claim_key: str, value: int, public_key: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypts a numeric claim with Paillier Homomorphic encryption."""
        from .confidential import ConfidentialClaimsEngine
        return ConfidentialClaimsEngine.encrypt_claim(claim_key, value, public_key)
