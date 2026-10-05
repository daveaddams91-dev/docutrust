from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class DecryptMixin:

    def decrypt_data(self, encrypted_payload: Dict[str, Any], passphrase: str) -> Dict[str, Any]:
        """Decrypts AES-256-GCM payload via API vault."""
        url = f"{self.api_url}/vault/decrypt"
        res = self.session.post(url, json={"encrypted": encrypted_payload, "passphrase": passphrase})
        res.raise_for_status()
        return res.json()

    def decrypt_jwe(
        self,
        jwe: Dict[str, Any],
        recipient_did: str,
        recipient_private_key: Union[str, bytes]
    ) -> Dict[str, Any]:
        """Decrypts General JWE payload for recipient DID."""
        from .jwe import MultiRecipientJWE
        return MultiRecipientJWE.decrypt(jwe, recipient_did, recipient_private_key)
