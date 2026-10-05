from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class DidcommMixin:

    def didcomm_pack(
        self,
        message: Dict[str, Any],
        recipient_public_key_hex: str,
        recipient_did: str,
        sender_keypair: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Packs a DIDComm v2 authenticated encrypted envelope."""
        url = f"{self.api_url}/didcomm/pack"
        payload = {
            "message": message,
            "recipientPublicKeyHex": recipient_public_key_hex,
            "recipientDid": recipient_did,
            "senderKeyPair": sender_keypair
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def didcomm_unpack(
        self,
        envelope: Dict[str, Any],
        recipient_keypair: Dict[str, Any],
        expected_sender_did: Optional[str] = None
    ) -> Dict[str, Any]:
        """Unpacks and decrypts a DIDComm v2 message envelope."""
        url = f"{self.api_url}/didcomm/unpack"
        payload = {
            "envelope": envelope,
            "recipientKeyPair": recipient_keypair,
            "expectedSenderDid": expected_sender_did
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()
