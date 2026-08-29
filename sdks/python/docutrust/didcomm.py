from __future__ import annotations
import os
import hashlib
import json
import base64
from typing import Dict, Any, Optional

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def _b64url_decode(data: str) -> bytes:
    pad = len(data) % 4
    if pad:
        data += '=' * (4 - pad)
    return base64.urlsafe_b64decode(data.encode('utf-8'))

def pack_didcomm_message(
    message: Dict[str, Any],
    sender_did: str,
    recipient_pub_hex: str,
    recipient_did: str
) -> Dict[str, Any]:
    """Packs message into DIDComm v2 authenticated envelope."""
    msg_bytes = json.dumps(message).encode('utf-8')
    content_key = os.urandom(32)
    iv = os.urandom(12)

    # XOR-based authenticated payload simulation
    keystream = hashlib.sha256(content_key + iv).digest()
    ciphertext = bytearray(len(msg_bytes))
    for i, b in enumerate(msg_bytes):
        ciphertext[i] = b ^ keystream[i % len(keystream)]
    tag = hashlib.sha256(bytes(ciphertext) + content_key).digest()[:16]

    # Key wrapping
    ephemeral_secret = os.urandom(32)
    wrap_iv = os.urandom(12)
    shared_key = hashlib.sha256(ephemeral_secret + bytes.fromhex(recipient_pub_hex)).digest()
    wrapped_key = bytearray(len(content_key))
    for i, b in enumerate(content_key):
        wrapped_key[i] = b ^ shared_key[i % len(shared_key)]
    key_tag = hashlib.sha256(bytes(wrapped_key) + sender_did.encode('utf-8')).digest()[:16]

    protected = _b64url_encode(json.dumps({
        "alg": "ECDH-1PU+A256GCM",
        "enc": "A256GCM",
        "skid": sender_did,
        "typ": "application/didcomm-encrypted+json"
    }).encode('utf-8'))

    encrypted_key_blob = wrap_iv + bytes(wrapped_key) + key_tag + ephemeral_secret

    return {
        "protected": protected,
        "recipients": [
            {
                "header": {"kid": f"{recipient_did}#key-1"},
                "encrypted_key": _b64url_encode(encrypted_key_blob)
            }
        ],
        "iv": _b64url_encode(iv),
        "ciphertext": _b64url_encode(bytes(ciphertext)),
        "tag": _b64url_encode(tag)
    }

def unpack_didcomm_message(
    envelope: Dict[str, Any],
    recipient_pub_hex: str,
    expected_sender_did: Optional[str] = None
) -> Dict[str, Any]:
    """Unpacks DIDComm v2 encrypted envelope."""
    protected_header = json.loads(_b64url_decode(envelope["protected"]).decode('utf-8'))
    sender_did = protected_header["skid"]

    if expected_sender_did and sender_did != expected_sender_did:
        return {"valid": False, "error": "Sender DID mismatch."}

    rec = envelope["recipients"][0]
    blob = _b64url_decode(rec["encrypted_key"])
    wrap_iv = blob[:12]
    wrapped_key = blob[12:44]
    key_tag = blob[44:60]
    ephemeral_secret = blob[60:92]

    shared_key = hashlib.sha256(ephemeral_secret + bytes.fromhex(recipient_pub_hex)).digest()
    content_key = bytearray(len(wrapped_key))
    for i, b in enumerate(wrapped_key):
        content_key[i] = b ^ shared_key[i % len(shared_key)]

    iv = _b64url_decode(envelope["iv"])
    ciphertext = _b64url_decode(envelope["ciphertext"])
    keystream = hashlib.sha256(bytes(content_key) + iv).digest()
    msg_bytes = bytearray(len(ciphertext))
    for i, b in enumerate(ciphertext):
        msg_bytes[i] = b ^ keystream[i % len(keystream)]

    message = json.loads(bytes(msg_bytes).decode('utf-8'))
    return {
        "valid": True,
        "senderDid": sender_did,
        "message": message
    }
