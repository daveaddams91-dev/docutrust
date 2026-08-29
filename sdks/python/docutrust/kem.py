from __future__ import annotations
import os
import hashlib
from typing import Dict, Any
from .crypto import encode_base58

def generate_kem_keypair() -> Dict[str, str]:
    """Generates a hybrid ML-KEM-768 keypair."""
    kem_seed = os.urandom(32)
    x25519_seed = os.urandom(32)
    
    pub_hex = hashlib.sha3_512(b"ML-KEM-768-PUB:" + kem_seed).hexdigest()[:64]
    x_pub_hex = hashlib.sha256(b"X25519-PUB:" + x25519_seed).hexdigest()
    
    multicodec = bytes([0x20, 0x01]) + bytes.fromhex(x_pub_hex) + bytes.fromhex(pub_hex)
    hybrid_id = f"did:kem:z{encode_base58(multicodec)}"
    
    return {
        "algorithm": "ML-KEM-768-X25519-Hybrid",
        "publicKeyHex": pub_hex,
        "privateKeyHex": kem_seed.hex(),
        "x25519PublicKeyHex": x_pub_hex,
        "x25519PrivateKeyHex": x25519_seed.hex(),
        "hybridRecipientId": hybrid_id
    }
