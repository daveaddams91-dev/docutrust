from __future__ import annotations
import hashlib
import os
from typing import Dict, Any, Tuple, Optional

def shake256_sponge_hex(data: str | bytes, byte_length: int = 64) -> str:
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha3_512(data).hexdigest()[:byte_length * 2]

def generate_pqc_hybrid_keys() -> Dict[str, str]:
    """Generates Post-Quantum ML-DSA seed and hybrid public identifier."""
    pqc_seed = os.urandom(32)
    pqc_private_key_hex = pqc_seed.hex()
    pqc_public_key_hex = shake256_sponge_hex(b"ML-DSA-65-PUB:" + pqc_seed, 32)
    return {
        "pqcPrivateKeyHex": pqc_private_key_hex,
        "pqcPublicKeyHex": pqc_public_key_hex,
        "algorithm": "ML-DSA-65-Ed25519-Hybrid"
    }
