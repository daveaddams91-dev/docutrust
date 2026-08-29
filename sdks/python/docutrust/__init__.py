from __future__ import annotations
from .client import DocuTrustClient
from .crypto import canonicalize_json, sha256_hex, MerkleTree
from .pqc import generate_pqc_hybrid_keys
from .encryption import encrypt_aes_gcm, decrypt_aes_gcm
from .zk_predicates import prove_range, verify_range_proof, create_commitment
from .kem import generate_kem_keypair

__version__ = "1.3.0"
__all__ = [
    "DocuTrustClient",
    "canonicalize_json",
    "sha256_hex",
    "MerkleTree",
    "generate_pqc_hybrid_keys",
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    "prove_range",
    "verify_range_proof",
    "create_commitment",
    "generate_kem_keypair"
]
