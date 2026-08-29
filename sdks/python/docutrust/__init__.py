from __future__ import annotations
from .client import DocuTrustClient
from .crypto import canonicalize_json, sha256_hex, MerkleTree
from .pqc import generate_pqc_hybrid_keys
from .encryption import encrypt_aes_gcm, decrypt_aes_gcm
from .zk_predicates import (
    prove_range,
    verify_range_proof,
    create_commitment,
    prove_age_above,
    verify_age_proof,
    prove_date_range,
    verify_date_range_proof,
    prove_set_membership,
    verify_set_membership_proof
)
from .kem import generate_kem_keypair
from .shamir import split_secret, combine_shares
from .bbs import generate_bbs_keypair, sign_bbs, derive_bbs_proof, verify_bbs_proof
from .oracle import issue_timestamp_token, verify_timestamp_token
from .didcomm import pack_didcomm_message, unpack_didcomm_message
from .mmr import MerkleMountainRange

__version__ = "2.1.1"
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
    "prove_age_above",
    "verify_age_proof",
    "prove_date_range",
    "verify_date_range_proof",
    "prove_set_membership",
    "verify_set_membership_proof",
    "generate_kem_keypair",
    "split_secret",
    "combine_shares",
    "generate_bbs_keypair",
    "sign_bbs",
    "derive_bbs_proof",
    "verify_bbs_proof",
    "issue_timestamp_token",
    "verify_timestamp_token",
    "pack_didcomm_message",
    "unpack_didcomm_message",
    "MerkleMountainRange"
]
