"""DocuTrust Python SDK for W3C Verifiable Credentials and Ledger Anchoring."""

from __future__ import annotations
from .client import DocuTrustClient
from .crypto import canonicalize_json, sha256_hex, MerkleTree
from .pqc import generate_pqc_hybrid_keys

__version__ = "1.1.0"
__all__ = [
    "DocuTrustClient",
    "canonicalize_json",
    "sha256_hex",
    "MerkleTree",
    "generate_pqc_hybrid_keys"
]
