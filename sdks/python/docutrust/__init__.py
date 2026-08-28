"""DocuTrust Python SDK for W3C Verifiable Credentials and Ledger Anchoring."""

from .client import DocuTrustClient
from .crypto import canonicalize_json, sha256_hex, MerkleTree

__version__ = "1.0.0"
__all__ = [
    "DocuTrustClient",
    "canonicalize_json",
    "sha256_hex",
    "MerkleTree"
]
