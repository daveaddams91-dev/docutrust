from __future__ import annotations
from .client import DocuTrustClient
from .crypto import canonicalize_json, sha256_hex, MerkleTree, encode_base58, decode_base58
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
    verify_set_membership_proof,
    prove_set_non_membership,
    verify_set_non_membership_proof,
    prove_set_intersection,
    verify_set_intersection_proof,
    prove_composite_predicate,
    verify_composite_predicate,
    prove_predicate_graph,
    verify_predicate_graph
)
from .kem import generate_kem_keypair
from .shamir import split_secret, combine_shares
from .bbs import generate_bbs_keypair, sign_bbs, derive_bbs_proof, verify_bbs_proof
from .oracle import issue_timestamp_token, verify_timestamp_token
from .didcomm import pack_didcomm_message, unpack_didcomm_message
from .mmr import MerkleMountainRange
from .eip712 import (
    generate_secp256k1_key_pair,
    sign_vc_eip712,
    verify_vc_eip712,
    derive_ethereum_address
)
from .social_recovery import SocialRecoveryEngine
from .multichain import MultiChainLedgerAnchor
from .schema import SchemaValidator
from .accumulator import CryptographicAccumulator, extended_gcd
from .jwe import MultiRecipientJWE
from .status_list import BitstringStatusList2024
from .presentation_exchange import PresentationExchangeEngine
from .multisig import MultiSigEngine
from .did import DIDResolver
from .anoncreds import AnonCredsEngine
from .dkg import DKGEngine
from .solidity import SolidityEngine
from .bundle import AuditBundleEngine
from .dataintegrity import DataIntegrityEngine
from .confidential import PaillierCryptosystem, ConfidentialClaimsEngine
from .jsonld import JsonLdCanonicalizationEngine
from .trustchain import TrustChainEngine
from .quantum_armor import DualHybridKEMEngine

__version__ = "8.0.0"
__all__ = [
    "DocuTrustClient",
    "canonicalize_json",
    "sha256_hex",
    "MerkleTree",
    "encode_base58",
    "decode_base58",
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
    "prove_set_non_membership",
    "verify_set_non_membership_proof",
    "prove_set_intersection",
    "verify_set_intersection_proof",
    "prove_composite_predicate",
    "verify_composite_predicate",
    "prove_predicate_graph",
    "verify_predicate_graph",
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
    "MerkleMountainRange",
    "generate_secp256k1_key_pair",
    "sign_vc_eip712",
    "verify_vc_eip712",
    "derive_ethereum_address",
    "SocialRecoveryEngine",
    "MultiChainLedgerAnchor",
    "SchemaValidator",
    "CryptographicAccumulator",
    "extended_gcd",
    "MultiRecipientJWE",
    "BitstringStatusList2024",
    "PresentationExchangeEngine",
    "MultiSigEngine",
    "DIDResolver",
    "AnonCredsEngine",
    "DKGEngine",
    "SolidityEngine",
    "AuditBundleEngine",
    "DataIntegrityEngine",
    "PaillierCryptosystem",
    "ConfidentialClaimsEngine",
    "JsonLdCanonicalizationEngine",
    "TrustChainEngine",
    "DualHybridKEMEngine"
]
