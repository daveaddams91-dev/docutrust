from __future__ import annotations
__version__ = "13.0.0"
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
from .badge import BadgeEngine
from .policy import PolicyEngine
from .did import create_did_peer_0, create_did_peer_2, create_did_jwk, encode_did_jwk, decode_did_jwk
from .ringsig import RingSignatureEngine
from .smt import SparseMerkleTree
from .slhdsa import SLHDSAEngine
from .webauthn import WebAuthnAttestationEngine
from .crosschain import CrossChainBridgeEngine
from .groth16 import Groth16Engine
from .trust_score import TrustScoreEngine
from .verifiable_compute import VerifiableComputeEngine
from .vanish_cred import VanishCredEngine
from .state_sync import StateSyncEngine
from .zk_recursive import ZKRecursiveEngine
from .revocation_lattice import RevocationLatticeEngine
from .agent_provenance import AgentProvenanceEngine
from .vrf_oracle import VRFOracleEngine
from .zk_dsl import ZKDSLEngine
from .ai_bom import AIBOMRegistryEngine
from .pqc_falcon import PQCFalconEngine

__version__ = "14.0.0"
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
    "create_did_peer_0",
    "create_did_peer_2",
    "create_did_jwk",
    "encode_did_jwk",
    "decode_did_jwk",
    "AnonCredsEngine",
    "DKGEngine",
    "SolidityEngine",
    "AuditBundleEngine",
    "DataIntegrityEngine",
    "PaillierCryptosystem",
    "ConfidentialClaimsEngine",
    "JsonLdCanonicalizationEngine",
    "TrustChainEngine",
    "DualHybridKEMEngine",
    "BadgeEngine",
    "PolicyEngine",
    "RingSignatureEngine",
    "SparseMerkleTree",
    "SLHDSAEngine",
    "WebAuthnAttestationEngine",
    "CrossChainBridgeEngine",
    "Groth16Engine",
    "TrustScoreEngine",
    "VerifiableComputeEngine",
    "VanishCredEngine",
    "StateSyncEngine",
    "ZKRecursiveEngine",
    "RevocationLatticeEngine",
    "AgentProvenanceEngine",
    "VRFOracleEngine",
    "ZKDSLEngine",
    "AIBOMRegistryEngine",
    "PQCFalconEngine"
]


