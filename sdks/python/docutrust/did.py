from __future__ import annotations
from typing import Dict, Any
from .crypto import decode_base58

class DIDResolver:
    """
    Universal DID Resolver for DocuTrust DIDs (did:key, did:pqc, did:kem, did:bbs, did:pkh, did:web).
    """

    @staticmethod
    def resolve(did: str) -> Dict[str, Any]:
        if not did or not isinstance(did, str):
            raise ValueError("Invalid DID string provided.")

        parts = did.split(":")
        if len(parts) < 3 or parts[0] != "did":
            raise ValueError(f"Malformed DID syntax: {did}")

        method = parts[1]

        if method == "key":
            raw_str = parts[2].split("#")[0]
            multibase = raw_str[1:] if raw_str.startswith("z") else raw_str
            raw = decode_base58(multibase)
            pub_hex = raw[2:34].hex()
            vm_id = f"{did}#{multibase}"
            return {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/ed25519-2020/v1"
                ],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": multibase,
                    "publicKeyHex": pub_hex
                }],
                "authentication": [vm_id],
                "assertionMethod": [vm_id]
            }

        if method == "pqc":
            raw_str = parts[2].split("#")[0]
            multibase = raw_str[1:] if raw_str.startswith("z") else raw_str
            raw = decode_base58(multibase)
            pub_hex = raw[2:34].hex()
            vm_id = f"{did}#ml-dsa-65-hybrid"
            return {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/jws-2020/v1"
                ],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "MLDSA65HybridVerificationKey2026",
                    "controller": did,
                    "publicKeyMultibase": multibase,
                    "classicalPublicKeyHex": pub_hex
                }],
                "authentication": [vm_id],
                "assertionMethod": [vm_id]
            }

        if method == "kem":
            raw_str = parts[2].split("#")[0]
            multibase = raw_str[1:] if raw_str.startswith("z") else raw_str
            raw = decode_base58(multibase)
            pub_hex = raw[2:].hex()
            vm_id = f"{did}#ml-kem-768"
            return {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "MLKEM768KeyAgreementKey2026",
                    "controller": did,
                    "publicKeyMultibase": multibase,
                    "publicKeyHex": pub_hex
                }],
                "keyAgreement": [vm_id]
            }

        if method == "bbs":
            raw_str = parts[2].split("#")[0]
            multibase = raw_str[1:] if raw_str.startswith("z") else raw_str
            raw = decode_base58(multibase)
            pub_hex = raw[2:50].hex() if len(raw) >= 50 else raw[2:].hex()
            vm_id = f"{did}#bbs-g2"
            return {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/bbs/v1"
                ],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "Bls12381G2Key2020",
                    "controller": did,
                    "publicKeyMultibase": multibase,
                    "publicKeyHex": pub_hex
                }],
                "assertionMethod": [vm_id]
            }

        if method == "pkh":
            address = parts[-1]
            vm_id = f"{did}#blockchainAccountId"
            return {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/secp256k1recovery-2020/v1"
                ],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "EcdsaSecp256k1RecoveryMethod2020",
                    "controller": did,
                    "blockchainAccountId": f"{parts[2]}:{address}"
                }],
                "authentication": [vm_id],
                "assertionMethod": [vm_id]
            }

        if method == "web":
            domain = parts[2].replace("%3A", ":")
            vm_id = f"{did}#key-1"
            return {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did
                }],
                "authentication": [vm_id],
                "assertionMethod": [vm_id]
            }

        raise ValueError(f"Unsupported DID method: {method}")
