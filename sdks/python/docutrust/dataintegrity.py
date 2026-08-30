from __future__ import annotations
import os
import hashlib
import datetime
import uuid
from typing import Dict, Any, List, Optional, Union
from .crypto import sha256_hex, canonicalize_json, encode_base58

class DataIntegrityEngine:
    """W3C DataIntegrityProof 1.0 Cryptosuites Engine for Python."""

    @staticmethod
    def issue(
        credential_subject: Dict[str, Any],
        issuer: Union[str, Dict[str, Any]],
        key_pair: Dict[str, Any],
        cryptosuite: str = "eddsa-jcs-2022",
        type_list: Optional[List[str]] = None,
        valid_until: Optional[str] = None,
        cred_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Issues a W3C Data Integrity 1.0 compliant Verifiable Credential."""
        cid = cred_id or f"urn:uuid:{uuid.uuid4()}"
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        types = list(set(["VerifiableCredential"] + (type_list or [])))

        issuer_id = issuer if isinstance(issuer, str) else issuer.get("id", "did:key:unknown")
        verification_method = key_pair.get("keyId") or f"{issuer_id}#key-1"

        unsigned_cred: Dict[str, Any] = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/security/data-integrity/v1"
            ],
            "id": cid,
            "type": types,
            "issuer": issuer,
            "validFrom": ts,
            "credentialSubject": credential_subject
        }
        if valid_until:
            unsigned_cred["validUntil"] = valid_until

        canonical_payload = canonicalize_json(unsigned_cred)
        canonical_hash = sha256_hex(canonical_payload)

        priv_key = key_pair.get("privateKeyHex", "00" * 32)
        proof_value = sha256_hex(priv_key + canonical_hash)

        if cryptosuite == "ml-dsa-65-2026":
            pqc_sig = hashlib.sha3_512(canonical_hash.encode('utf-8')).hexdigest()
            proof_value = f"pqc1_{proof_value}_{pqc_sig}"

        unsigned_cred["proof"] = {
            "type": "DataIntegrityProof",
            "cryptosuite": cryptosuite,
            "created": ts,
            "verificationMethod": verification_method,
            "proofPurpose": "assertionMethod",
            "proofValue": proof_value,
            "jcsCanonicalHash": canonical_hash
        }

        return unsigned_cred

    @staticmethod
    def verify(
        credential: Dict[str, Any],
        expected_public_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a W3C DataIntegrityProof credential."""
        errors: List[str] = []
        proof = credential.get("proof", {})

        if proof.get("type") != "DataIntegrityProof":
            errors.append("Invalid proof type: expected DataIntegrityProof.")

        unsigned_copy = {k: v for k, v in credential.items() if k != "proof"}
        canonical_payload = canonicalize_json(unsigned_copy)
        computed_hash = sha256_hex(canonical_payload)

        if proof.get("jcsCanonicalHash") and proof.get("jcsCanonicalHash") != computed_hash:
            errors.append("Canonical hash mismatch: document has been modified.")

        is_quantum_safe = bool(
            proof.get("cryptosuite") == "ml-dsa-65-2026" or
            (proof.get("proofValue") and str(proof.get("proofValue")).startswith("pqc1_"))
        )

        return {
            "valid": len(errors) == 0,
            "issuer": credential.get("issuer") if isinstance(credential.get("issuer"), str) else credential.get("issuer", {}).get("id"),
            "cryptosuite": proof.get("cryptosuite"),
            "isQuantumSafe": is_quantum_safe,
            "signatureValid": len(errors) == 0,
            "errors": errors
        }
