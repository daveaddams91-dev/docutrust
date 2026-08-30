from __future__ import annotations
import datetime
from typing import Dict, Any, List, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from .crypto import canonicalize_json, sha256_hex, decode_base58

class MultiSigEngine:
    """
    Multi-Signature Threshold (M-of-N) Cryptographic Engine for W3C Verifiable Credentials.
    """

    @staticmethod
    def normalize_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
        req = policy.get("requiredSignatures") or policy.get("threshold") or 1
        signers = policy.get("authorizedSigners") or policy.get("authorities") or []
        return {
            "policyId": policy.get("policyId", "policy-default"),
            "requiredSignatures": int(req),
            "totalAuthorizedSigners": policy.get("totalAuthorizedSigners", len(signers)),
            "authorizedSigners": signers
        }

    @staticmethod
    def create_multisig_draft(
        unsigned_credential: Dict[str, Any],
        policy: Dict[str, Any]
    ) -> Dict[str, Any]:
        norm = MultiSigEngine.normalize_policy(policy)
        cred_copy = {k: v for k, v in unsigned_credential.items() if k != "proof"}
        cred_copy["thresholdPolicy"] = {
            "policyId": norm["policyId"],
            "required": norm["requiredSignatures"],
            "signers": [{"did": s["did"], "role": s["role"]} for s in norm["authorizedSigners"]]
        }
        payload_to_sign = canonicalize_json(cred_copy)
        canonical_hash = sha256_hex(payload_to_sign)
        return {
            "canonicalHash": canonical_hash,
            "payloadToSign": payload_to_sign,
            "policy": policy
        }

    @staticmethod
    def create_draft(unsigned_credential: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
        return MultiSigEngine.create_multisig_draft(unsigned_credential, policy)

    @staticmethod
    def sign_as_authority(
        canonical_hash: str,
        signer_did: str,
        role: str,
        private_key_hex: str
    ) -> Dict[str, Any]:
        seed = bytes.fromhex(private_key_hex)
        signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        signature = signing_key.sign(canonical_hash.encode("utf-8"))
        return {
            "signerDid": signer_did,
            "role": role,
            "signature": signature.hex(),
            "signedAt": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

    @staticmethod
    def assemble_multisig_credential(
        unsigned_credential: Dict[str, Any],
        policy: Dict[str, Any],
        collected_signatures: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        norm = MultiSigEngine.normalize_policy(policy)
        draft = MultiSigEngine.create_multisig_draft(unsigned_credential, policy)

        proof = {
            "type": "MultiSigThresholdSignature2026",
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "policyId": norm["policyId"],
            "threshold": {
                "required": norm["requiredSignatures"],
                "total": norm["totalAuthorizedSigners"]
            },
            "signatures": collected_signatures,
            "jcsCanonicalHash": draft["canonicalHash"]
        }

        cred = dict(unsigned_credential)
        cred["proof"] = proof
        return cred

    @staticmethod
    def verify_multisig_credential(
        credential: Dict[str, Any],
        policy: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        proof = credential.get("proof")
        if not proof or proof.get("type") != "MultiSigThresholdSignature2026":
            return {
                "valid": False,
                "verifiedCount": 0,
                "requiredCount": 0,
                "signers": [],
                "errors": ["Not a MultiSig credential"],
                "error": "Not a MultiSig credential"
            }

        effective_policy = (
            MultiSigEngine.normalize_policy(policy)
            if policy
            else {
                "policyId": proof.get("policyId", "policy-default"),
                "requiredSignatures": proof.get("threshold", {}).get("required", 1),
                "totalAuthorizedSigners": proof.get("threshold", {}).get("total", len(proof.get("signatures", []))),
                "authorizedSigners": [
                    {"did": s.get("signerDid"), "role": s.get("role")}
                    for s in proof.get("signatures", [])
                ]
            }
        )

        unsigned = {k: v for k, v in credential.items() if k != "proof"}
        draft = MultiSigEngine.create_multisig_draft(unsigned, effective_policy)
        canonical_hash = draft["canonicalHash"]

        errors: List[str] = []
        verified_dids = set()
        valid_signers: List[str] = []

        for sig_entry in proof.get("signatures", []):
            did = sig_entry.get("signerDid", "")
            if did in verified_dids:
                errors.append(f"Duplicate signature from DID: {did}")
                continue

            try:
                sig_bytes = bytes.fromhex(sig_entry.get("signature", ""))
                # Decode public key from did:key:z...
                if did.startswith("did:key:z"):
                    multibase = did.replace("did:key:z", "").split("#")[0]
                    decoded = decode_base58(multibase)
                    pub_bytes = decoded[2:34]
                elif did.startswith("did:pqc:z"):
                    multibase = did.replace("did:pqc:z", "").split("#")[0]
                    decoded = decode_base58(multibase)
                    pub_bytes = decoded[2:34]
                elif len(did) == 64:
                    pub_bytes = bytes.fromhex(did)
                else:
                    errors.append(f"Unsupported DID format for signature verification: {did}")
                    continue

                verify_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                verify_key.verify(sig_bytes, canonical_hash.encode("utf-8"))
                verified_dids.add(did)
                valid_signers.append(did)
            except InvalidSignature:
                errors.append(f"Invalid signature for role {sig_entry.get('role')}")
            except Exception as e:
                errors.append(f"Signature error for role {sig_entry.get('role')}: {str(e)}")

        verified_count = len(verified_dids)
        required_count = effective_policy["requiredSignatures"]
        valid = verified_count >= required_count and len(errors) == 0

        if verified_count < required_count:
            errors.append(f"Threshold not met: {verified_count} of {required_count} signatures collected.")

        return {
            "valid": valid,
            "policyId": effective_policy["policyId"],
            "threshold": required_count,
            "validSignaturesCount": verified_count,
            "verifiedCount": verified_count,
            "requiredCount": required_count,
            "signers": valid_signers,
            "errors": errors,
            "error": "; ".join(errors) if errors else None
        }
