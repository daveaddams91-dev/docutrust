"""
DocuTrust Hierarchical Verifiable Trust Chains & Authority Delegation Engine (Python SDK).
Enables multi-tier institutional governance with cryptographic delegation tokens and constraint path validation.
"""

import time
import uuid
import hashlib
from typing import Dict, Any, List, Optional
from .crypto import canonicalize_json, sign_data, verify_signature, decode_base58


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


class TrustChainEngine:
    """Hierarchical Verifiable Trust Chains & Authority Delegation Engine."""

    @staticmethod
    def create_delegation_token(
        delegator_key_pair: Dict[str, Any],
        delegate_did: str,
        allowed_credential_types: Optional[List[str]] = None,
        max_depth: int = 2,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None
    ) -> Dict[str, Any]:
        token_id = f"urn:uuid:delegation-{uuid.uuid4()}"
        now_ts = time.time()
        vf = valid_from or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts))
        vu = valid_until or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts + 365 * 24 * 3600))

        constraints = {
            "allowedCredentialTypes": allowed_credential_types or ["*"],
            "maxDepth": max_depth
        }

        unsigned = {
            "type": "DocuTrustDelegationToken2026",
            "id": token_id,
            "delegatorDid": delegator_key_pair["did"],
            "delegateDid": delegate_did,
            "constraints": constraints,
            "validFrom": vf,
            "validUntil": vu
        }

        canonical = canonicalize_json(unsigned)
        digest = _sha256_hex(canonical)
        created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        proof_value = sign_data(f"{digest}:{created}", delegator_key_pair["privateKeyHex"])

        unsigned["proof"] = {
            "type": "Ed25519Signature2020",
            "created": created,
            "verificationMethod": f"{delegator_key_pair['did']}#key-1",
            "proofValue": proof_value
        }

        return unsigned

    @staticmethod
    def verify_delegation_token(
        token: Dict[str, Any],
        expected_delegator_pub_hex: Optional[str] = None
    ) -> bool:
        if not isinstance(token, dict) or token.get("type") != "DocuTrustDelegationToken2026" or "proof" not in token:
            return False

        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if now_iso < token.get("validFrom", "") or now_iso > token.get("validUntil", ""):
            return False

        copy = dict(token)
        copy.pop("proof", None)
        canonical = canonicalize_json(copy)
        digest = _sha256_hex(canonical)

        pub_hex = expected_delegator_pub_hex
        if not pub_hex and token.get("delegatorDid", "").startswith("did:key:"):
            try:
                raw = decode_base58(token["delegatorDid"].replace("did:key:z", ""))
                pub_hex = raw[2:].hex()
            except Exception:
                pass

        if not pub_hex:
            return False

        return verify_signature(f"{digest}:{token['proof']['created']}", token["proof"]["proofValue"], pub_hex)

    @classmethod
    def verify_trust_chain(
        cls,
        chain: List[Dict[str, Any]],
        credential: Dict[str, Any],
        accredited_root_dids: List[str]
    ) -> Dict[str, Any]:
        errors = []
        if not chain or not isinstance(chain, list):
            return {
                "valid": False,
                "rootAuthorityDid": "",
                "leafIssuerDid": "",
                "chainDepth": 0,
                "tokensVerified": 0,
                "isAccreditedRoot": False,
                "errors": ["Trust chain is empty or invalid."]
            }

        cred_issuer = credential.get("issuer")
        if isinstance(cred_issuer, dict):
            cred_issuer = cred_issuer.get("id")

        cred_types = credential.get("type", [])
        if isinstance(cred_types, str):
            cred_types = [cred_types]

        root_token = chain[0]
        is_accredited = root_token.get("delegatorDid") in accredited_root_dids
        if not is_accredited:
            errors.append(f"Root delegator {root_token.get('delegatorDid')} is not accredited.")

        current_delegator = root_token.get("delegatorDid")
        for i, token in enumerate(chain):
            if token.get("delegatorDid") != current_delegator:
                errors.append(f"Chain broken at step {i}: expected {current_delegator}, got {token.get('delegatorDid')}")

            if not cls.verify_delegation_token(token):
                errors.append(f"Delegation token at step {i} (ID: {token.get('id')}) failed verification.")

            max_depth = token.get("constraints", {}).get("maxDepth", 2)
            remaining_depth = len(chain) - 1 - i
            if remaining_depth > max_depth:
                errors.append(f"Sub-delegation depth {remaining_depth} exceeds permitted maxDepth {max_depth} at step {i}.")

            allowed = token.get("constraints", {}).get("allowedCredentialTypes", ["*"])
            if "*" not in allowed:
                if not any(t in allowed for t in cred_types):
                    errors.append(f"Credential type not permitted by delegation token {token.get('id')}.")

            current_delegator = token.get("delegateDid")

        leaf_token = chain[-1]
        if leaf_token.get("delegateDid") != cred_issuer:
            errors.append(f"Leaf delegate {leaf_token.get('delegateDid')} does not match credential issuer {cred_issuer}.")

        return {
            "valid": len(errors) == 0,
            "rootAuthorityDid": root_token.get("delegatorDid", ""),
            "leafIssuerDid": leaf_token.get("delegateDid", ""),
            "chainDepth": len(chain),
            "tokensVerified": len(chain),
            "isAccreditedRoot": is_accredited,
            "errors": errors
        }
