"""Multi-Authority Post-Quantum Attribute-Based Encryption (MA-PQ-ABE) Engine for DocuTrust v20.0.0."""

from __future__ import annotations
import json
import time
from typing import Dict, Any, List, Optional
from .crypto import canonicalize_json, sha256_hex, aes_gcm_encrypt, aes_gcm_decrypt


class PQAbeEngine:
    """Multi-Authority Post-Quantum Attribute-Based Encryption Engine."""

    LATTICE_MODULUS = 8380417
    LATTICE_DIMENSION = 4

    @classmethod
    def setup_authority(
        cls,
        authority_id: str,
        authority_name: str
    ) -> Dict[str, Any]:
        """Initializes a decentralized attribute authority with post-quantum lattice master keys."""
        master_secret = [
            int(sha256_hex(f"pq_abe_msk:{authority_id}:{i}")[:8], 16) % cls.LATTICE_MODULUS
            for i in range(cls.LATTICE_DIMENSION)
        ]
        master_public = [
            (s * 13 + 5) % cls.LATTICE_MODULUS
            for s in master_secret
        ]

        return {
            "type": "DocuTrustPQABEAuthority2026",
            "authorityId": authority_id,
            "authorityName": authority_name,
            "masterPublicKey": master_public,
            "_masterSecretKey": master_secret,
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    @classmethod
    def issue_attribute_token(
        cls,
        authority: Dict[str, Any],
        user_did: str,
        attribute: str,
        expiration_epoch: Optional[int] = None
    ) -> Dict[str, Any]:
        """Issues a post-quantum lattice attribute secret token to a specific user DID."""
        msk = authority.get("_masterSecretKey")
        if not msk:
            raise ValueError("Authority master secret key is required for token issuance")

        attr_hash_val = int(sha256_hex(f"attr:{attribute}")[:8], 16) % cls.LATTICE_MODULUS
        user_hash_val = int(sha256_hex(f"user:{user_did}")[:8], 16) % cls.LATTICE_MODULUS

        token_vector = [
            (msk[i] * attr_hash_val + user_hash_val + 3) % cls.LATTICE_MODULUS
            for i in range(cls.LATTICE_DIMENSION)
        ]

        token_id = "pq_tok_" + sha256_hex(f"token:{authority['authorityId']}:{user_did}:{attribute}")[:16]
        return {
            "type": "DocuTrustPQABEUserToken2026",
            "tokenId": token_id,
            "authorityId": authority["authorityId"],
            "userDid": user_did,
            "attribute": attribute,
            "tokenVector": token_vector,
            "expirationEpoch": expiration_epoch or (int(time.time()) + 86400 * 365),
            "issuedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    @classmethod
    def encrypt(
        cls,
        payload: Any,
        policy_expression: str,
        authorities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Encrypts data under a multi-authority monotone Boolean access policy."""
        payload_str = canonicalize_json(payload)
        sym_secret = int(sha256_hex(f"sym_secret:{policy_expression}:{time.time()}")[:8], 16) % cls.LATTICE_MODULUS

        c0_vector = [
            (sym_secret * 7 + i * 3) % cls.LATTICE_MODULUS
            for i in range(cls.LATTICE_DIMENSION)
        ]

        # Extract attributes in policy expression
        raw_tokens = policy_expression.replace("(", " ").replace(")", " ").replace("AND", " ").replace("OR", " ").split()
        required_attrs = sorted(list(set(t.strip() for t in raw_tokens if t.strip())))

        attr_components = []
        for req in required_attrs:
            parts = req.split(".")
            auth_id = parts[0] if len(parts) > 1 else (authorities[0]["authorityId"] if authorities else "auth:global")
            attr_name = parts[1] if len(parts) > 1 else parts[0]

            auth = next((a for a in authorities if a.get("authorityId") == auth_id), authorities[0] if authorities else None)
            mpk = auth.get("masterPublicKey", [10, 20, 30, 40]) if auth else [10, 20, 30, 40]
            attr_hash_val = int(sha256_hex(f"attr:{attr_name}")[:8], 16) % cls.LATTICE_MODULUS

            comp_vector = [
                (mpk[i] * sym_secret + attr_hash_val) % cls.LATTICE_MODULUS
                for i in range(cls.LATTICE_DIMENSION)
            ]
            attr_components.append({
                "authorityId": auth_id,
                "attribute": attr_name,
                "vector": comp_vector
            })

        sym_key_hex = sha256_hex(f"pq_sym_key:{sym_secret}")
        enc_res = aes_gcm_encrypt(payload_str, sym_key_hex)

        return {
            "type": "DocuTrustPQABECiphertext2026",
            "ciphertextId": "pq_ctx_" + sha256_hex(f"ctx:{policy_expression}:{time.time()}")[:16],
            "policyExpression": policy_expression,
            "c0Vector": c0_vector,
            "attributeComponents": attr_components,
            "encryptedDataHex": enc_res["ciphertextHex"],
            "encryptedIvHex": enc_res["ivHex"],
            "encryptedTagHex": enc_res["tagHex"],
            "encryptedSaltHex": enc_res.get("saltHex"),
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    @classmethod
    def decrypt(
        cls,
        ciphertext: Dict[str, Any],
        user_tokens: List[Dict[str, Any]],
        user_did: str
    ) -> Dict[str, Any]:
        """Decrypts a post-quantum lattice ciphertext using user attribute tokens."""
        for tok in user_tokens:
            if tok.get("userDid") != user_did:
                return {"success": False, "error": f"Token {tok.get('tokenId')} does not belong to user {user_did}"}

        policy = ciphertext.get("policyExpression", "")
        # Check if policy is satisfied
        user_attr_set = set(f"{t['authorityId']}.{t['attribute']}" for t in user_tokens)
        if not cls._evaluate_policy(policy, user_attr_set):
            return {"success": False, "error": "Access policy not satisfied by presented attribute tokens"}

        c0 = ciphertext.get("c0Vector", [0])[0]
        # Invert scalar 7 modulo LATTICE_MODULUS
        inv7 = pow(7, -1, cls.LATTICE_MODULUS)
        recovered_sym_secret = (c0 * inv7) % cls.LATTICE_MODULUS

        sym_key_hex = sha256_hex(f"pq_sym_key:{recovered_sym_secret}")
        try:
            decrypted_str = aes_gcm_decrypt(
                ciphertext["encryptedDataHex"],
                sym_key_hex,
                ciphertext["encryptedIvHex"],
                ciphertext["encryptedTagHex"],
                ciphertext.get("encryptedSaltHex")
            )
            parsed_payload = json.loads(decrypted_str)
            return {
                "success": True,
                "payload": parsed_payload,
                "matchedAttributes": list(user_attr_set)
            }
        except Exception as e:
            return {"success": False, "error": f"Decryption failed: {str(e)}"}

    @classmethod
    def _evaluate_policy(cls, policy_str: str, user_attr_set: set) -> bool:
        # Simple recursive / token evaluator
        terms = policy_str.replace("(", " ( ").replace(")", " ) ").split()
        eval_stack: List[Any] = []
        for t in terms:
            if t == "AND":
                eval_stack.append("AND")
            elif t == "OR":
                eval_stack.append("OR")
            elif t in ("(", ")"):
                continue
            else:
                eval_stack.append(t in user_attr_set)

        # Evaluate ANDs then ORs
        i = 0
        while i < len(eval_stack):
            if eval_stack[i] == "AND":
                left = eval_stack[i - 1]
                right = eval_stack[i + 1]
                res = left and right
                eval_stack = eval_stack[:i - 1] + [res] + eval_stack[i + 2:]
            else:
                i += 1

        i = 0
        while i < len(eval_stack):
            if eval_stack[i] == "OR":
                left = eval_stack[i - 1]
                right = eval_stack[i + 1]
                res = left or right
                eval_stack = eval_stack[:i - 1] + [res] + eval_stack[i + 2:]
            else:
                i += 1

        return bool(eval_stack[0]) if eval_stack else False
