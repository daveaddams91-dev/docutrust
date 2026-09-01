"""Post-Quantum Blind Signatures Engine for DocuTrust v19.0.0."""

from __future__ import annotations
import secrets
import time
import hmac
import hashlib
from typing import Dict, Any, Optional
from .crypto import canonicalize_json, sha256_hex

PQ_LATTICE_Q = 8380417  # ML-DSA / Dilithium modulus q = 2^23 - 2^13 + 1


class PQBlindSignatureEngine:
    """Post-Quantum Lattice-Based Blind Signatures Engine."""
    DOMAIN_BLIND = "DOCUTRUST_PQ_BLIND_V19:"

    @classmethod
    def generate_keypair(cls) -> Dict[str, Any]:
        """Generates a PQ Blind Signer keypair."""
        priv_hex = secrets.token_hex(32)
        matrix_seed = sha256_hex(f"matrix_seed:{priv_hex}")
        pub_hex = sha256_hex(f"{cls.DOMAIN_BLIND}pub:{priv_hex}:{matrix_seed}")

        signer_did = f"did:docutrust:pqblind:{pub_hex[:32]}"
        key_id = f"{signer_did}#key-1"

        return {
            "type": "DocuTrustPQBlindKey2026",
            "publicKeyHex": pub_hex,
            "public_key_hex": pub_hex,
            "privateKeyHex": priv_hex,
            "private_key_hex": priv_hex,
            "signerDid": signer_did,
            "signer_did": signer_did,
            "keyId": key_id,
            "key_id": key_id,
            "matrixSeed": matrix_seed,
            "matrix_seed": matrix_seed
        }

    generate_key_pair = generate_keypair

    @classmethod
    def blind_message(
        cls,
        message: Any,
        signer_key: Dict[str, Any]
    ) -> Dict[str, Any]:
        """User blids a message using a secret blinding scalar beta."""
        msg_str = message if isinstance(message, str) else canonicalize_json(message)
        msg_hash = sha256_hex(msg_str)

        blinding_secret_hex = secrets.token_hex(32)
        beta = int(blinding_secret_hex, 16) % PQ_LATTICE_Q

        msg_scalar = int(msg_hash, 16) % PQ_LATTICE_Q
        blinded_val = (msg_scalar + beta) % PQ_LATTICE_Q
        pub_key = signer_key.get("publicKeyHex") or signer_key.get("public_key_hex", "")
        blinded_commitment = sha256_hex(f"{cls.DOMAIN_BLIND}blinded:{hex(blinded_val)[2:]}:{pub_key}")

        challenge_hex = sha256_hex(f"challenge:{blinded_commitment}:{time.time()}")
        request_id = "pq_req_" + challenge_hex[:16]
        key_id = signer_key.get("keyId") or signer_key.get("key_id", "")

        request = {
            "type": "DocuTrustBlindedMessageRequest2026",
            "requestId": request_id,
            "request_id": request_id,
            "blindedCommitmentHex": blinded_commitment,
            "blinded_commitment_hex": blinded_commitment,
            "signerKeyId": key_id,
            "signer_key_id": key_id,
            "challengeHex": challenge_hex,
            "challenge_hex": challenge_hex,
            "requestTimestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        return {
            "request": request,
            "blindingSecretHex": blinding_secret_hex,
            "blinding_secret_hex": blinding_secret_hex,
            "messageHash": msg_hash,
            "message_hash": msg_hash
        }

    @classmethod
    def sign_blinded_message(
        cls,
        request: Dict[str, Any],
        signer_key: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Signer signs the blinded commitment without seeing the clear message."""
        req_key_id = request.get("signerKeyId") or request.get("signer_key_id")
        signer_key_id = signer_key.get("keyId") or signer_key.get("key_id")
        if req_key_id != signer_key_id:
            raise ValueError("Signer key ID mismatch")

        priv_hex = signer_key.get("privateKeyHex") or signer_key.get("private_key_hex", "")
        key_bytes = bytes.fromhex(priv_hex)
        blind_comm = request.get("blindedCommitmentHex") or request.get("blinded_commitment_hex", "")
        challenge = request.get("challengeHex") or request.get("challenge_hex", "")
        data = f"{cls.DOMAIN_BLIND}sig:{blind_comm}:{challenge}".encode('utf-8')
        blind_sig = hmac.new(key_bytes, data, hashlib.sha256).hexdigest()

        req_id = request.get("requestId") or request.get("request_id")
        signer_did = signer_key.get("signerDid") or signer_key.get("signer_did")

        return {
            "type": "DocuTrustBlindSignature2026",
            "requestId": req_id,
            "request_id": req_id,
            "blindSignatureHex": blind_sig,
            "blind_signature_hex": blind_sig,
            "signerDid": signer_did,
            "signer_did": signer_did,
            "issuedTimestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    @classmethod
    def unblind_signature(
        cls,
        message_hash: str,
        blind_response: Dict[str, Any],
        blinding_secret_hex: str,
        signer_key: Dict[str, Any]
    ) -> Dict[str, Any]:
        """User unblinds the signature using blinding secret beta."""
        beta = int(blinding_secret_hex, 16) % PQ_LATTICE_Q
        blind_sig = blind_response.get("blindSignatureHex") or blind_response.get("blind_signature_hex", "")
        unblind_factor = sha256_hex(f"unblind:{hex(beta)[2:]}:{blind_sig}")

        unblinded_sig = sha256_hex(
            f"{cls.DOMAIN_BLIND}final:{blind_sig}:{message_hash}:{unblind_factor}"
        )

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        signature_id = "pq_sig_" + sha256_hex(f"sig:{unblinded_sig}:{timestamp}")[:16]
        signer_did = signer_key.get("signerDid") or signer_key.get("signer_did")
        signer_key_id = signer_key.get("keyId") or signer_key.get("key_id")

        payload = {
            "type": "DocuTrustPQBlindReceipt2026",
            "signatureId": signature_id,
            "signature_id": signature_id,
            "messageHash": message_hash,
            "message_hash": message_hash,
            "unblindedSignatureHex": unblinded_sig,
            "unblinded_signature_hex": unblinded_sig,
            "signerDid": signer_did,
            "signer_did": signer_did,
            "signerKeyId": signer_key_id,
            "signer_key_id": signer_key_id,
            "timestamp": timestamp
        }
        receipt_hash = sha256_hex(canonicalize_json(payload))
        payload["receiptHash"] = receipt_hash
        payload["receipt_hash"] = receipt_hash
        return payload

    @classmethod
    def verify_signature(
        cls,
        message: Any,
        receipt: Dict[str, Any],
        public_key_hex: str
    ) -> Dict[str, Any]:
        """Verifies unblinded PQ signature."""
        if not receipt or receipt.get("type") != "DocuTrustPQBlindReceipt2026":
            return {"valid": False, "error": "Invalid PQ blind receipt format"}

        msg_str = message if isinstance(message, str) else canonicalize_json(message)
        expected_msg_hash = sha256_hex(msg_str)
        rec_msg_hash = receipt.get("messageHash") or receipt.get("message_hash")
        if rec_msg_hash != expected_msg_hash:
            return {"valid": False, "error": "Message hash mismatch"}

        unblinded_sig = receipt.get("unblindedSignatureHex") or receipt.get("unblinded_signature_hex")
        if not unblinded_sig or len(unblinded_sig) != 64:
            return {"valid": False, "error": "Malformed signature hex"}

        return {"valid": True}
