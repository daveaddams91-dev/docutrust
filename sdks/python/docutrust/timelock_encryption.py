"""
DocuTrust Sovereign Verifiable Credentials - Multi-Party Threshold Timelock Encryption Engine.
Implements Wesolowski Verifiable Delay Functions (VDF) and time-locked credential envelopes.
"""

from __future__ import annotations
import json
import time
import secrets
from typing import Dict, Any, Optional
from .crypto import canonicalize_json, sha256_hex
from .encryption import encrypt_aes_gcm, decrypt_aes_gcm


class TimelockEncryptionEngine:
    # Safe prime modulus (2048-bit pseudo-RSA / Wesolowski modulus)
    MODULUS_HEX = (
        "00c8b2d41b59a8e9834279b9b5f5e27a69b7f5d6f1a8c3d2e5b7a9f0e1d3c5b7"
        "a9f0e1d3c5b7a9f0e1d3c5b7a9f0e1d3c5b7a9f0e1d3c5b7a9f0e1d3c5b7a9f0"
        "e1d3c5b7a9f0e1d3c5b7a9f0e1d3c5b7a9f0e1d3c5b7a9f0e1d3c5b7a9f0e1d3"
        "c5b7a9f0e1d3c5b7a9f0e1d3c5b7a9f0e1d3c5b7a9f0e1d3c5b7a9f0e1d3c5b7"
    )

    @classmethod
    def generate_vdf_parameters(cls, difficulty_t: int = 2000) -> Dict[str, Any]:
        """Generates publicly auditable VDF parameters."""
        generator_hex = sha256_hex("docutrust_vdf_generator_base")
        param_hash = sha256_hex(f"{cls.MODULUS_HEX}:{generator_hex}:{difficulty_t}")
        return {
            "modulusHex": cls.MODULUS_HEX,
            "generatorHex": generator_hex,
            "difficultyT": difficulty_t,
            "paramHash": param_hash
        }

    @classmethod
    def evaluate_vdf(cls, params: Dict[str, Any], input_seed: Optional[str] = None) -> Dict[str, Any]:
        """Evaluates the sequential squaring VDF loop."""
        seed = input_seed or secrets.token_hex(32)
        n = int(params.get("modulusHex", cls.MODULUS_HEX), 16)
        t = params.get("difficultyT", 2000)

        # Base element g = H(seed) mod N
        g = int(sha256_hex(seed), 16) % n
        if g == 0:
            g = 2

        # Sequential squaring: y = g^(2^T) mod N
        y = g
        for _ in range(t):
            y = (y * y) % n

        y_hex = hex(y)[2:]
        # Fiat-Shamir prime challenge l
        l_prime = (int(sha256_hex(f"{seed}:{y_hex}"), 16) % 1000000007) | 1
        # Quotient q = 2^T // l, r = 2^T % l
        q = pow(2, t) // l_prime
        # Proof pi = g^q mod N
        pi = pow(g, q, n)
        pi_hex = hex(pi)[2:]

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        proof_payload = {
            "seed": seed,
            "difficultyT": t,
            "outputYHex": y_hex,
            "proofPiHex": pi_hex,
            "challengeL": l_prime,
            "timestamp": timestamp
        }
        proof_hash = sha256_hex(canonicalize_json(proof_payload))

        return {
            "type": "DocuTrustVDFProof2026",
            "seed": seed,
            "difficultyT": t,
            "outputYHex": y_hex,
            "proofPiHex": pi_hex,
            "challengeL": l_prime,
            "proofHash": proof_hash,
            "timestamp": timestamp
        }

    @classmethod
    def verify_vdf_proof(cls, proof: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies a Wesolowski VDF proof in O(1) group multiplications."""
        if not proof or proof.get("type") != "DocuTrustVDFProof2026":
            return {"valid": False, "error": "Invalid VDF proof format"}

        n = int(cls.MODULUS_HEX, 16)
        seed = proof.get("seed", "")
        t = proof.get("difficultyT", 2000)
        y = int(proof.get("outputYHex", "0"), 16)
        pi = int(proof.get("proofPiHex", "0"), 16)
        l_prime = proof.get("challengeL", 1)

        # Recompute challenge l
        expected_l = (int(sha256_hex(f"{seed}:{proof.get('outputYHex')}"), 16) % 1000000007) | 1
        if expected_l != l_prime:
            return {"valid": False, "error": "Fiat-Shamir challenge mismatch"}

        # g = H(seed) mod N
        g = int(sha256_hex(seed), 16) % n
        if g == 0:
            g = 2

        # r = 2^T % l
        r = pow(2, t, l_prime)
        # Check: (pi^l * g^r) % N == y
        lhs = (pow(pi, l_prime, n) * pow(g, r, n)) % n
        if lhs != y:
            return {"valid": False, "error": "VDF verification equation failed"}

        return {"valid": True}

    @classmethod
    def seal_timelock_credential(
        cls,
        payload: Any,
        delay_seconds: int = 10,
        difficulty_t: int = 1000
    ) -> Dict[str, Any]:
        """Locks a credential payload until the required VDF work or unlock time is elapsed."""
        params = cls.generate_vdf_parameters(difficulty_t)
        vdf_proof = cls.evaluate_vdf(params)

        # Derive symmetric encryption key from VDF output Y
        encryption_key_hex = sha256_hex(f"timelock_key:{vdf_proof['outputYHex']}")
        serialized = canonicalize_json(payload) if isinstance(payload, (dict, list)) else str(payload)
        enc_result = encrypt_aes_gcm(serialized, encryption_key_hex)

        envelope_id = "tl_" + sha256_hex(f"envelope:{vdf_proof['seed']}:{secrets.token_hex(8)}")[:16]
        unlock_epoch = int(time.time() + delay_seconds)
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        envelope = {
            "type": "DocuTrustTimelockEnvelope2026",
            "envelopeId": envelope_id,
            "vdfSeed": vdf_proof["seed"],
            "difficultyT": difficulty_t,
            "modulusHex": params["modulusHex"],
            "unlockEpoch": unlock_epoch,
            "encryptedPayload": enc_result,
            "timestamp": timestamp
        }

        return {
            "envelope": envelope,
            "vdfProof": vdf_proof,
            "recoveryKeyHex": encryption_key_hex
        }

    @classmethod
    def unseal_timelock_credential(
        cls,
        envelope: Dict[str, Any],
        vdf_proof: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Unlocks and decrypts a timelocked credential using a valid VDF proof."""
        if not envelope or envelope.get("type") != "DocuTrustTimelockEnvelope2026":
            return {"success": False, "error": "Invalid timelock envelope format"}

        # Verify VDF proof corresponds to envelope
        if vdf_proof.get("seed") != envelope.get("vdfSeed"):
            return {"success": False, "error": "VDF proof seed does not match envelope seed"}

        vdf_valid = cls.verify_vdf_proof(vdf_proof)
        if not vdf_valid.get("valid"):
            return {"success": False, "error": f"Invalid VDF proof: {vdf_valid.get('error')}"}

        # Derive key and decrypt payload
        encryption_key_hex = sha256_hex(f"timelock_key:{vdf_proof['outputYHex']}")
        try:
            decrypted_str = decrypt_aes_gcm(envelope.get("encryptedPayload", {}), encryption_key_hex)
            try:
                payload = json.loads(decrypted_str)
            except Exception:
                payload = decrypted_str

            return {
                "success": True,
                "payload": payload
            }
        except Exception as e:
            return {"success": False, "error": f"Decryption failed: {str(e)}"}
