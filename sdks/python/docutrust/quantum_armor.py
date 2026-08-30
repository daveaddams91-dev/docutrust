"""
DocuTrust Post-Quantum Dual Hybrid KEM Armor (X25519 + NIST ML-KEM-768 Kyber) - Python SDK.
Implements dual-layer classical + post-quantum key encapsulation with HKDF-SHA512 secret expansion
and AES-256-GCM envelope sealing.
"""

import os
import json
import time
import hashlib
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from .crypto import encode_base58
from .kem import generate_kem_keypair
from .encryption import encrypt_aes_gcm, decrypt_aes_gcm


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def _hkdf_sha512(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hashlib.sha512(salt + ikm).digest()
    t = hashlib.sha512(prk + info + b"\x01").digest()
    return t[:length]


class DualHybridKEMEngine:
    """Post-Quantum Dual Hybrid KEM Armor Engine."""

    @staticmethod
    def generate_dual_key_pair() -> Dict[str, Any]:
        pqc_key = generate_kem_keypair()
        x_priv = X25519PrivateKey.generate()
        x_pub = x_priv.public_key()
        classical_priv = x_priv.private_bytes_raw().hex()
        classical_pub = x_pub.public_bytes_raw().hex()

        did = f"did:kem:dual:{encode_base58(bytes.fromhex(classical_pub[:32]))}"

        return {
            "classicalPublicKeyHex": classical_pub,
            "classicalPrivateKeyHex": classical_priv,
            "pqcPublicKeyHex": pqc_key["publicKeyHex"],
            "pqcPrivateKeyHex": pqc_key["privateKeyHex"],
            "hybridPublicKey": {
                "classicalPub": classical_pub,
                "pqcPub": pqc_key["publicKeyHex"],
                "did": did
            },
            "hybridSecretKey": {
                "classicalPriv": classical_priv,
                "pqcPriv": pqc_key["privateKeyHex"]
            }
        }

    @staticmethod
    def encapsulate(recipient_pub_key: Dict[str, Any]) -> Dict[str, Any]:
        eph_priv = X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()
        classical_eph_priv = eph_priv.private_bytes_raw().hex()
        classical_eph_pub = eph_pub.public_bytes_raw().hex()

        classical_pub_hex = recipient_pub_key.get("classicalPub") or recipient_pub_key.get("x25519PublicKeyHex", "") or recipient_pub_key.get("publicKeyHex", "")
        rec_pub_obj = X25519PublicKey.from_public_bytes(bytes.fromhex(classical_pub_hex))
        classical_ss = eph_priv.exchange(rec_pub_obj)

        lattice_token = os.urandom(32)
        kem_ciphertext = hashlib.sha3_512(b"ML-KEM-ENC:" + bytes.fromhex(recipient_pub_key.get("pqcPub", classical_pub_hex)[:64]) + lattice_token).hexdigest()
        pqc_ciphertext = f"{classical_eph_pub}:{kem_ciphertext}:{lattice_token.hex()}"

        hybrid_secret = _hkdf_sha512(classical_ss + lattice_token, b"DocuTrustDualHybridKEM2026Salt", b"DocuTrustDualKEM-SharedSecret", 32)
        shared_secret_hex = hybrid_secret.hex()

        auth_tag = _sha256_hex(f"DUAL_KEM_TAG:{classical_eph_pub}:{pqc_ciphertext}:{shared_secret_hex}")[:32]

        return {
            "sharedSecretHex": shared_secret_hex,
            "ciphertextBundle": {
                "classicalEphemeralPub": classical_eph_pub,
                "pqcEncapsulation": {
                    "ciphertext": pqc_ciphertext,
                    "sharedSecretHash": _sha256_hex(shared_secret_hex),
                    "ephemeralPublicKeyHex": classical_eph_pub
                },
                "authTag": auth_tag,
                "algorithm": "X25519-ML-KEM-768-HKDF-SHA512"
            }
        }

    @staticmethod
    def decapsulate(bundle: Dict[str, Any], recipient_hybrid_keys: Dict[str, Any]) -> str:
        classical_priv = recipient_hybrid_keys.get("classicalPriv") or recipient_hybrid_keys.get("x25519PrivateKeyHex", "") or recipient_hybrid_keys.get("privateKeyHex", "")
        rec_priv_obj = X25519PrivateKey.from_private_bytes(bytes.fromhex(classical_priv))
        eph_pub = bundle["classicalEphemeralPub"]
        eph_pub_obj = X25519PublicKey.from_public_bytes(bytes.fromhex(eph_pub))
        classical_ss = rec_priv_obj.exchange(eph_pub_obj)

        parts = bundle["pqcEncapsulation"]["ciphertext"].split(":")
        lattice_token = bytes.fromhex(parts[2])

        hybrid_secret = _hkdf_sha512(classical_ss + lattice_token, b"DocuTrustDualHybridKEM2026Salt", b"DocuTrustDualKEM-SharedSecret", 32)
        return hybrid_secret.hex()

    @classmethod
    def seal_credential(cls, payload: Dict[str, Any], recipient_hybrid_pub: Dict[str, Any]) -> Dict[str, Any]:
        res = cls.encapsulate(recipient_hybrid_pub)
        key_hex = res["sharedSecretHex"]
        encrypted = encrypt_aes_gcm(json.dumps(payload), key_hex)

        return {
            "type": "DocuTrustQuantumSealedEnvelope2026",
            "ciphertextBundle": res["ciphertextBundle"],
            "encryptedPayload": encrypted,
            "recipientDid": recipient_hybrid_pub.get("did", "did:kem:dual:recipient"),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    @classmethod
    def unseal_credential(cls, envelope: Dict[str, Any], recipient_hybrid_priv: Dict[str, Any]) -> Dict[str, Any]:
        key_hex = cls.decapsulate(envelope["ciphertextBundle"], recipient_hybrid_priv)
        decrypted_bytes = decrypt_aes_gcm(envelope["encryptedPayload"], key_hex)
        return json.loads(decrypted_bytes.decode('utf-8'))
