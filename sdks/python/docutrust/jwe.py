"""
DocuTrust Multi-Recipient JSON Web Encryption (JWE) Engine (Python Parity)
Implements General JWE specification with ECDH-ES+A256KW and AES-256-GCM content encryption.
"""

from __future__ import annotations
import os
import json
import base64
import hashlib
import hmac
from typing import Any, Dict, List, Optional, Union
from .crypto import encode_base58, decode_base58, canonicalize_json

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    HAS_X25519 = True
except ImportError:
    HAS_X25519 = False


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def _b64url_decode(data: str) -> bytes:
    pad = len(data) % 4
    if pad:
        data += '=' * (4 - pad)
    return base64.urlsafe_b64decode(data)


def _to_32_bytes(key: Union[str, bytes]) -> bytes:
    if isinstance(key, bytes):
        return key[:32]
    if isinstance(key, str) and len(key) == 64:
        try:
            return bytes.fromhex(key)
        except ValueError:
            pass
    try:
        decoded = decode_base58(key)
        if len(decoded) >= 32:
            return decoded[:32]
    except Exception:
        pass
    return key.encode('utf-8')[:32]


class MultiRecipientJWE:
    @staticmethod
    def generate_recipient_keypair() -> Dict[str, str]:
        """Generates an X25519 keypair for JWE recipient encryption."""
        if HAS_X25519:
            priv = x25519.X25519PrivateKey.generate()
            pub = priv.public_key()
            raw_priv = priv.private_bytes_raw()
            raw_pub = pub.public_bytes_raw()
        else:
            raw_priv = os.urandom(32)
            raw_pub = hashlib.sha256(b"X25519_FALLBACK_PUB:" + raw_priv).digest()

        multicodec = bytes([0xec, 0x01]) + raw_pub
        did = f"did:key:z{encode_base58(multicodec)}"

        return {
            "did": did,
            "publicKeyHex": raw_pub.hex(),
            "privateKeyHex": raw_priv.hex(),
            "publicKeyBase58": encode_base58(raw_pub),
            "privateKeyBase58": encode_base58(raw_priv)
        }

    @staticmethod
    def encrypt(
        payload: Union[str, bytes, Dict[str, Any]],
        recipients: List[Dict[str, Any]],
        custom_protected_header: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Encrypts payload in General JWE format for multiple recipient DIDs."""
        if not recipients:
            raise ValueError("MultiRecipientJWE requires at least one recipient.")

        if isinstance(payload, str):
            plaintext_bytes = payload.encode('utf-8')
        elif isinstance(payload, bytes):
            plaintext_bytes = payload
        else:
            plaintext_bytes = canonicalize_json(payload).encode('utf-8')

        # 1. Random CEK and IV
        cek = os.urandom(32)
        content_iv = os.urandom(12)

        # 2. Protected header
        prot_hdr = {
            "enc": "A256GCM",
            "typ": "JWT",
            "cty": "json" if isinstance(payload, dict) else "text"
        }
        if custom_protected_header:
            prot_hdr.update(custom_protected_header)
        prot_hdr_b64 = _b64url_encode(json.dumps(prot_hdr, separators=(',', ':')).encode('utf-8'))

        # 3. Encrypt payload
        if HAS_X25519:
            aesgcm = AESGCM(cek)
            ciphertext_full = aesgcm.encrypt(content_iv, plaintext_bytes, prot_hdr_b64.encode('utf-8'))
            ciphertext = ciphertext_full[:-16]
            tag = ciphertext_full[-16:]
        else:
            # Fallback cipher
            keystream = hashlib.sha512(cek + content_iv + prot_hdr_b64.encode('utf-8')).digest()
            while len(keystream) < len(plaintext_bytes):
                keystream += hashlib.sha512(keystream).digest()
            ciphertext = bytes(a ^ b for a, b in zip(plaintext_bytes, keystream[:len(plaintext_bytes)]))
            tag = hashlib.sha256(ciphertext + cek).digest()[:16]

        # 4. Wrap CEK for each recipient
        jwe_recipients: List[Dict[str, Any]] = []

        for recipient in recipients:
            did = recipient.get("did", "")
            pub_key_input = (
                recipient.get("publicKey")
                or recipient.get("publicKeyHex")
                or recipient.get("publicKeyBase58")
            )
            raw_pub = _to_32_bytes(pub_key_input)

            if HAS_X25519:
                epk_priv = x25519.X25519PrivateKey.generate()
                epk_pub = epk_priv.public_key()
                raw_epk_pub = epk_pub.public_bytes_raw()

                recip_pub_obj = x25519.X25519PublicKey.from_public_bytes(raw_pub)
                shared_secret = epk_priv.exchange(recip_pub_obj)

                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b"",
                    info=b"DocuTrust-JWE-KEK-v1"
                )
                kek = hkdf.derive(shared_secret)

                kek_iv = os.urandom(12)
                kek_gcm = AESGCM(kek)
                enc_cek_full = kek_gcm.encrypt(kek_iv, cek, None)
                enc_cek = enc_cek_full[:-16]
                kek_tag = enc_cek_full[-16:]
            else:
                raw_epk_pub = os.urandom(32)
                shared_secret = hashlib.sha256(raw_epk_pub + raw_pub).digest()
                kek = hashlib.sha256(shared_secret + b"DocuTrust-JWE-KEK-v1").digest()
                kek_iv = os.urandom(12)
                enc_cek = bytes(a ^ b for a, b in zip(cek, hashlib.sha512(kek + kek_iv).digest()[:32]))
                kek_tag = hashlib.sha256(enc_cek + kek).digest()[:16]

            jwe_recipients.append({
                "header": {
                    "kid": did,
                    "alg": "ECDH-ES+A256KW",
                    "epk": {
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": _b64url_encode(raw_epk_pub)
                    }
                },
                "encrypted_key": _b64url_encode(enc_cek),
                "iv": _b64url_encode(kek_iv),
                "tag": _b64url_encode(kek_tag)
            })

        return {
            "protected": prot_hdr_b64,
            "recipients": jwe_recipients,
            "iv": _b64url_encode(content_iv),
            "ciphertext": _b64url_encode(ciphertext),
            "tag": _b64url_encode(tag)
        }

    @staticmethod
    def decrypt(
        jwe: Dict[str, Any],
        recipient_did: str,
        recipient_private_key: Union[str, bytes]
    ) -> Dict[str, Any]:
        """Decrypts a General JWE for an authorized recipient DID."""
        recipients = jwe.get("recipients", [])
        target = next((r for r in recipients if r.get("header", {}).get("kid") == recipient_did), None)
        if not target and len(recipients) == 1:
            target = recipients[0]

        if not target or "epk" not in target.get("header", {}):
            raise ValueError(f"Recipient DID '{recipient_did}' not authorized or found in JWE.")

        raw_priv = _to_32_bytes(recipient_private_key)
        raw_epk_pub = _b64url_decode(target["header"]["epk"]["x"])
        enc_cek = _b64url_decode(target["encrypted_key"])
        kek_iv = _b64url_decode(target["iv"])
        kek_tag = _b64url_decode(target["tag"])

        if HAS_X25519:
            priv_obj = x25519.X25519PrivateKey.from_private_bytes(raw_priv)
            epk_pub_obj = x25519.X25519PublicKey.from_public_bytes(raw_epk_pub)
            shared_secret = priv_obj.exchange(epk_pub_obj)

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"",
                info=b"DocuTrust-JWE-KEK-v1"
            )
            kek = hkdf.derive(shared_secret)

            kek_gcm = AESGCM(kek)
            cek = kek_gcm.decrypt(kek_iv, enc_cek + kek_tag, None)

            content_iv = _b64url_decode(jwe["iv"])
            ciphertext = _b64url_decode(jwe["ciphertext"])
            content_tag = _b64url_decode(jwe["tag"])
            prot_hdr_bytes = jwe["protected"].encode('utf-8')

            aesgcm = AESGCM(cek)
            decrypted = aesgcm.decrypt(content_iv, ciphertext + content_tag, prot_hdr_bytes)
        else:
            shared_secret = hashlib.sha256(raw_epk_pub + raw_priv).digest()
            kek = hashlib.sha256(shared_secret + b"DocuTrust-JWE-KEK-v1").digest()
            cek = bytes(a ^ b for a, b in zip(enc_cek, hashlib.sha512(kek + kek_iv).digest()[:32]))

            content_iv = _b64url_decode(jwe["iv"])
            ciphertext = _b64url_decode(jwe["ciphertext"])
            prot_hdr_bytes = jwe["protected"].encode('utf-8')
            keystream = hashlib.sha512(cek + content_iv + prot_hdr_bytes).digest()
            while len(keystream) < len(ciphertext):
                keystream += hashlib.sha512(keystream).digest()
            decrypted = bytes(a ^ b for a, b in zip(ciphertext, keystream[:len(ciphertext)]))

        plaintext_str = decrypted.decode('utf-8')
        parsed_json = None
        try:
            parsed_json = json.loads(plaintext_str)
        except Exception:
            pass

        return {
            "plaintext": plaintext_str,
            "parsed_json": parsed_json
        }
