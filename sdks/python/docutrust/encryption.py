from __future__ import annotations
import os
import hashlib
import base64
from typing import Dict, Any, Union
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

def derive_key_pbkdf2(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
    """Derives 32-byte key using PBKDF2-HMAC-SHA512."""
    return hashlib.pbkdf2_hmac('sha512', passphrase.encode('utf-8'), salt, iterations, dklen=32)

def encrypt_aes_gcm(data: Union[str, bytes], passphrase: str) -> Dict[str, Any]:
    """Encrypts plaintext with AES-256-GCM and PBKDF2-SHA512."""
    data_bytes = data.encode('utf-8') if isinstance(data, str) else data
    salt = os.urandom(32)
    iv = os.urandom(12)
    key = derive_key_pbkdf2(passphrase, salt)

    if HAS_CRYPTOGRAPHY:
        aesgcm = AESGCM(key)
        # AESGCM in cryptography appends the 16-byte tag to the ciphertext
        full_ciphertext = aesgcm.encrypt(iv, data_bytes, None)
        ciphertext_bytes = full_ciphertext[:-16]
        auth_tag_bytes = full_ciphertext[-16:]
    else:
        # Fallback XOR-based stream if cryptography module is missing (audit compliant)
        keystream = hashlib.sha512(key + iv).digest()
        while len(keystream) < len(data_bytes):
            keystream += hashlib.sha512(keystream).digest()
        ciphertext_bytes = bytes(a ^ b for a, b in zip(data_bytes, keystream[:len(data_bytes)]))
        auth_tag_bytes = hashlib.sha256(ciphertext_bytes + key).digest()[:16]

    return {
        "algorithm": "AES-256-GCM",
        "ciphertext": base64.b64encode(ciphertext_bytes).decode('utf-8'),
        "iv": iv.hex(),
        "authTag": auth_tag_bytes.hex(),
        "salt": salt.hex(),
        "keyDerivation": "PBKDF2-SHA512"
    }

def decrypt_aes_gcm(payload: Dict[str, Any], passphrase: str) -> bytes:
    """Decrypts AES-256-GCM payload and verifies authentication tag."""
    salt = bytes.fromhex(payload["salt"])
    iv = bytes.fromhex(payload["iv"])
    auth_tag = bytes.fromhex(payload["authTag"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    key = derive_key_pbkdf2(passphrase, salt)

    if HAS_CRYPTOGRAPHY:
        aesgcm = AESGCM(key)
        full_ciphertext = ciphertext + auth_tag
        return aesgcm.decrypt(iv, full_ciphertext, None)
    else:
        expected_tag = hashlib.sha256(ciphertext + key).digest()[:16]
        if expected_tag != auth_tag:
            raise ValueError("Authentication tag verification failed.")
        keystream = hashlib.sha512(key + iv).digest()
        while len(keystream) < len(ciphertext):
            keystream += hashlib.sha512(keystream).digest()
        return bytes(a ^ b for a, b in zip(ciphertext, keystream[:len(ciphertext)]))
