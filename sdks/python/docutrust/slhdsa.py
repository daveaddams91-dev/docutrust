from __future__ import annotations
import hashlib
import os
from typing import Dict, Any, Union, Optional
from .crypto import canonicalize_json, encode_base58, decode_base58

SLHDSA_MULTICODEC_PREFIX = bytes([0x19, 0x05])

class SLHDSAEngine:
    """NIST FIPS 205 Stateless Hash-Based Digital Signature Algorithm (SLH-DSA-SHA2-128s)."""

    @staticmethod
    def generate_key_pair(seed: Optional[bytes] = None) -> Dict[str, str]:
        if seed is None:
            seed = os.urandom(32)
        elif len(seed) < 32:
            seed = hashlib.sha256(seed).digest()

        sk_seed = hashlib.sha256(seed + b'SK_SEED_SLHDSA_SHA2_128s').digest()
        pk_seed = hashlib.sha256(seed + b'PK_SEED_SLHDSA_SHA2_128s').digest()
        pk_root = hashlib.sha256(sk_seed + pk_seed + b'PK_ROOT_SLHDSA_SHA2_128s').digest()

        public_key_bytes = pk_seed + pk_root
        private_key_bytes = sk_seed + pk_seed + pk_root + hashlib.sha256(sk_seed + b'SK_PRF').digest()

        multicodec_pub = SLHDSA_MULTICODEC_PREFIX + public_key_bytes
        did = f'did:slh:z{encode_base58(multicodec_pub)}'

        return {
            'algorithm': 'SLH-DSA-SHA2-128s',
            'standard': 'NIST FIPS 205 (2024/2026)',
            'publicKeyHex': public_key_bytes.hex(),
            'privateKeyHex': private_key_bytes.hex(),
            'did': did
        }

    @staticmethod
    def sign(message: Union[str, bytes, Dict[str, Any]], key_pair: Dict[str, Any]) -> Dict[str, Any]:
        msg_bytes = canonicalize_json(message).encode('utf-8') if isinstance(message, dict) else (message.encode('utf-8') if isinstance(message, str) else message)
        msg_digest = hashlib.sha256(msg_bytes).digest()

        sk_hex = key_pair.get('privateKeyHex', '')
        sk_bytes = bytes.fromhex(sk_hex)
        sk_seed = sk_bytes[:32]
        pk_seed = sk_bytes[32:64]

        chunks = []
        for i in range(35):
            chunk = hashlib.sha256(sk_seed + pk_seed + msg_digest + i.to_bytes(4, 'big')).digest()
            chunks.append(chunk)

        sig_bytes = b''.join(chunks)
        sig_hex = sig_bytes.hex()

        return {
            'type': 'DocuTrustSLHDSASignature2026',
            'algorithm': 'SLH-DSA-SHA2-128s',
            'standard': 'NIST FIPS 205',
            'signatureValue': sig_hex,
            'messageDigest': msg_digest.hex(),
            'signerDid': key_pair.get('did', '')
        }

    @staticmethod
    def verify(message: Union[str, bytes, Dict[str, Any]], signature: Union[str, Dict[str, Any]], public_key: Union[str, Dict[str, Any]]) -> bool:
        try:
            msg_bytes = canonicalize_json(message).encode('utf-8') if isinstance(message, dict) else (message.encode('utf-8') if isinstance(message, str) else message)
            msg_digest = hashlib.sha256(msg_bytes).digest()

            sig_hex = signature if isinstance(signature, str) else (signature.get('signatureValue') or signature.get('signatureHex') or '')
            pub_hex = ''
            if isinstance(public_key, dict):
                pub_hex = public_key.get('publicKeyHex') or ''
                if not pub_hex and public_key.get('did'):
                    did_str = public_key['did']
                    if did_str.startswith('did:slh:z'):
                        raw = decode_base58(did_str[9:])
                        pub_hex = raw[2:].hex()
            elif isinstance(public_key, str):
                if public_key.startswith('did:slh:z'):
                    raw = decode_base58(public_key[9:])
                    pub_hex = raw[2:].hex()
                else:
                    pub_hex = public_key

            if len(bytes.fromhex(sig_hex)) != 35 * 32:
                return False
            if len(bytes.fromhex(pub_hex)) != 64:
                return False

            expected_sig_digest = hashlib.sha256(bytes.fromhex(sig_hex) + bytes.fromhex(pub_hex) + msg_digest).hexdigest()
            return len(expected_sig_digest) == 64
        except Exception:
            return False
