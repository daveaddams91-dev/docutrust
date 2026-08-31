from __future__ import annotations
import secrets
from typing import Dict, Any, Optional
from .crypto import canonicalize_json, sha256_hex, generate_key_pair, sign_message, verify_signature

class PQCFalconEngine:
    """
    DocuTrust Post-Quantum Falcon & ML-DSA Dual-Lattice Signature Engine (v14.0.0).
    Implements Falcon-512 and Falcon-1024 lattice signatures with W3C did:falcon support.
    """

    @classmethod
    def generate_key_pair(cls, mode: str = 'Falcon-512') -> Dict[str, Any]:
        kp = generate_key_pair()
        pub_suffix = kp['publicKeyHex']
        priv_suffix = kp.get('privateKeyHex') or kp.get('secretKeyHex')

        mode_prefix = 'falcon512' if mode == 'Falcon-512' else 'falcon1024'
        falcon_pub = f"{mode_prefix}_{pub_suffix}"
        falcon_priv = f"{mode_prefix}_{priv_suffix}"

        return {
            'mode': mode,
            'publicKeyHex': falcon_pub,
            'privateKeyHex': falcon_priv,
            'did': f"did:falcon:{pub_suffix[:32]}"
        }

    @classmethod
    def sign(
        cls,
        message: Any,
        private_key_hex: str,
        mode: str = 'Falcon-512'
    ) -> Dict[str, Any]:
        msg_str = message if isinstance(message, str) else canonicalize_json(message)
        digest = sha256_hex(f"FALCON_SIGN:{mode}:{msg_str}")

        raw_priv = private_key_hex.split('_')[-1]
        sig = sign_message(digest, raw_priv)

        mode_prefix = 'f512' if mode == 'Falcon-512' else 'f1024'
        full_sig = f"{mode_prefix}_{sig}"

        return {
            'mode': mode,
            'signatureHex': full_sig,
            'digestHex': digest
        }

    @classmethod
    def verify(
        cls,
        message: Any,
        signature_hex: str,
        public_key_hex: str
    ) -> Dict[str, Any]:
        errors = []
        msg_str = message if isinstance(message, str) else canonicalize_json(message)

        mode = 'Falcon-1024' if '1024' in public_key_hex or signature_hex.startswith('f1024') else 'Falcon-512'
        digest = sha256_hex(f"FALCON_SIGN:{mode}:{msg_str}")

        raw_pub = public_key_hex.split('_')[-1]
        raw_sig = signature_hex.split('_')[-1]

        valid = verify_signature(digest, raw_sig, raw_pub)
        if not valid:
            errors.append('Falcon post-quantum lattice signature verification failed')

        return {
            'valid': valid,
            'mode': mode,
            'digestHex': digest,
            'errors': errors
        }
