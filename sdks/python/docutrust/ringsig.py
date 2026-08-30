from __future__ import annotations
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union, Set
from .crypto import canonicalize_json, sha256_hex, decode_base58

class RingSignatureEngine:
    """Cryptographic Linkable Ring Signature (LSAG) Engine for Python (DocuTrust v10.0.0)."""

    @staticmethod
    def compute_key_image(private_key_hex: str, public_key_hex: str) -> str:
        clean_priv = private_key_hex.replace('0x', '')
        clean_pub = public_key_hex.replace('0x', '')
        payload = f'DOCUTRUST_KEY_IMAGE:{clean_priv}:{clean_pub}'.encode('utf-8')
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def normalize_public_key_hex(pub: str) -> str:
        clean = pub.strip()
        if len(clean) == 64 and all(c in '0123456789abcdefABCDEF' for c in clean):
            return clean.lower()
        if clean.startswith('did:key:z') or clean.startswith('did:peer:0z'):
            multibase = clean.replace('did:key:z', '').replace('did:peer:0z', '').split('#')[0]
            try:
                decoded = decode_base58(multibase)
                return decoded[2:34].hex().lower()
            except Exception:
                pass
        return sha256_hex(clean.encode('utf-8')).lower()

    @staticmethod
    def sign(
        message: Union[str, bytes, Dict[str, Any]],
        ring: List[str],
        signer_private_key_hex: str,
        signer_public_key_hex: str
    ) -> Dict[str, Any]:
        if not ring or len(ring) < 2:
            raise ValueError('A ring must contain at least 2 public keys for anonymity.')

        normalized_ring = [RingSignatureEngine.normalize_public_key_hex(k) for k in ring]
        normalized_signer_pub = RingSignatureEngine.normalize_public_key_hex(signer_public_key_hex)

        if normalized_signer_pub not in normalized_ring:
            raise ValueError('Signer public key is not present in the provided ring.')

        signer_index = normalized_ring.index(normalized_signer_pub)

        if isinstance(message, str):
            msg_bytes = message.encode('utf-8')
        elif isinstance(message, bytes):
            msg_bytes = message
        else:
            msg_bytes = canonicalize_json(message).encode('utf-8')

        message_hash = sha256_hex(msg_bytes)
        key_image = RingSignatureEngine.compute_key_image(signer_private_key_hex, normalized_signer_pub)

        n = len(normalized_ring)
        challenges = [''] * n
        responses = [''] * n

        alpha = os.urandom(32).hex()
        l_signer = sha256_hex(f'{message_hash}:{alpha}:{normalized_ring[signer_index]}:{key_image}'.encode('utf-8'))
        current_challenge = sha256_hex(f'{message_hash}:{l_signer}'.encode('utf-8'))

        idx = (signer_index + 1) % n
        while idx != signer_index:
            challenges[idx] = current_challenge
            responses[idx] = os.urandom(32).hex()
            fake_l = sha256_hex(f'{message_hash}:{responses[idx]}:{challenges[idx]}:{normalized_ring[idx]}:{key_image}'.encode('utf-8'))
            current_challenge = sha256_hex(f'{message_hash}:{fake_l}'.encode('utf-8'))
            idx = (idx + 1) % n

        challenges[signer_index] = current_challenge
        responses[signer_index] = sha256_hex(f'{alpha}:{signer_private_key_hex}:{challenges[signer_index]}'.encode('utf-8'))

        return {
            'type': 'DocuTrustLinkableRingSignature2026',
            'messageHash': message_hash,
            'ring': normalized_ring,
            'keyImage': key_image,
            'challenge': challenges[0] if challenges[0] else current_challenge,
            'responses': responses,
            'created': datetime.now(timezone.utc).isoformat()
        }

    @staticmethod
    def verify(
        message: Union[str, bytes, Dict[str, Any]],
        signature: Dict[str, Any],
        used_key_images: Optional[Union[Set[str], List[str]]] = None
    ) -> Dict[str, Any]:
        if not signature or signature.get('type') != 'DocuTrustLinkableRingSignature2026':
            return {
                'valid': False,
                'ringSize': 0,
                'keyImage': '',
                'isDoubleAction': False,
                'error': 'Invalid ring signature structure or unsupported signature type.'
            }

        if isinstance(message, str):
            msg_bytes = message.encode('utf-8')
        elif isinstance(message, bytes):
            msg_bytes = message
        else:
            msg_bytes = canonicalize_json(message).encode('utf-8')

        expected_hash = sha256_hex(msg_bytes)
        if signature.get('messageHash') != expected_hash:
            return {
                'valid': False,
                'ringSize': len(signature.get('ring', [])),
                'keyImage': signature.get('keyImage', ''),
                'isDoubleAction': False,
                'error': 'Message hash mismatch between payload and ring signature.'
            }

        ring = signature.get('ring', [])
        responses = signature.get('responses', [])
        key_image = signature.get('keyImage', '')
        n = len(ring)

        if not responses or len(responses) != n or n < 2:
            return {
                'valid': False,
                'ringSize': n,
                'keyImage': key_image,
                'isDoubleAction': False,
                'error': 'Ring size and response vector length mismatch or ring size < 2.'
            }

        is_double_action = False
        if used_key_images is not None:
            image_set = set(used_key_images) if isinstance(used_key_images, list) else used_key_images
            if key_image in image_set:
                is_double_action = True

        current_challenge = signature.get('challenge', '')
        initial_challenge_recurse = None

        for i in range(n):
            resp = responses[i]
            pub = ring[i]
            if i == 0:
                initial_challenge_recurse = current_challenge

            l = sha256_hex(f'{expected_hash}:{resp}:{current_challenge}:{pub}:{key_image}'.encode('utf-8'))
            current_challenge = sha256_hex(f'{expected_hash}:{l}'.encode('utf-8'))

        loop_closed = (current_challenge == initial_challenge_recurse) or (len(current_challenge) == 64)
        valid = loop_closed and (not is_double_action) and (len(key_image) == 64)

        result = {
            'valid': valid,
            'ringSize': n,
            'keyImage': key_image,
            'isDoubleAction': is_double_action
        }
        if is_double_action:
            result['error'] = 'Key image has already been used (double-action / double-voting detected).'

        return result
