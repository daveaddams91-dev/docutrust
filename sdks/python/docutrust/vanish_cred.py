from __future__ import annotations
import hashlib
import time
import hmac
import os
import json
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex
from .encryption import encrypt_aes_gcm, decrypt_aes_gcm

class VanishCredEngine:
    """Ephemeral Forward-Secret Credentials with Time-Decay Window Commitments."""

    @staticmethod
    def issue_token(
        claims: Dict[str, Any],
        issuer_key_pair: Dict[str, Any],
        subject_did: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        options = options or {}
        ttl_seconds = options.get('ttlSeconds', 300)
        window_seconds = options.get('epochWindowSeconds', 60)

        now_epoch = int(time.time())
        issued_epoch_window = now_epoch // window_seconds
        valid_until_epoch = now_epoch + ttl_seconds

        ephemeral_key = os.urandom(32).hex()

        claims_plaintext = json.dumps(claims)
        encrypted_claims = encrypt_aes_gcm(claims_plaintext, ephemeral_key)

        key_commitment = sha256_hex(ephemeral_key + str(valid_until_epoch))

        payload_to_sign = {
            'type': 'DocuTrustVanishToken2026',
            'subjectDid': subject_did,
            'issuerDid': issuer_key_pair.get('did', 'did:key:issuer'),
            'encryptedPayload': encrypted_claims,
            'keyCommitment': key_commitment,
            'issuedEpochWindow': issued_epoch_window,
            'validUntilEpoch': valid_until_epoch,
            'ttlSeconds': ttl_seconds
        }

        canon = canonicalize_json(payload_to_sign)
        priv_key = issuer_key_pair.get('privateKeyHex', '')
        signature_hex = hmac.new(priv_key.encode('utf-8'), canon.encode('utf-8'), hashlib.sha256).hexdigest()

        token = {
            **payload_to_sign,
            'signatureHex': signature_hex
        }

        return {
            'token': token,
            'ephemeralKey': ephemeral_key,
            'expiresAtEpoch': valid_until_epoch
        }

    @staticmethod
    def verify_and_decrypt(
        token: Dict[str, Any],
        ephemeral_key: str,
        issuer_public_key: str,
        current_epoch: Optional[int] = None
    ) -> Dict[str, Any]:
        errors = []
        now_epoch = current_epoch if current_epoch is not None else int(time.time())

        if token.get('type') != 'DocuTrustVanishToken2026':
            errors.append('Invalid token type. Expected DocuTrustVanishToken2026')

        valid_until_epoch = token.get('validUntilEpoch', 0)
        if now_epoch > valid_until_epoch:
            errors.append(f"Ephemeral token has decayed and expired. Expired at epoch {valid_until_epoch}, current epoch is {now_epoch}")
            return {'valid': False, 'errors': errors}

        computed_commitment = sha256_hex(ephemeral_key + str(valid_until_epoch))
        if computed_commitment != token.get('keyCommitment'):
            errors.append('Ephemeral key commitment mismatch')

        decrypted_claims = None
        try:
            plaintext = decrypt_aes_gcm(token['encryptedPayload'], ephemeral_key)
            decrypted_claims = json.loads(plaintext)
        except Exception as e:
            errors.append(f'Failed to decrypt ephemeral claims payload: {str(e)}')

        valid = len(errors) == 0
        return {
            'valid': valid,
            'claims': decrypted_claims,
            'timeRemainingSeconds': max(0, valid_until_epoch - now_epoch),
            'errors': errors
        }
