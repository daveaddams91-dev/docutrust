from __future__ import annotations
import base64
import hashlib
import json
import os
import struct
from typing import Dict, Any, Union, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from .crypto import canonicalize_json, encode_base58, decode_base58

WEBAUTHN_MULTICODEC_PREFIX = bytes([0x12, 0x01])

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(s: str) -> bytes:
    padding = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)

class WebAuthnAttestationEngine:
    """WebAuthn / FIDO2 Passkey Hardware Attestation Engine with P-256 / ES256."""

    @staticmethod
    def generate_key_pair(rp_id: str = "localhost") -> Dict[str, Any]:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        pub_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        priv_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        raw_pub = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        credential_id_bytes = os.urandom(32)
        credential_id = base64url_encode(credential_id_bytes)

        multicodec = WEBAUTHN_MULTICODEC_PREFIX + raw_pub
        did = f'did:webauthn:z{encode_base58(multicodec)}'

        return {
            'algorithm': 'ES256',
            'curve': 'P-256',
            'credentialId': credential_id,
            'rpId': rp_id,
            'publicKeyHex': raw_pub.hex(),
            'privateKeyHex': priv_der.hex(),
            'publicKeyPem': pub_pem,
            'privateKeyPem': priv_pem,
            'did': did
        }

    @staticmethod
    def create_assertion(
        challenge: str,
        key_pair: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        options = options or {}
        rp_id = options.get('rpId') or key_pair.get('rpId', 'localhost')
        origin = options.get('origin', f'https://{rp_id}')
        user_verified = options.get('userVerified', True)
        sign_count = options.get('signCount', 1)

        client_data = {
            'type': 'webauthn.get',
            'challenge': challenge,
            'origin': origin,
            'crossOrigin': False
        }
        client_data_json = json.dumps(client_data, separators=(',', ':'))
        client_data_hash = hashlib.sha256(client_data_json.encode('utf-8')).digest()

        rp_id_hash = hashlib.sha256(rp_id.encode('utf-8')).digest()
        flags = 0x01  # UP
        if user_verified:
            flags |= 0x04  # UV

        auth_data = rp_id_hash + bytes([flags]) + struct.pack('>I', sign_count)
        sign_payload = auth_data + client_data_hash

        # Sign using private key
        priv_pem = key_pair.get('privateKeyPem')
        if priv_pem:
            private_key = serialization.load_pem_private_key(priv_pem.encode('utf-8'), password=None)
        else:
            priv_bytes = bytes.fromhex(key_pair['privateKeyHex'])
            private_key = serialization.load_der_private_key(priv_bytes, password=None)

        sig_der = private_key.sign(sign_payload, ec.ECDSA(hashes.SHA256()))

        return {
            'type': 'DocuTrustWebAuthnAssertion2026',
            'credentialId': key_pair.get('credentialId', ''),
            'clientDataJSON': base64url_encode(client_data_json.encode('utf-8')),
            'authenticatorData': base64url_encode(auth_data),
            'signature': base64url_encode(sig_der),
            'userHandle': options.get('userHandle') or key_pair.get('did', '')
        }

    @staticmethod
    def verify_assertion(
        assertion: Dict[str, Any],
        expected_challenge: str,
        public_key: Union[Dict[str, Any], str],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        options = options or {}
        errors = []

        try:
            client_data_bytes = base64url_decode(assertion['clientDataJSON'])
            client_data = json.loads(client_data_bytes.decode('utf-8'))
            client_data_hash = hashlib.sha256(client_data_bytes).digest()

            if client_data.get('type') != 'webauthn.get':
                errors.append(f"Invalid clientData type: expected webauthn.get, got {client_data.get('type')}")

            if client_data.get('challenge') != expected_challenge:
                errors.append(f"Challenge mismatch: expected {expected_challenge}, got {client_data.get('challenge')}")

            auth_data = base64url_decode(assertion['authenticatorData'])
            if len(auth_data) < 37:
                errors.append("Invalid authenticatorData length (must be at least 37 bytes)")

            rp_id_hash = auth_data[:32]
            flags = auth_data[32]
            sign_count = struct.unpack('>I', auth_data[33:37])[0]

            user_present = bool(flags & 0x01)
            user_verified = bool(flags & 0x04)

            if not user_present:
                errors.append("User Presence (UP) flag not set")

            expected_rp_id = options.get('expectedRpId')
            if expected_rp_id:
                expected_rp_hash = hashlib.sha256(expected_rp_id.encode('utf-8')).digest()
                if rp_id_hash != expected_rp_hash:
                    errors.append(f"RP ID Hash mismatch for {expected_rp_id}")

            sign_payload = auth_data + client_data_hash
            sig_der = base64url_decode(assertion['signature'])

            # Public key parsing
            if isinstance(public_key, dict) and public_key.get('publicKeyPem'):
                pub_obj = serialization.load_pem_public_key(public_key['publicKeyPem'].encode('utf-8'))
            elif isinstance(public_key, dict) and public_key.get('publicKeyHex'):
                pub_bytes = bytes.fromhex(public_key['publicKeyHex'])
                pub_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
            elif isinstance(public_key, str) and public_key.startswith('did:webauthn:z'):
                raw = decode_base58(public_key[14:])
                pub_bytes = raw[2:]
                pub_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
            elif isinstance(public_key, str):
                pub_bytes = bytes.fromhex(public_key)
                pub_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
            else:
                raise ValueError("Unsupported public key format")

            pub_obj.verify(sig_der, sign_payload, ec.ECDSA(hashes.SHA256()))

            return {
                'valid': len(errors) == 0,
                'userPresent': user_present,
                'userVerified': user_verified,
                'signCount': sign_count,
                'errors': errors
            }
        except Exception as e:
            errors.append(str(e))
            return {
                'valid': False,
                'userPresent': False,
                'userVerified': False,
                'signCount': 0,
                'errors': errors
            }
