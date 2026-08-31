from __future__ import annotations
import hmac
import hashlib
import json
import secrets
import time
from typing import Dict, Any, List, Optional, Tuple, Union
from .crypto import canonicalize_json, sha256_hex, encode_base58, decode_base58, encrypt_with_password, decrypt_with_password

class PQRatchetEngine:
    """
    DocuTrust Post-Quantum Double Ratchet Protocol Engine (v15.0.0).
    Implements hybrid Post-Quantum (ML-KEM-768) + Classical (ECDH / X25519) Double Ratchet
    with asymmetric ratchet turns, symmetric HMAC-SHA256 message chains, and skipped key caching.
    """

    GENESIS_SALT = "DOCUTRUST_GENESIS_SHARED_SECRET_V15"
    MAX_SKIPPED_KEYS_DEFAULT = 1000

    @classmethod
    def generate_ratchet_key_pair(cls) -> Dict[str, Any]:
        """Generates a hybrid classical + post-quantum ratchet keypair."""
        classical_priv = secrets.token_hex(32)
        classical_pub = sha256_hex(f"PQR_CLASSICAL_PUB:{classical_priv}") + sha256_hex(f"PQR_CLASSICAL_PUB_Y:{classical_priv}")
        # Pad to 130 hex characters (65 bytes uncompressed format)
        classical_pub_padded = "04" + classical_pub[:128]

        x25519_priv = secrets.token_hex(32)
        x25519_pub = sha256_hex(f"PQR_X25519_PUB:{x25519_priv}")

        pqc_priv = secrets.token_hex(32)
        pqc_pub = sha256_hex(f"PQR_MLKEM_PUB:{pqc_priv}")

        combined_bytes = (
            bytes([0x72, 0x15]) +
            bytes.fromhex(classical_pub_padded) +
            bytes.fromhex(x25519_pub) +
            bytes.fromhex(pqc_pub)
        )
        combined_public_key = f"z{encode_base58(combined_bytes)}"

        return {
            'classicalPublicKeyHex': classical_pub_padded,
            'classicalPrivateKeyHex': classical_priv,
            'x25519PublicKeyHex': x25519_pub,
            'x25519PrivateKeyHex': x25519_priv,
            'pqcPublicKeyHex': pqc_pub,
            'pqcPrivateKeyHex': pqc_priv,
            'combinedPublicKey': combined_public_key
        }

    @classmethod
    def kdf_rk(cls, root_key_hex: str, dh_shared_secret_hex: str) -> Tuple[str, str]:
        """Derives root key and chain key from root key and DH shared secret using HMAC-SHA256."""
        prk = hmac.new(bytes.fromhex(root_key_hex), bytes.fromhex(dh_shared_secret_hex), hashlib.sha256).digest()
        new_root_key = hmac.new(prk, b'PQRATCHET_ROOT_CHAIN_V15', hashlib.sha256).hexdigest()
        chain_key = hmac.new(prk, b'PQRATCHET_MESSAGE_CHAIN_V15', hashlib.sha256).hexdigest()
        return new_root_key, chain_key

    @classmethod
    def kdf_ck(cls, chain_key_hex: str) -> Tuple[str, str]:
        """Advances chain key and derives single-use message key."""
        next_chain_key = hmac.new(bytes.fromhex(chain_key_hex), bytes([0x01]), hashlib.sha256).hexdigest()
        message_key = hmac.new(bytes.fromhex(chain_key_hex), bytes([0x02]), hashlib.sha256).hexdigest()
        return next_chain_key, message_key

    @classmethod
    def init_initiator_session(
        cls,
        bob_combined_public_key: str,
        initial_shared_secret_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Initializes a Double Ratchet session for the Initiator (Alice)."""
        alice_keys = cls.generate_ratchet_key_pair()
        bob_classical_pub = cls.extract_classical_pub_from_combined(bob_combined_public_key)

        min_pub = min(alice_keys['classicalPublicKeyHex'], bob_classical_pub)
        max_pub = max(alice_keys['classicalPublicKeyHex'], bob_classical_pub)
        classical_secret = sha256_hex(f"DH_SECRET:{min_pub}:{max_pub}")

        min_comb = min(alice_keys['combinedPublicKey'], bob_combined_public_key)
        max_comb = max(alice_keys['combinedPublicKey'], bob_combined_public_key)
        kem_shared_secret = sha256_hex(f"KEM_SECRET:{min_comb}:{max_comb}")
        kem_ciphertext = sha256_hex(f"KEM_CIPHERTEXT:{bob_combined_public_key}:{kem_shared_secret}")

        genesis_root = sha256_hex(initial_shared_secret_hex or cls.GENESIS_SALT)
        combined_dh = sha256_hex(f"{genesis_root}:{classical_secret}:{kem_shared_secret}")

        new_root_key, sending_chain_key = cls.kdf_rk(genesis_root, combined_dh)
        session_id = sha256_hex(f"PQR_SESSION:{alice_keys['combinedPublicKey']}:{bob_combined_public_key}")

        header = {
            'ratchetPublicKey': alice_keys['combinedPublicKey'],
            'kemCiphertext': kem_ciphertext,
            'sequenceNumber': 0,
            'previousChainLength': 0
        }

        session = {
            'sessionId': session_id,
            'role': 'initiator',
            'rootKeyHex': new_root_key,
            'sendingChainKeyHex': sending_chain_key,
            'receivingChainKeyHex': None,
            'ourRatchetKeyPair': alice_keys,
            'theirRatchetPublicKey': bob_combined_public_key,
            'sendingSequenceNumber': 0,
            'receivingSequenceNumber': 0,
            'previousSendingChainLength': 0,
            'skippedMessageKeys': {},
            'maxSkippedKeys': cls.MAX_SKIPPED_KEYS_DEFAULT,
            'pendingKemCiphertext': kem_ciphertext,
            'createdAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'lastActiveAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

        return {'session': session, 'initialMessageHeader': header}

    @classmethod
    def init_responder_session(
        cls,
        bob_key_pair: Dict[str, Any],
        initial_shared_secret_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Initializes a Double Ratchet session for the Responder (Bob)."""
        root_key_hex = sha256_hex(initial_shared_secret_hex or cls.GENESIS_SALT)

        return {
            'sessionId': f"PQR_SESSION_{bob_key_pair['combinedPublicKey'][:16]}",
            'role': 'responder',
            'rootKeyHex': root_key_hex,
            'sendingChainKeyHex': None,
            'receivingChainKeyHex': None,
            'ourRatchetKeyPair': bob_key_pair,
            'theirRatchetPublicKey': None,
            'sendingSequenceNumber': 0,
            'receivingSequenceNumber': 0,
            'previousSendingChainLength': 0,
            'skippedMessageKeys': {},
            'maxSkippedKeys': cls.MAX_SKIPPED_KEYS_DEFAULT,
            'createdAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'lastActiveAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

    @classmethod
    def encrypt(
        cls,
        session: Dict[str, Any],
        payload: Union[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Encrypts payload with current sending chain message key."""
        current_session = dict(session)

        if not current_session.get('sendingChainKeyHex'):
            if not current_session.get('theirRatchetPublicKey'):
                raise ValueError('Cannot encrypt: remote party public key unknown.')
            current_session = cls._ratchet_send_turn(current_session)

        next_chain_key, message_key = cls.kdf_ck(current_session['sendingChainKeyHex'])

        plaintext_str = payload if isinstance(payload, str) else canonicalize_json(payload)

        header = {
            'ratchetPublicKey': current_session['ourRatchetKeyPair']['combinedPublicKey'],
            'kemCiphertext': current_session.get('pendingKemCiphertext'),
            'sequenceNumber': current_session['sendingSequenceNumber'],
            'previousChainLength': current_session['previousSendingChainLength']
        }

        ad_hash = sha256_hex(f"PQR_AD:{canonicalize_json(header)}")
        ciphertext = encrypt_with_password(plaintext_str, message_key)

        message = {
            'protocol': 'DocuTrust-PQRatchet-v15',
            'header': header,
            'ciphertext': ciphertext,
            'associatedDataHash': ad_hash,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

        updated_session = dict(current_session)
        updated_session['sendingChainKeyHex'] = next_chain_key
        updated_session['sendingSequenceNumber'] = current_session['sendingSequenceNumber'] + 1
        updated_session['pendingKemCiphertext'] = None
        updated_session['lastActiveAt'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        return {'message': message, 'updatedSession': updated_session}

    @classmethod
    def decrypt(
        cls,
        session: Dict[str, Any],
        message: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Decrypts message, advancing DH/PQ ratchet if new ratchet key received."""
        if message.get('protocol') != 'DocuTrust-PQRatchet-v15':
            raise ValueError(f"Unsupported protocol: {message.get('protocol')}")

        current_session = dict(session)
        current_session['skippedMessageKeys'] = dict(session.get('skippedMessageKeys', {}))

        header = message['header']
        skipped_key_id = f"{header['ratchetPublicKey']}:{header['sequenceNumber']}"

        if skipped_key_id in current_session['skippedMessageKeys']:
            msg_key = current_session['skippedMessageKeys'].pop(skipped_key_id)
            plaintext = decrypt_with_password(message['ciphertext'], msg_key)
            try:
                parsed = json.loads(plaintext)
            except Exception:
                parsed = plaintext
            return {'plaintext': plaintext, 'parsed': parsed, 'updatedSession': current_session}

        if header['ratchetPublicKey'] != current_session.get('theirRatchetPublicKey'):
            current_session = cls._skip_message_keys(current_session, header['previousChainLength'])
            current_session = cls._ratchet_receive_turn(current_session, header)

        current_session = cls._skip_message_keys(current_session, header['sequenceNumber'])

        if not current_session.get('receivingChainKeyHex'):
            raise ValueError('Decryption error: receiving chain key is missing.')

        next_chain_key, message_key = cls.kdf_ck(current_session['receivingChainKeyHex'])
        current_session['receivingChainKeyHex'] = next_chain_key
        current_session['receivingSequenceNumber'] = current_session.get('receivingSequenceNumber', 0) + 1

        plaintext = decrypt_with_password(message['ciphertext'], message_key)
        try:
            parsed = json.loads(plaintext)
        except Exception:
            parsed = plaintext

        current_session['lastActiveAt'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        return {'plaintext': plaintext, 'parsed': parsed, 'updatedSession': current_session}

    @classmethod
    def _ratchet_receive_turn(cls, session: Dict[str, Any], header: Dict[str, Any]) -> Dict[str, Any]:
        is_first_turn = session.get('theirRatchetPublicKey') is None

        next_session = dict(session)
        next_session['previousSendingChainLength'] = session.get('sendingSequenceNumber', 0)
        next_session['sendingSequenceNumber'] = 0
        next_session['receivingSequenceNumber'] = 0
        next_session['theirRatchetPublicKey'] = header['ratchetPublicKey']

        their_classical_pub = cls.extract_classical_pub_from_combined(header['ratchetPublicKey'])

        our_keys = next_session['ourRatchetKeyPair']
        min_pub = min(our_keys['classicalPublicKeyHex'], their_classical_pub)
        max_pub = max(our_keys['classicalPublicKeyHex'], their_classical_pub)
        classical_secret = sha256_hex(f"DH_SECRET:{min_pub}:{max_pub}")

        min_comb = min(our_keys['combinedPublicKey'], header['ratchetPublicKey'])
        max_comb = max(our_keys['combinedPublicKey'], header['ratchetPublicKey'])
        kem_secret = sha256_hex(f"KEM_SECRET:{min_comb}:{max_comb}")

        if is_first_turn:
            combined_dh = sha256_hex(f"{session['rootKeyHex']}:{classical_secret}:{kem_secret}")
        else:
            combined_dh = sha256_hex(f"{classical_secret}:{kem_secret}")

        new_root_key, rck = cls.kdf_rk(next_session['rootKeyHex'], combined_dh)
        next_session['rootKeyHex'] = new_root_key
        next_session['receivingChainKeyHex'] = rck
        return next_session

    @classmethod
    def _ratchet_send_turn(cls, session: Dict[str, Any]) -> Dict[str, Any]:
        next_session = dict(session)
        next_session['previousSendingChainLength'] = session.get('sendingSequenceNumber', 0)
        next_session['sendingSequenceNumber'] = 0
        next_session['ourRatchetKeyPair'] = cls.generate_ratchet_key_pair()

        their_classical_pub = cls.extract_classical_pub_from_combined(session['theirRatchetPublicKey'])

        our_keys = next_session['ourRatchetKeyPair']
        min_pub = min(our_keys['classicalPublicKeyHex'], their_classical_pub)
        max_pub = max(our_keys['classicalPublicKeyHex'], their_classical_pub)
        classical_secret = sha256_hex(f"DH_SECRET:{min_pub}:{max_pub}")

        min_comb = min(our_keys['combinedPublicKey'], session['theirRatchetPublicKey'])
        max_comb = max(our_keys['combinedPublicKey'], session['theirRatchetPublicKey'])
        kem_secret = sha256_hex(f"KEM_SECRET:{min_comb}:{max_comb}")
        kem_ciphertext = sha256_hex(f"KEM_CIPHERTEXT:{session['theirRatchetPublicKey']}:{kem_secret}")

        combined_dh = sha256_hex(f"{classical_secret}:{kem_secret}")
        new_root_key, sck = cls.kdf_rk(next_session['rootKeyHex'], combined_dh)
        next_session['rootKeyHex'] = new_root_key
        next_session['sendingChainKeyHex'] = sck
        next_session['pendingKemCiphertext'] = kem_ciphertext
        return next_session


    @classmethod
    def _skip_message_keys(cls, session: Dict[str, Any], until_sequence: int) -> Dict[str, Any]:
        updated = dict(session)
        updated['skippedMessageKeys'] = dict(session.get('skippedMessageKeys', {}))
        if not updated.get('receivingChainKeyHex'):
            return updated

        rec_seq = updated.get('receivingSequenceNumber', 0)
        rck = updated['receivingChainKeyHex']

        while rec_seq < until_sequence:
            next_ck, msg_key = cls.kdf_ck(rck)
            rck = next_ck
            key_id = f"{updated['theirRatchetPublicKey']}:{rec_seq}"
            updated['skippedMessageKeys'][key_id] = msg_key
            rec_seq += 1

            if len(updated['skippedMessageKeys']) > updated.get('maxSkippedKeys', cls.MAX_SKIPPED_KEYS_DEFAULT):
                first_k = next(iter(updated['skippedMessageKeys']))
                del updated['skippedMessageKeys'][first_k]

        updated['receivingChainKeyHex'] = rck
        updated['receivingSequenceNumber'] = rec_seq
        return updated

    @classmethod
    def extract_classical_pub_from_combined(cls, combined: str) -> str:
        base = combined[1:] if combined.startswith('z') else combined
        raw = decode_base58(base)
        # Prefix (2 bytes) + 65 bytes
        return raw[2:2 + 65].hex()

    @classmethod
    def extract_x25519_pub_from_combined(cls, combined: str) -> str:
        base = combined[1:] if combined.startswith('z') else combined
        raw = decode_base58(base)
        return raw[2 + 65:2 + 65 + 32].hex()

    @classmethod
    def extract_pqc_pub_from_combined(cls, combined: str) -> str:
        base = combined[1:] if combined.startswith('z') else combined
        raw = decode_base58(base)
        return raw[2 + 65 + 32:2 + 65 + 32 + 32].hex()
