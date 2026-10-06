from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class PqMixin:

    def pq_ratchet_generate_keys(self) -> Dict[str, Any]:
        """Generates a hybrid classical + post-quantum ratchet key pair."""
        from .pq_ratchet import PQRatchetEngine
        return PQRatchetEngine.generate_ratchet_key_pair()

    def pq_ratchet_init_initiator(
        self,
        bob_combined_public_key: str,
        initial_shared_secret_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Initializes a Double Ratchet session for the Initiator."""
        from .pq_ratchet import PQRatchetEngine
        return PQRatchetEngine.init_initiator_session(bob_combined_public_key, initial_shared_secret_hex)

    def pq_ratchet_init_responder(
        self,
        bob_key_pair: Dict[str, Any],
        initial_shared_secret_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Initializes a Double Ratchet session for the Responder."""
        from .pq_ratchet import PQRatchetEngine
        return PQRatchetEngine.init_responder_session(bob_key_pair, initial_shared_secret_hex)

    def pq_ratchet_encrypt(
        self,
        session: Dict[str, Any],
        payload: Union[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Encrypts payload with current sending chain message key."""
        from .pq_ratchet import PQRatchetEngine
        return PQRatchetEngine.encrypt(session, payload)

    def pq_ratchet_decrypt(
        self,
        session: Dict[str, Any],
        message: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Decrypts message, advancing ratchet if new ratchet key received."""
        from .pq_ratchet import PQRatchetEngine
        return PQRatchetEngine.decrypt(session, message)

    def pq_blind_generate_keypair(self) -> Dict[str, Any]:
        """Generates a Post-Quantum Blind Signer keypair."""
        from .pq_blind import PQBlindSignatureEngine
        return PQBlindSignatureEngine.generate_keypair()

    def pq_blind_message(
        self,
        message: Any,
        signer_key: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Blinds a message using secret scalar beta before sending to signer."""
        from .pq_blind import PQBlindSignatureEngine
        return PQBlindSignatureEngine.blind_message(message, signer_key)

    def pq_blind_sign(
        self,
        request: Dict[str, Any],
        signer_key: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Signer blind-signs the blinded commitment without knowing message contents."""
        from .pq_blind import PQBlindSignatureEngine
        return PQBlindSignatureEngine.sign_blinded_message(request, signer_key)

    def pq_blind_unblind(
        self,
        message_hash: str,
        blind_response: Dict[str, Any],
        blinding_secret_hex: str,
        signer_key: Dict[str, Any]
    ) -> Dict[str, Any]:
        """User unblinds the blind signature to obtain a valid public signature."""
        from .pq_blind import PQBlindSignatureEngine
        return PQBlindSignatureEngine.unblind_signature(message_hash, blind_response, blinding_secret_hex, signer_key)

    def pq_blind_verify(
        self,
        message: Any,
        receipt: Dict[str, Any],
        public_key_hex: str
    ) -> Dict[str, Any]:
        """Verifies an unblinded Post-Quantum signature."""
        from .pq_blind import PQBlindSignatureEngine
        return PQBlindSignatureEngine.verify_signature(message, receipt, public_key_hex)

    def pq_abe_setup(
        self,
        authority_id: str,
        authority_name: str
    ) -> Dict[str, Any]:
        """Initializes a decentralized attribute authority with post-quantum lattice master keys."""
        from .pq_abe import PQAbeEngine
        return PQAbeEngine.setup_authority(authority_id, authority_name)

    def pq_abe_issue_token(
        self,
        authority: Dict[str, Any],
        user_did: str,
        attribute: str,
        expiration_epoch: Optional[int] = None
    ) -> Dict[str, Any]:
        """Issues a post-quantum lattice attribute secret token to a specific user DID."""
        from .pq_abe import PQAbeEngine
        return PQAbeEngine.issue_attribute_token(authority, user_did, attribute, expiration_epoch)

    def pq_abe_encrypt(
        self,
        payload: Any,
        policy_expression: str,
        authorities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Encrypts data under a multi-authority monotone Boolean access policy."""
        from .pq_abe import PQAbeEngine
        return PQAbeEngine.encrypt(payload, policy_expression, authorities)

    def pq_abe_decrypt(
        self,
        ciphertext: Dict[str, Any],
        user_tokens: List[Dict[str, Any]],
        user_did: str
    ) -> Dict[str, Any]:
        """Decrypts a post-quantum lattice ciphertext using user attribute tokens."""
        from .pq_abe import PQAbeEngine
        return PQAbeEngine.decrypt(ciphertext, user_tokens, user_did)
