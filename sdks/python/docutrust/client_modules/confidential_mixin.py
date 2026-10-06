from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class ConfidentialMixin:

    def confidential_shuffle_keygen(self) -> Dict[str, Any]:
        """Generates ElGamal homomorphic encryption keypair."""
        from .confidential_shuffle import ConfidentialShuffleEngine
        return ConfidentialShuffleEngine.generate_keypair()

    def confidential_shuffle_batch(
        self,
        plaintexts: List[str],
        public_key: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Encrypts plaintexts, permutes them, applies homomorphic re-randomization, and constructs a ZK shuffle argument."""
        from .confidential_shuffle import ConfidentialShuffleEngine
        return ConfidentialShuffleEngine.shuffle_and_rerandomize(plaintexts, public_key)

    def confidential_shuffle_verify(
        self,
        input_ciphertexts: List[Dict[str, Any]],
        shuffled_ciphertexts: List[Dict[str, Any]],
        proof: Dict[str, Any],
        public_key: Dict[str, Any]
    ) -> bool:
        """Verifies zero-knowledge shuffle proof and length conservation."""
        from .confidential_shuffle import ConfidentialShuffleEngine
        return ConfidentialShuffleEngine.verify_shuffle(input_ciphertexts, shuffled_ciphertexts, proof, public_key)

    def confidential_shuffle_decrypt(
        self,
        ciphertexts: List[Dict[str, Any]],
        secret_key: str
    ) -> List[str]:
        """Decrypts a batch of ElGamal ciphertexts."""
        from .confidential_shuffle import ConfidentialShuffleEngine
        return ConfidentialShuffleEngine.batch_decrypt(ciphertexts, secret_key)
