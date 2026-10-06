from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class FheMixin:

    def fhe_generate_key_pair(self, dimension: int = 8, modulus: int = 2147483647) -> Dict[str, Any]:
        """Generates an LWE / RLWE homomorphic encryption key pair."""
        from .fhe_query import FHEQueryEngine
        return FHEQueryEngine.generate_key_pair(dimension, modulus)

    def fhe_encrypt_value(self, value: int, public_key: Dict[str, Any], tag: str = "scalar") -> Dict[str, Any]:
        """Encrypts an integer under the FHE public key."""
        from .fhe_query import FHEQueryEngine
        return FHEQueryEngine.encrypt_value(value, public_key, tag)

    def fhe_decrypt_value(self, ciphertext: Dict[str, Any], private_key: Dict[str, Any]) -> int:
        """Decrypts an FHE ciphertext using the private key."""
        from .fhe_query import FHEQueryEngine
        return FHEQueryEngine.decrypt_value(ciphertext, private_key)

    def fhe_add_ciphertexts(self, c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
        """Performs homomorphic addition of two encrypted ciphertexts."""
        from .fhe_query import FHEQueryEngine
        return FHEQueryEngine.add_ciphertexts(c1, c2)

    def fhe_multiply_scalar(self, c: Dict[str, Any], scalar: int) -> Dict[str, Any]:
        """Performs homomorphic scalar multiplication on a ciphertext."""
        from .fhe_query import FHEQueryEngine
        return FHEQueryEngine.multiply_scalar(c, scalar)

    def fhe_linear_combination(self, ciphertexts: List[Dict[str, Any]], weights: List[int]) -> Dict[str, Any]:
        """Computes homomorphic linear combination of ciphertexts."""
        from .fhe_query import FHEQueryEngine
        return FHEQueryEngine.linear_combination(ciphertexts, weights)

    def fhe_query_encrypted_database(
        self,
        records: List[Dict[str, Any]],
        attribute_name: str,
        weights: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """Evaluates an aggregation query over an encrypted credential dataset."""
        from .fhe_query import FHEQueryEngine
        return FHEQueryEngine.query_encrypted_database(records, attribute_name, weights)

    def fhe_create_query_receipt(
        self,
        query_id: str,
        filter_type: str,
        record_count: int,
        result_ciphertext: Dict[str, Any],
        issuer_did: str,
        issuer_private_key_hex: str
    ) -> Dict[str, Any]:
        """Creates a signed verifiable query receipt for an FHE computation."""
        from .fhe_query import FHEQueryEngine
        return FHEQueryEngine.create_query_receipt(
            query_id, filter_type, record_count, result_ciphertext, issuer_did, issuer_private_key_hex
        )

    def fhe_verify_query_receipt(
        self,
        receipt: Dict[str, Any],
        expected_issuer_private_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies an FHE query receipt."""
        from .fhe_query import FHEQueryEngine
        return FHEQueryEngine.verify_query_receipt(receipt, expected_issuer_private_key_hex)
