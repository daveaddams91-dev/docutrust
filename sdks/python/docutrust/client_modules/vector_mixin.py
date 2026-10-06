from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class VectorMixin:

    def vector_commit(
        self,
        vector: List[Any],
        crs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Computes an O(1) succinct vector commitment over an attribute list."""
        from .vector_commitments import VectorCommitmentEngine
        return VectorCommitmentEngine.commit(vector, crs)

    def vector_prove_position(
        self,
        vector: List[Any],
        index: int,
        crs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generates a single-position opening proof."""
        from .vector_commitments import VectorCommitmentEngine
        return VectorCommitmentEngine.prove_position(vector, index, crs)

    def vector_verify_position(
        self,
        commitment_hex: str,
        proof: Dict[str, Any],
        crs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Verifies a single-position opening proof."""
        from .vector_commitments import VectorCommitmentEngine
        return VectorCommitmentEngine.verify_position(commitment_hex, proof, crs)

    def vector_prove_subvector(
        self,
        vector: List[Any],
        indices: List[int],
        crs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generates an aggregated subvector opening proof for an index subset."""
        from .vector_commitments import VectorCommitmentEngine
        return VectorCommitmentEngine.prove_subvector(vector, indices, crs)

    def vector_verify_subvector(
        self,
        commitment_hex: str,
        proof: Dict[str, Any],
        crs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Verifies an aggregated subvector opening proof in O(|I|) time."""
        from .vector_commitments import VectorCommitmentEngine
        return VectorCommitmentEngine.verify_subvector(commitment_hex, proof, crs)
