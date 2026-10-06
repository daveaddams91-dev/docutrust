from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class PolyMixin:

    def poly_generate_srs(self, max_degree: int = 64, secret_seed: str = 'DOCUTRUST_POLYNOMIAL_SRS_SEED_V15') -> Dict[str, Any]:
        """Generates a Structured Reference String (SRS) for polynomial commitments."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.generate_srs(max_degree, secret_seed)

    def poly_commit(self, coefficients: List[Union[int, str]], srs: Dict[str, Any]) -> Dict[str, Any]:
        """Commits to a polynomial represented by coefficients."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.commit(coefficients, srs)

    def poly_evaluate(self, coefficients: List[Union[int, str]], point_z: Union[int, str]) -> int:
        """Evaluates polynomial P(z) at point z modulo BN254 prime."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.evaluate_polynomial(coefficients, point_z)

    def poly_create_proof(self, coefficients: List[Union[int, str]], point_z: Union[int, str], srs: Dict[str, Any]) -> Dict[str, Any]:
        """Creates an opening proof for polynomial P(x) at point z."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.create_evaluation_proof(coefficients, point_z, srs)

    def poly_verify_proof(self, commitment: Dict[str, Any], proof: Dict[str, Any], srs: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies an opening proof against a polynomial commitment."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.verify_evaluation_proof(commitment, proof, srs)

    def poly_multi_proof(self, coefficients: List[Union[int, str]], points: List[Union[int, str]], srs: Dict[str, Any]) -> Dict[str, Any]:
        """Creates a multi-point evaluation proof."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.create_multi_point_proof(coefficients, points, srs)

    def poly_aggregate_proofs(self, commitments: List[Dict[str, Any]], proofs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregates multiple evaluation proofs into a batch proof with EVM calldata."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.aggregate_proofs(commitments, proofs)
