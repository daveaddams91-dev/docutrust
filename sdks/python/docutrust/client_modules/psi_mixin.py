from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class PsiMixin:

    def psi_blind_dataset(
        self,
        party_id: str,
        items: List[str],
        secret_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Blinds a dataset using commutative exponentiation."""
        from .psi_engine import PSIEngine
        return PSIEngine.blind_dataset(party_id, items, secret_key_hex)

    def psi_double_blind_dataset(
        self,
        blinded_elements: List[str],
        second_key_hex: str
    ) -> List[str]:
        """Applies a second party's secret blinding key to pre-blinded elements."""
        from .psi_engine import PSIEngine
        return PSIEngine.double_blind_dataset(blinded_elements, second_key_hex)

    def psi_compute_intersection(
        self,
        party_a_id: str,
        party_b_id: str,
        double_blinded_a: List[str],
        double_blinded_b: List[str]
    ) -> Dict[str, Any]:
        """Computes matching intersection cardinality between double-blinded sets."""
        from .psi_engine import PSIEngine
        return PSIEngine.compute_intersection(party_a_id, party_b_id, double_blinded_a, double_blinded_b)

    def psi_create_receipt(
        self,
        dataset_a: Dict[str, Any],
        dataset_b: Dict[str, Any],
        intersection_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generates a cryptographic execution receipt for a completed PSI run."""
        from .psi_engine import PSIEngine
        return PSIEngine.create_execution_receipt(dataset_a, dataset_b, intersection_result)

    def psi_verify_receipt(
        self,
        receipt: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verifies a PSI execution receipt."""
        from .psi_engine import PSIEngine
        return PSIEngine.verify_execution_receipt(receipt)
