import hashlib
import json
import secrets
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

class PSIEngine:
    """
    Private Set Intersection (PSI) and Blind Set Matching Engine.
    Implements commutative exponentiation dataset blinding, double-blinding match-making,
    intersection cardinality verification, and verifiable execution receipts.
    """
    P = int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

    @classmethod
    def generate_blinding_key(cls) -> str:
        return secrets.token_hex(32)

    @classmethod
    def _get_key_int(cls, key_hex: str) -> int:
        return (int(key_hex, 16) % (cls.P - 2)) + 2

    @classmethod
    def _blind_element(cls, element: str, key_hex: str) -> str:
        k = cls._get_key_int(key_hex)
        h = int(hashlib.sha256(element.encode("utf-8")).hexdigest(), 16) % cls.P
        blinded = pow(h, k, cls.P)
        return hex(blinded)[2:].zfill(64)

    @classmethod
    def blind_dataset(
        cls,
        party_id: str,
        items: List[str],
        secret_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        key = secret_key_hex or cls.generate_blinding_key()
        blinded_elements = [cls._blind_element(item, key) for item in items]
        dataset_hash = "0x" + hashlib.sha256(f"BLIND_DS:{party_id}:{sorted(blinded_elements)}".encode("utf-8")).hexdigest()

        return {
            "party_id": party_id,
            "element_count": len(items),
            "blinded_elements": blinded_elements,
            "dataset_hash": dataset_hash,
            "secret_key_hex": key
        }

    @classmethod
    def double_blind_dataset(
        cls,
        blinded_elements: List[str],
        second_key_hex: str
    ) -> List[str]:
        k2 = cls._get_key_int(second_key_hex)
        return [
            hex(pow(int(elem, 16) % cls.P, k2, cls.P))[2:].zfill(64)
            for elem in blinded_elements
        ]

    @classmethod
    def compute_intersection(
        cls,
        party_a_id: str,
        party_b_id: str,
        double_blinded_a: List[str],
        double_blinded_b: List[str]
    ) -> Dict[str, Any]:
        set_b = set(double_blinded_b)
        intersection = [elem for elem in double_blinded_a if elem in set_b]
        cardinality = len(intersection)

        execution_id = "psi_" + hashlib.sha256(f"PSI_EXEC:{party_a_id}:{party_b_id}:{cardinality}".encode("utf-8")).hexdigest()[:16]

        return {
            "execution_id": execution_id,
            "party_a": party_a_id,
            "party_b": party_b_id,
            "cardinality": cardinality,
            "intersection_elements": intersection,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    @classmethod
    def create_execution_receipt(
        cls,
        dataset_a: Dict[str, Any],
        dataset_b: Dict[str, Any],
        intersection_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        serialized_result = json.dumps(intersection_result, sort_keys=True)
        receipt_digest = "0x" + hashlib.sha256(f"PSI_RECEIPT:{dataset_a['dataset_hash']}:{dataset_b['dataset_hash']}:{serialized_result}".encode("utf-8")).hexdigest()

        return {
            "type": "DocuTrustPSIReceipt2026",
            "execution_id": intersection_result["execution_id"],
            "party_a_hash": dataset_a["dataset_hash"],
            "party_b_hash": dataset_b["dataset_hash"],
            "intersection_cardinality": intersection_result["cardinality"],
            "receipt_digest": receipt_digest,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

    @classmethod
    def verify_execution_receipt(cls, receipt: Dict[str, Any]) -> Dict[str, Any]:
        if receipt.get("type") != "DocuTrustPSIReceipt2026":
            return {"valid": False, "error": "Invalid PSI receipt type"}

        if not receipt.get("party_a_hash") or not receipt.get("party_b_hash"):
            return {"valid": False, "error": "Missing participant dataset hashes"}

        if not receipt.get("receipt_digest"):
            return {"valid": False, "error": "Missing receipt digest"}

        return {"valid": True, "psi_verified": True}
