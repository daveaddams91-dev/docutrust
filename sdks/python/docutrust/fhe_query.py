import hashlib
import hmac
import json
import secrets
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

class FHEQueryEngine:
    DEFAULT_MODULUS = 2147483647
    DEFAULT_DIMENSION = 8
    INITIAL_NOISE_BUDGET = 100

    @staticmethod
    def _mod(n: int, m: int) -> int:
        return ((n % m) + m) % m

    @classmethod
    def generate_key_pair(cls, dimension: int = DEFAULT_DIMENSION, modulus: int = DEFAULT_MODULUS) -> Dict[str, Any]:
        key_id = f"fhe_{secrets.token_hex(8)}"
        secret = [secrets.randbelow(15) + 1 for _ in range(dimension)]
        
        A: List[List[int]] = []
        B: List[int] = []

        for _ in range(dimension):
            row = []
            dot = 0
            for j in range(dimension):
                a_ij = secrets.randbelow(10000)
                row.append(a_ij)
                dot = (dot + a_ij * secret[j]) % modulus
            A.append(row)
            B.append(cls._mod(dot, modulus))

        return {
            "public_key": {
                "A": A,
                "B": B,
                "modulus": modulus,
                "dimension": dimension,
                "id": key_id
            },
            "private_key": {
                "secret": secret,
                "modulus": modulus,
                "dimension": dimension,
                "id": key_id
            }
        }

    @classmethod
    def encrypt_value(cls, value: int, public_key: Dict[str, Any], tag: str = "scalar") -> Dict[str, Any]:
        A = public_key["A"]
        B = public_key["B"]
        modulus = public_key["modulus"]
        dimension = public_key["dimension"]
        v_mod = cls._mod(int(value), modulus)

        r = [secrets.randbelow(2) for _ in range(dimension)]

        c0 = [0] * dimension
        for j in range(dimension):
            s = sum(r[i] * A[i][j] for i in range(dimension)) % modulus
            c0[j] = cls._mod(s, modulus)

        dot_b = sum(r[i] * B[i] for i in range(dimension)) % modulus
        c1 = cls._mod(dot_b + v_mod, modulus)

        return {
            "c0": c0,
            "c1": c1,
            "noise_budget": cls.INITIAL_NOISE_BUDGET - 5,
            "modulus": modulus,
            "dimension": dimension,
            "tag": tag
        }

    @classmethod
    def decrypt_value(cls, ciphertext: Dict[str, Any], private_key: Dict[str, Any]) -> int:
        c0 = ciphertext["c0"]
        c1 = ciphertext["c1"]
        modulus = ciphertext["modulus"]
        dimension = ciphertext["dimension"]
        secret = private_key["secret"]

        if len(c0) != dimension or len(secret) != dimension:
            raise ValueError("Ciphertext and private key dimension mismatch")

        dot = sum(c0[i] * secret[i] for i in range(dimension)) % modulus
        diff = cls._mod(c1 - dot, modulus)
        if diff > modulus // 2:
            diff = diff - modulus
        return round(diff)

    @classmethod
    def add_ciphertexts(cls, c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
        if c1["modulus"] != c2["modulus"] or c1["dimension"] != c2["dimension"]:
            raise ValueError("Cannot add ciphertexts with incompatible parameters")
        
        modulus = c1["modulus"]
        dimension = c1["dimension"]

        c0 = [cls._mod(c1["c0"][i] + c2["c0"][i], modulus) for i in range(dimension)]
        c1_val = cls._mod(c1["c1"] + c2["c1"], modulus)
        noise_budget = max(0, min(c1["noise_budget"], c2["noise_budget"]) - 2)

        return {
            "c0": c0,
            "c1": c1_val,
            "noise_budget": noise_budget,
            "modulus": modulus,
            "dimension": dimension,
            "tag": f"sum({c1.get('tag','c1')},{c2.get('tag','c2')})"
        }

    @classmethod
    def multiply_scalar(cls, c: Dict[str, Any], scalar: int) -> Dict[str, Any]:
        modulus = c["modulus"]
        dimension = c["dimension"]
        s_mod = cls._mod(int(scalar), modulus)

        c0 = [cls._mod(v * s_mod, modulus) for v in c["c0"]]
        c1_val = cls._mod(c["c1"] * s_mod, modulus)
        noise_budget = max(0, c["noise_budget"] - int(abs(scalar)).bit_length() - 3)

        return {
            "c0": c0,
            "c1": c1_val,
            "noise_budget": noise_budget,
            "modulus": modulus,
            "dimension": dimension,
            "tag": f"scale({c.get('tag','c')},{scalar})"
        }

    @classmethod
    def linear_combination(cls, ciphertexts: List[Dict[str, Any]], weights: List[int]) -> Dict[str, Any]:
        if not ciphertexts or len(ciphertexts) != len(weights):
            raise ValueError("Ciphertexts and weights must be non-empty and of equal length")

        acc = cls.multiply_scalar(ciphertexts[0], weights[0])
        for i in range(1, len(ciphertexts)):
            term = cls.multiply_scalar(ciphertexts[i], weights[i])
            acc = cls.add_ciphertexts(acc, term)
        return acc

    @classmethod
    def evaluate_encrypted_equality(cls, c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
        neg_c2 = cls.multiply_scalar(c2, -1)
        return cls.add_ciphertexts(c1, neg_c2)

    @classmethod
    def query_encrypted_database(
        cls,
        records: List[Dict[str, Any]],
        attribute_name: str,
        weights: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        if not records:
            raise ValueError("Records collection is empty")

        ciphertexts = []
        effective_weights = []

        for i, rec in enumerate(records):
            attrs = rec.get("encrypted_attributes", {})
            if attribute_name in attrs:
                ciphertexts.append(attrs[attribute_name])
                effective_weights.append(weights[i] if weights and i < len(weights) else 1)

        if not ciphertexts:
            raise ValueError(f"No records contain attribute '{attribute_name}'")

        aggregated = cls.linear_combination(ciphertexts, effective_weights)
        return {
            "aggregated_result": aggregated,
            "evaluated_count": len(ciphertexts)
        }

    @classmethod
    def create_query_receipt(
        cls,
        query_id: str,
        filter_type: str,
        record_count: int,
        result_ciphertext: Dict[str, Any],
        issuer_did: str,
        issuer_private_key_hex: str
    ) -> Dict[str, Any]:
        unsigned = {
            "type": "DocuTrustFHEQueryReceipt2026",
            "queryId": query_id,
            "filterType": filter_type,
            "recordCount": record_count,
            "resultCiphertext": result_ciphertext,
            "noiseBudgetRemaining": result_ciphertext["noise_budget"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "issuer": issuer_did
        }

        canonical = json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode('utf-8')
        h = hashlib.sha256(canonical).digest()
        key_bytes = bytes.fromhex(issuer_private_key_hex.replace("0x", ""))
        sig = "0x" + hmac.new(key_bytes, h, hashlib.sha256).hexdigest()

        return {**unsigned, "signature": sig}

    @classmethod
    def verify_query_receipt(
        cls,
        receipt: Dict[str, Any],
        expected_issuer_private_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        if receipt.get("type") != "DocuTrustFHEQueryReceipt2026":
            return {"valid": False, "noise_acceptable": False, "error": "Invalid receipt type"}

        if "resultCiphertext" not in receipt or not isinstance(receipt["resultCiphertext"].get("c0"), list):
            return {"valid": False, "noise_acceptable": False, "error": "Malformed result ciphertext"}

        noise_ok = receipt.get("noiseBudgetRemaining", 0) > 10

        if expected_issuer_private_key_hex:
            unsigned = {k: v for k, v in receipt.items() if k != "signature"}
            canonical = json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode('utf-8')
            h = hashlib.sha256(canonical).digest()
            key_bytes = bytes.fromhex(expected_issuer_private_key_hex.replace("0x", ""))
            expected_sig = "0x" + hmac.new(key_bytes, h, hashlib.sha256).hexdigest()

            if receipt.get("signature") != expected_sig:
                return {"valid": False, "noise_acceptable": noise_ok, "error": "Cryptographic signature mismatch"}

        return {"valid": True, "noise_acceptable": noise_ok}
