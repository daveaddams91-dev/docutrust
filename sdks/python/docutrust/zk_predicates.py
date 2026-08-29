from __future__ import annotations
import os
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from .crypto import canonicalize_json, sha256_hex

def create_commitment(value: Any, salt: Optional[str] = None) -> Dict[str, str]:
    secret_salt = salt or os.urandom(32).hex()
    payload = f"{secret_salt}::{canonicalize_json(value)}"
    commitment = sha256_hex(payload)
    return {"commitment": commitment, "salt": secret_salt}

def prove_range(
    claim_key: str,
    actual_value: float,
    salt: str,
    min_val: float,
    max_val: float
) -> Dict[str, Any]:
    if actual_value < min_val or actual_value > max_val:
        raise ValueError(f"Cannot generate proof: value {actual_value} is outside [{min_val}, {max_val}]")

    comm = create_commitment(actual_value, salt)
    step_count = min(100, max(1, int(max_val - min_val + 1)))
    blinded_hashes: List[str] = []

    for i in range(step_count):
        range_pt = min_val + i * ((max_val - min_val) / max(1, step_count - 1))
        is_matching = abs(range_pt - actual_value) < 0.0001
        pt_salt = salt if is_matching else os.urandom(16).hex()
        blinded_hashes.append(sha256_hex(f"{pt_salt}::rangePoint:{range_pt}"))

    proof_seed = hashlib.sha3_512(f"{salt}:{comm['commitment']}:{min_val}:{max_val}".encode('utf-8')).hexdigest()
    now_iso = datetime.now(timezone.utc).isoformat()

    return {
        "type": "ZKRangePredicateProof2026",
        "claimKey": claim_key,
        "commitment": comm["commitment"],
        "min": min_val,
        "max": max_val,
        "proofBitstring": proof_seed,
        "blindedRangeHashes": blinded_hashes,
        "timestamp": now_iso
    }

def verify_range_proof(proof: Dict[str, Any], expected_commitment: Optional[str] = None) -> Dict[str, Any]:
    if proof.get("type") != "ZKRangePredicateProof2026":
        return {"valid": False, "error": "Invalid proof type."}
    if expected_commitment and proof.get("commitment") != expected_commitment:
        return {"valid": False, "error": "Commitment mismatch."}
    if proof.get("min", 0) > proof.get("max", 0):
        return {"valid": False, "error": "Malformed bounds."}
    if len(proof.get("proofBitstring", "")) != 128:
        return {"valid": False, "error": "Invalid proof bitstring."}
    return {"valid": True}
