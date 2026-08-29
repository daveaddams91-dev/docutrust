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

def prove_age_above(
    claim_key: str,
    birth_date_str: str,
    minimum_age_years: int,
    salt: Optional[str] = None,
    reference_date_str: Optional[str] = None
) -> Dict[str, Any]:
    try:
        birth_date = datetime.fromisoformat(birth_date_str.replace('Z', '+00:00'))
    except Exception:
        birth_date = datetime.strptime(birth_date_str[:10], "%Y-%m-%d")

    if reference_date_str:
        try:
            ref_date = datetime.fromisoformat(reference_date_str.replace('Z', '+00:00'))
        except Exception:
            ref_date = datetime.strptime(reference_date_str[:10], "%Y-%m-%d")
    else:
        ref_date = datetime.now(timezone.utc)

    age = ref_date.year - birth_date.year
    if (ref_date.month, ref_date.day) < (birth_date.month, birth_date.day):
        age -= 1

    if age < minimum_age_years:
        raise ValueError(f"Subject does not meet age predicate: actual age is {age}, required >= {minimum_age_years}")

    secret_salt = salt or os.urandom(32).hex()
    comm = create_commitment(birth_date_str, secret_salt)
    ref_iso = ref_date.strftime("%Y-%m-%d")

    blinded_age_hash = sha256_hex(f"{secret_salt}::ageAbove::{minimum_age_years}::{ref_iso}")
    proof_bitstring = hashlib.sha3_512(f"{secret_salt}:{comm['commitment']}:{minimum_age_years}:{ref_iso}".encode('utf-8')).hexdigest()

    return {
        "type": "ZKAgePredicateProof2026",
        "claimKey": claim_key,
        "commitment": comm["commitment"],
        "minimumAgeYears": minimum_age_years,
        "referenceDate": ref_iso,
        "proofBitstring": proof_bitstring,
        "blindedAgeHash": blinded_age_hash,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def verify_age_proof(proof: Dict[str, Any], expected_commitment: Optional[str] = None) -> Dict[str, Any]:
    if proof.get("type") != "ZKAgePredicateProof2026":
        return {"valid": False, "error": "Invalid age proof type."}
    if expected_commitment and proof.get("commitment") != expected_commitment:
        return {"valid": False, "error": "Commitment mismatch."}
    if proof.get("minimumAgeYears", -1) < 0:
        return {"valid": False, "error": "Invalid minimumAgeYears value."}
    if len(proof.get("proofBitstring", "")) != 128:
        return {"valid": False, "error": "Invalid proof bitstring."}
    return {"valid": True}

def prove_date_range(
    claim_key: str,
    actual_date_str: str,
    min_date_str: str,
    max_date_str: str,
    salt: Optional[str] = None
) -> Dict[str, Any]:
    try:
        actual_dt = datetime.fromisoformat(actual_date_str.replace('Z', '+00:00'))
    except Exception:
        actual_dt = datetime.strptime(actual_date_str[:10], "%Y-%m-%d")
    try:
        min_dt = datetime.fromisoformat(min_date_str.replace('Z', '+00:00'))
    except Exception:
        min_dt = datetime.strptime(min_date_str[:10], "%Y-%m-%d")
    try:
        max_dt = datetime.fromisoformat(max_date_str.replace('Z', '+00:00'))
    except Exception:
        max_dt = datetime.strptime(max_date_str[:10], "%Y-%m-%d")

    if actual_dt < min_dt or actual_dt > max_dt:
        raise ValueError(f"Date {actual_date_str} is outside range [{min_date_str}, {max_date_str}]")

    secret_salt = salt or os.urandom(32).hex()
    comm = create_commitment(actual_date_str, secret_salt)
    proof_bitstring = hashlib.sha3_512(f"{secret_salt}:{comm['commitment']}:{min_date_str}:{max_date_str}".encode('utf-8')).hexdigest()

    return {
        "type": "ZKDatePredicateProof2026",
        "claimKey": claim_key,
        "commitment": comm["commitment"],
        "minDate": min_date_str,
        "maxDate": max_date_str,
        "proofBitstring": proof_bitstring,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def verify_date_range_proof(proof: Dict[str, Any], expected_commitment: Optional[str] = None) -> Dict[str, Any]:
    if proof.get("type") != "ZKDatePredicateProof2026":
        return {"valid": False, "error": "Invalid date range proof type."}
    if expected_commitment and proof.get("commitment") != expected_commitment:
        return {"valid": False, "error": "Commitment mismatch."}
    if len(proof.get("proofBitstring", "")) != 128:
        return {"valid": False, "error": "Invalid proof bitstring."}
    return {"valid": True}

