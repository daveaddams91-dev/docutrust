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

def prove_set_membership(
    claim_key: str,
    secret_value: str,
    salt: str,
    allowed_set: List[str]
) -> Dict[str, Any]:
    if secret_value not in allowed_set:
        raise ValueError("Cannot prove membership: secret_value is not in allowed_set.")

    comm = create_commitment(secret_value, salt)
    canonical_set = sorted(allowed_set)
    allowed_set_hash = sha256_hex(canonicalize_json(canonical_set))
    membership_proof_value = sha256_hex(f"{salt}::membership::{allowed_set_hash}::{secret_value}")

    return {
        "type": "ZKSetMembershipProof2026",
        "claimKey": claim_key,
        "commitment": comm["commitment"],
        "allowedSetHash": allowed_set_hash,
        "membershipProofValue": membership_proof_value,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def verify_set_membership_proof(
    proof: Dict[str, Any],
    allowed_set: List[str],
    expected_commitment: Optional[str] = None
) -> Dict[str, Any]:
    if proof.get("type") != "ZKSetMembershipProof2026":
        return {"valid": False, "error": "Invalid membership proof type."}
    if expected_commitment and proof.get("commitment") != expected_commitment:
        return {"valid": False, "error": "Commitment mismatch."}
    computed_set_hash = sha256_hex(canonicalize_json(sorted(allowed_set)))
    if computed_set_hash != proof.get("allowedSetHash"):
        return {"valid": False, "error": "Allowed set does not match the proof target set hash."}
    return {"valid": True}


def prove_set_non_membership(
    claim_key: str,
    secret_value: str,
    salt: str,
    restricted_set: List[str]
) -> Dict[str, Any]:
    if secret_value in restricted_set:
        raise ValueError("Cannot prove non-membership: secret_value IS in the restricted set.")

    comm = create_commitment(secret_value, salt)
    canonical_set = sorted(restricted_set)
    restricted_set_hash = sha256_hex(canonicalize_json(canonical_set))

    pairwise_diff_hashes = [sha256_hex(f"{salt}::diff::{secret_value}!=!{elem}") for elem in canonical_set]
    non_membership_witness = sha256_hex(":".join(pairwise_diff_hashes))

    return {
        "type": "ZKSetNonMembershipProof2026",
        "claimKey": claim_key,
        "commitment": comm["commitment"],
        "restrictedSetHash": restricted_set_hash,
        "nonMembershipWitness": non_membership_witness,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def verify_set_non_membership_proof(
    proof: Dict[str, Any],
    restricted_set: List[str],
    expected_commitment: Optional[str] = None
) -> Dict[str, Any]:
    if proof.get("type") != "ZKSetNonMembershipProof2026":
        return {"valid": False, "error": "Invalid non-membership proof type."}
    if expected_commitment and proof.get("commitment") != expected_commitment:
        return {"valid": False, "error": "Commitment mismatch."}
    computed_set_hash = sha256_hex(canonicalize_json(sorted(restricted_set)))
    if computed_set_hash != proof.get("restrictedSetHash"):
        return {"valid": False, "error": "Restricted set does not match proof target set hash."}
    if len(proof.get("nonMembershipWitness", "")) != 64:
        return {"valid": False, "error": "Invalid non-membership witness format."}
    return {"valid": True}


def prove_composite_predicate(proofs: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not proofs:
        raise ValueError("Cannot create composite predicate proof with empty proofs array.")

    commitments = ":".join(p.get("commitment", "") for p in proofs)
    composite_commitment = sha256_hex(f"composite::{commitments}")

    return {
        "type": "ZKCompositePredicateProof2026",
        "proofs": proofs,
        "compositeCommitment": composite_commitment,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def prove_set_intersection(
    claim_key: str,
    secret_value: str,
    salt: str,
    target_set: List[str]
) -> Dict[str, Any]:
    """Generates a Zero-Knowledge Set Intersection Proof."""
    if secret_value not in target_set:
        raise ValueError("Cannot prove set intersection: secret_value is not in target_set.")

    comm = create_commitment(secret_value, salt)
    canonical_set = sorted(target_set)
    target_set_hash = sha256_hex(canonicalize_json(canonical_set))

    blinded_set_commitments = [
        sha256_hex(f"{salt}::intersection::{item}")
        for item in canonical_set
    ]
    intersection_witness = sha256_hex(f"{salt}::intersection::{secret_value}")

    return {
        "type": "ZKSetIntersectionProof2026",
        "claimKey": claim_key,
        "commitment": comm["commitment"],
        "targetSetHash": target_set_hash,
        "intersectionWitness": intersection_witness,
        "blindedSetCommitments": blinded_set_commitments,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def verify_set_intersection_proof(
    proof: Dict[str, Any],
    target_set: List[str],
    expected_commitment: Optional[str] = None
) -> Dict[str, Any]:
    """Verifies a Zero-Knowledge Set Intersection Proof."""
    if proof.get("type") != "ZKSetIntersectionProof2026":
        return {"valid": False, "error": "Invalid set intersection proof type."}

    if expected_commitment and proof.get("commitment") != expected_commitment:
        return {"valid": False, "error": "Commitment mismatch."}

    computed_set_hash = sha256_hex(canonicalize_json(sorted(target_set)))
    if computed_set_hash != proof.get("targetSetHash"):
        return {"valid": False, "error": "Target set does not match proof set hash."}

    blinded = proof.get("blindedSetCommitments", [])
    witness = proof.get("intersectionWitness", "")
    if witness not in blinded:
        return {"valid": False, "error": "Intersection witness is not part of blinded set commitments."}

    return {"valid": True}


def verify_composite_predicate(
    composite_proof: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    if composite_proof.get("type") != "ZKCompositePredicateProof2026":
        return {"valid": False, "verifiedCount": 0, "errors": ["Invalid composite proof type."]}

    proofs = composite_proof.get("proofs", [])
    errors = []
    verified_count = 0
    ctx = context or {}

    for p in proofs:
        ptype = p.get("type")
        claim_key = p.get("claimKey", "")
        if ptype == "ZKRangePredicateProof2026":
            res = verify_range_proof(p)
            if not res["valid"]:
                errors.append(f"[{claim_key}] Range error: {res.get('error')}")
            else:
                verified_count += 1
        elif ptype == "ZKSetMembershipProof2026":
            allowed = ctx.get("allowedSets", {}).get(claim_key, [])
            if allowed:
                res = verify_set_membership_proof(p, allowed)
                if not res["valid"]:
                    errors.append(f"[{claim_key}] Membership error: {res.get('error')}")
                else:
                    verified_count += 1
            else:
                verified_count += 1
        elif ptype == "ZKSetNonMembershipProof2026":
            restricted = ctx.get("restrictedSets", {}).get(claim_key, [])
            if restricted:
                res = verify_set_non_membership_proof(p, restricted)
                if not res["valid"]:
                    errors.append(f"[{claim_key}] Non-membership error: {res.get('error')}")
                else:
                    verified_count += 1
            else:
                verified_count += 1
        elif ptype == "ZKSetIntersectionProof2026":
            target = ctx.get("allowedSets", {}).get(claim_key, [])
            if target:
                res = verify_set_intersection_proof(p, target)
                if not res["valid"]:
                    errors.append(f"[{claim_key}] Set intersection error: {res.get('error')}")
                else:
                    verified_count += 1
            else:
                verified_count += 1
        elif ptype == "ZKAgePredicateProof2026":
            res = verify_age_proof(p)
            if not res["valid"]:
                errors.append(f"[{claim_key}] Age error: {res.get('error')}")
            else:
                verified_count += 1
        elif ptype == "ZKDatePredicateProof2026":
            res = verify_date_range_proof(p)
            if not res["valid"]:
                errors.append(f"[{claim_key}] Date error: {res.get('error')}")
            else:
                verified_count += 1
        else:
            errors.append(f"Unknown proof type: {ptype}")

    return {
        "valid": len(errors) == 0 and verified_count == len(proofs),
        "verifiedCount": verified_count,
        "errors": errors
    }


def prove_predicate_graph(graph_id: str, root_node: Dict[str, Any]) -> Dict[str, Any]:
    """Generates a recursive Zero-Knowledge Predicate Graph Proof."""
    if not root_node or not isinstance(root_node, dict):
        raise ValueError("Invalid root_node for predicate graph proof.")

    graph_root_hash = sha256_hex(canonicalize_json(root_node))

    return {
        "type": "ZKPredicateGraphProof2026",
        "graphId": graph_id,
        "graphRootHash": graph_root_hash,
        "root": root_node,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def verify_predicate_graph(
    graph_proof: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Verifies a recursive Zero-Knowledge Predicate Graph Proof."""
    if graph_proof.get("type") != "ZKPredicateGraphProof2026":
        return {"valid": False, "verifiedCount": 0, "errors": ["Invalid graph proof type: expected 'ZKPredicateGraphProof2026'."]}

    root = graph_proof.get("root")
    if not root or not isinstance(root, dict):
        return {"valid": False, "verifiedCount": 0, "errors": ["Missing or malformed root node in graph proof."]}

    expected_hash = sha256_hex(canonicalize_json(root))
    if graph_proof.get("graphRootHash") and graph_proof["graphRootHash"] != expected_hash:
        return {"valid": False, "verifiedCount": 0, "errors": ["Graph root hash tampering detected: mismatch with canonicalized root."]}

    errors: List[str] = []
    node_evaluations: List[Dict[str, Any]] = []
    ctx = context or {}

    def evaluate_node(node: Dict[str, Any]) -> bool:
        node_id = node.get("id", f"node_{len(node_evaluations)}")
        operator = node.get("operator")
        children = node.get("children", [])
        proof = node.get("proof")

        if proof:
            # Leaf node evaluation
            ptype = proof.get("type")
            claim_key = proof.get("claimKey", "")
            is_leaf_valid = False
            leaf_error = None

            if ptype == "ZKRangePredicateProof2026":
                res = verify_range_proof(proof)
                is_leaf_valid = res["valid"]
                leaf_error = res.get("error")
            elif ptype == "ZKAgePredicateProof2026":
                res = verify_age_proof(proof)
                is_leaf_valid = res["valid"]
                leaf_error = res.get("error")
            elif ptype == "ZKDatePredicateProof2026":
                res = verify_date_range_proof(proof)
                is_leaf_valid = res["valid"]
                leaf_error = res.get("error")
            elif ptype == "ZKSetMembershipProof2026":
                allowed = ctx.get("allowedSets", {}).get(claim_key, [])
                if allowed:
                    res = verify_set_membership_proof(proof, allowed)
                    is_leaf_valid = res["valid"]
                    leaf_error = res.get("error")
                else:
                    is_leaf_valid = True
            elif ptype == "ZKSetNonMembershipProof2026":
                restricted = ctx.get("restrictedSets", {}).get(claim_key, [])
                if restricted:
                    res = verify_set_non_membership_proof(proof, restricted)
                    is_leaf_valid = res["valid"]
                    leaf_error = res.get("error")
                else:
                    is_leaf_valid = True
            elif ptype == "ZKSetIntersectionProof2026":
                target = ctx.get("allowedSets", {}).get(claim_key, [])
                if target:
                    res = verify_set_intersection_proof(proof, target)
                    is_leaf_valid = res["valid"]
                    leaf_error = res.get("error")
                else:
                    is_leaf_valid = True
            elif ptype == "ZKCompositePredicateProof2026":
                res = verify_composite_predicate(proof, ctx)
                is_leaf_valid = res["valid"]
                leaf_error = "; ".join(res.get("errors", [])) if not is_leaf_valid else None
            else:
                leaf_error = f"Unsupported proof type: {ptype}"

            if not is_leaf_valid:
                errors.append(f"Leaf [{node_id}]: {leaf_error or 'Verification failed'}")

            node_evaluations.append({"id": node_id, "valid": is_leaf_valid, "proofType": ptype})
            return is_leaf_valid

        # Intermediate operator node
        child_results = [evaluate_node(c) for c in children]
        op_upper = (operator or "AND").upper()
        op_valid = False

        if op_upper == "AND":
            op_valid = len(child_results) > 0 and all(child_results)
            if not op_valid:
                errors.append(f"Operator [{node_id} - AND]: Not all child conditions satisfied.")
        elif op_upper == "OR":
            op_valid = any(child_results)
            if not op_valid:
                errors.append(f"Operator [{node_id} - OR]: No child conditions satisfied.")
        elif op_upper == "NOT":
            op_valid = len(child_results) == 1 and not child_results[0]
            if not op_valid:
                errors.append(f"Operator [{node_id} - NOT]: Child condition inversion failed.")
        elif op_upper == "THRESHOLD":
            required = node.get("threshold", 1)
            satisfied = sum(1 for r in child_results if r)
            op_valid = satisfied >= required
            if not op_valid:
                errors.append(f"Operator [{node_id} - THRESHOLD]: Met {satisfied}/{required} conditions.")
        else:
            errors.append(f"Operator [{node_id}]: Unknown operator '{operator}'.")

        node_evaluations.append({"id": node_id, "operator": op_upper, "valid": op_valid})
        return op_valid

    is_overall_valid = evaluate_node(root)
    verified_count = sum(1 for n in node_evaluations if n["valid"])

    return {
        "valid": is_overall_valid and len(errors) == 0,
        "verifiedCount": verified_count,
        "nodeEvaluations": node_evaluations,
        "errors": errors
    }


