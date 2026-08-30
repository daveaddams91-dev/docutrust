"""
DocuTrust Sovereign Policy-as-Proof & Governance Rule Engine (DocuTrust v9.0.0).
Evaluates verifiable presentation claims, credential subjects, and zero-knowledge assertions
against AST-based logical constraint trees (AND, OR, NOT, GTE, LTE, EQ, NEQ, IN, CONTAINS, REGEX),
emitting cryptographically signed execution receipts.
"""

from __future__ import annotations
import re
import json
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timezone
from .crypto import canonicalize_json, sha256_hex, sign_data, verify_signature, decode_base58

class PolicyEngine:
    """Evaluates Verifiable Credentials and Presentations against declarative AST policies."""

    @classmethod
    def evaluate(
        cls,
        payload: Dict[str, Any],
        policy: Dict[str, Any],
        evaluator_keypair: Optional[Union[Dict[str, Any], Any]] = None,
        evaluation_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        errors: List[str] = []
        eval_time = evaluation_time or datetime.now(timezone.utc)
        evaluated_at = eval_time.isoformat()

        if not payload or not isinstance(payload, dict):
            return {
                "passed": False,
                "policyId": policy.get("id", "unknown") if policy else "unknown",
                "policyName": policy.get("name", "Unknown Policy") if policy else "Unknown Policy",
                "evaluatedAt": evaluated_at,
                "errors": ["Invalid credential/presentation payload provided."],
                "traces": {
                    "condition": policy.get("condition", {"operator": "and"}) if policy else {"operator": "and"},
                    "passed": False,
                    "reason": "Payload is null or not a dictionary."
                }
            }

        # 1. Check required credential types
        req_types = policy.get("requiredCredentialTypes") or []
        if req_types:
            payload_types = payload.get("type", [])
            if isinstance(payload_types, str):
                payload_types = [payload_types]
            missing_types = [t for t in req_types if t not in payload_types]
            if missing_types:
                errors.append(f"Payload missing required credential types: {', '.join(missing_types)}")

        # 2. Check allowed issuers
        allowed_issuers = policy.get("allowedIssuers") or []
        if allowed_issuers:
            issuer_val = payload.get("issuer")
            issuer_did = issuer_val if isinstance(issuer_val, str) else (issuer_val.get("id") if isinstance(issuer_val, dict) else "")
            clean_issuer = issuer_did.split("#")[0] if issuer_did else ""
            is_allowed = any(allowed.split("#")[0] == clean_issuer for allowed in allowed_issuers)
            if not is_allowed:
                errors.append(f"Issuer {issuer_did or 'unknown'} is not in the policy allowed issuers list.")

        # 3. Check maximum credential age
        max_age = policy.get("maxCredentialAgeSeconds")
        if max_age is not None and max_age > 0:
            issuance_str = payload.get("validFrom") or payload.get("issuanceDate")
            if issuance_str:
                try:
                    clean_str = issuance_str.replace("Z", "+00:00")
                    dt = datetime.fromisoformat(clean_str)
                    age_seconds = (eval_time.timestamp() - dt.timestamp())
                    if age_seconds > max_age:
                        errors.append(f"Credential age ({int(age_seconds)}s) exceeds max allowed age ({max_age}s).")
                except Exception:
                    pass

        # 4. Recursively evaluate condition AST
        traces = cls._evaluate_condition(payload, policy.get("condition", {"operator": "and"}))
        if not traces["passed"]:
            if traces.get("reason"):
                errors.append(traces["reason"])

        passed = len(errors) == 0 and traces["passed"]

        # 5. Generate signed receipt if evaluator keypair is provided
        receipt = None
        if evaluator_keypair:
            policy_canonical = canonicalize_json(policy)
            policy_hash = sha256_hex(policy_canonical)
            trace_canonical = canonicalize_json(traces)
            execution_trace_hash = sha256_hex(trace_canonical)
            target_cred_id = payload.get("id", f"urn:uuid:{sha256_hex(canonicalize_json(payload))[:16]}")

            if isinstance(evaluator_keypair, dict):
                evaluator_did = evaluator_keypair.get("did", "")
                priv_hex = evaluator_keypair.get("privateKeyHex") or evaluator_keypair.get("private_key_hex", "")
            else:
                evaluator_did = getattr(evaluator_keypair, "did", "")
                priv_hex = getattr(evaluator_keypair, "private_key_hex", getattr(evaluator_keypair, "privateKeyHex", ""))

            created = evaluated_at

            unsigned_receipt = {
                "type": "DocuTrustPolicyReceipt2026",
                "policyId": policy.get("id", ""),
                "policyHash": policy_hash,
                "targetCredentialId": target_cred_id,
                "passed": passed,
                "evaluatedAt": evaluated_at,
                "evaluatorDid": evaluator_did,
                "executionTraceHash": execution_trace_hash
            }

            digest = sha256_hex(canonicalize_json(unsigned_receipt))
            payload_to_sign = f"{digest}:{created}"
            proof_value = sign_data(payload_to_sign, priv_hex)

            receipt = {
                **unsigned_receipt,
                "proof": {
                    "type": "Ed25519Signature2020",
                    "created": created,
                    "verificationMethod": f"{evaluator_did}#key-1",
                    "proofValue": proof_value
                }
            }

        result = {
            "passed": passed,
            "policyId": policy.get("id", ""),
            "policyName": policy.get("name", ""),
            "evaluatedAt": evaluated_at,
            "errors": errors,
            "traces": traces
        }
        if receipt:
            result["receipt"] = receipt
        return result

    @classmethod
    def verify_receipt(cls, receipt: Dict[str, Any], expected_evaluator_public_key_hex: Optional[str] = None) -> bool:
        if not receipt or receipt.get("type") != "DocuTrustPolicyReceipt2026" or not receipt.get("proof"):
            return False

        unsigned = {k: v for k, v in receipt.items() if k != "proof"}
        proof = receipt["proof"]
        digest = sha256_hex(canonicalize_json(unsigned))

        pub_hex = expected_evaluator_public_key_hex
        evaluator_did = receipt.get("evaluatorDid", "")
        if not pub_hex and evaluator_did.startswith("did:key:"):
            try:
                clean_did = evaluator_did.split("#")[0]
                raw = decode_base58(clean_did.replace("did:key:z", ""))
                pub_hex = raw[2:].hex()
            except Exception:
                pass

        if not pub_hex:
            return False

        payload_signed = f"{digest}:{proof.get('created', '')}"
        return verify_signature(payload_signed, proof.get("proofValue", ""), pub_hex)

    @classmethod
    def resolve_field_value(cls, obj: Any, path: Optional[str]) -> Any:
        if not path or not obj:
            return None
        parts = path.split(".")
        curr = obj
        for part in parts:
            if curr is None or not isinstance(curr, dict):
                return None
            curr = curr.get(part)
        return curr

    @classmethod
    def _evaluate_condition(cls, payload: Dict[str, Any], condition: Dict[str, Any]) -> Dict[str, Any]:
        op = (condition.get("operator") or "").lower()

        # AND
        if op == "and":
            children = condition.get("conditions") or []
            child_traces = []
            all_passed = True
            first_fail = None

            for cond in children:
                trace = cls._evaluate_condition(payload, cond)
                child_traces.append(trace)
                if not trace["passed"]:
                    all_passed = False
                    if not first_fail:
                        first_fail = trace.get("reason")

            return {
                "condition": condition,
                "passed": all_passed,
                "reason": None if all_passed else (first_fail or "One or more AND conditions failed."),
                "childrenTraces": child_traces
            }

        # OR
        if op == "or":
            children = condition.get("conditions") or []
            child_traces = []
            any_passed = False

            for cond in children:
                trace = cls._evaluate_condition(payload, cond)
                child_traces.append(trace)
                if trace["passed"]:
                    any_passed = True

            return {
                "condition": condition,
                "passed": any_passed,
                "reason": None if any_passed else "None of the OR conditions were satisfied.",
                "childrenTraces": child_traces
            }

        # NOT
        if op == "not":
            children = condition.get("conditions") or []
            if not children:
                return {"condition": condition, "passed": False, "reason": "NOT condition missing child condition."}
            child_trace = cls._evaluate_condition(payload, children[0])
            return {
                "condition": condition,
                "passed": not child_trace["passed"],
                "reason": "NOT condition failed because inner condition evaluated to true." if child_trace["passed"] else None,
                "childrenTraces": [child_trace]
            }

        actual = cls.resolve_field_value(payload, condition.get("field"))
        expected = condition.get("value")

        if op == "exists":
            passed = actual is not None
            return {"condition": condition, "actualValue": actual, "passed": passed, "reason": None if passed else f"Field '{condition.get('field')}' does not exist."}

        if op == "not_exists":
            passed = actual is None
            return {"condition": condition, "actualValue": actual, "passed": passed, "reason": None if passed else f"Field '{condition.get('field')}' unexpectedly exists."}

        if op == "eq":
            passed = (actual == expected)
            return {"condition": condition, "actualValue": actual, "passed": passed, "reason": None if passed else f"Field '{condition.get('field')}' expected {expected}, got {actual}"}

        if op == "neq":
            passed = (actual != expected)
            return {"condition": condition, "actualValue": actual, "passed": passed, "reason": None if passed else f"Field '{condition.get('field')}' expected not equal to {expected}"}

        if op == "gt":
            passed = isinstance(actual, (int, float)) and actual > expected
            return {"condition": condition, "actualValue": actual, "passed": passed, "reason": None if passed else f"Field '{condition.get('field')}' ({actual}) is not greater than {expected}"}

        if op == "gte":
            passed = isinstance(actual, (int, float, str)) and actual >= expected
            return {"condition": condition, "actualValue": actual, "passed": passed, "reason": None if passed else f"Field '{condition.get('field')}' ({actual}) is not >= {expected}"}

        if op == "lt":
            passed = isinstance(actual, (int, float)) and actual < expected
            return {"condition": condition, "actualValue": actual, "passed": passed, "reason": None if passed else f"Field '{condition.get('field')}' ({actual}) is not less than {expected}"}

        if op == "lte":
            passed = isinstance(actual, (int, float, str)) and actual <= expected
            return {"condition": condition, "actualValue": actual, "passed": passed, "reason": None if passed else f"Field '{condition.get('field')}' ({actual}) is not <= {expected}"}

        if op == "in":
            arr = expected if isinstance(expected, list) else [expected]
            passed = actual in arr
            return {"condition": condition, "actualValue": actual, "passed": passed, "reason": None if passed else f"Field '{condition.get('field')}' ({actual}) not in allowed set {arr}"}

        if op == "not_in":
            arr = expected if isinstance(expected, list) else [expected]
            passed = actual not in arr
            return {"condition": condition, "actualValue": actual, "passed": passed, "reason": None if passed else f"Field '{condition.get('field')}' ({actual}) is in forbidden set {arr}"}

        if op == "contains":
            passed = False
            if isinstance(actual, list):
                passed = expected in actual
            elif isinstance(actual, str):
                passed = str(expected) in actual
            return {"condition": condition, "actualValue": actual, "passed": passed, "reason": None if passed else f"Field '{condition.get('field')}' does not contain {expected}"}

        if op == "regex":
            passed = False
            if isinstance(actual, str):
                try:
                    passed = bool(re.search(str(expected), actual))
                except Exception:
                    passed = False
            return {"condition": condition, "actualValue": actual, "passed": passed, "reason": None if passed else f"Field '{condition.get('field')}' does not match regex /{expected}/"}

        return {"condition": condition, "passed": False, "reason": f"Unsupported policy operator: {op}"}
