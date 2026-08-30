"""
DocuTrust DIF Presentation Exchange 2.0 Engine (Python Parity)
Provides evaluation of Verifiable Presentations against DIF Presentation Definitions.
"""

import re
from typing import Any, Dict, List, Optional, Union
from .crypto import sha256_hex


def json_path_query(obj: Any, path: str) -> List[Any]:
    """Lightweight JSONPath resolver supporting property access and array traversal."""
    if not path or not path.startswith("$"):
        return []

    tokens = []
    # Tokenize path like $.credentialSubject.degrees[0].name
    raw_tokens = re.findall(r'(\w+)|\[(\d+)\]|\[\*\]', path)
    for t in raw_tokens:
        if t[0]:
            tokens.append(t[0])
        elif t[1]:
            tokens.append(int(t[1]))
        else:
            tokens.append('*')

    # Remove root '$' if captured as first token
    if tokens and tokens[0] == '$':
        tokens = tokens[1:]

    def resolve(current: Any, remaining: List[Any]) -> List[Any]:
        if not remaining:
            return [current] if current is not None else []
        head = remaining[0]
        tail = remaining[1:]

        if current is None:
            return []

        if isinstance(current, dict):
            if head in current:
                return resolve(current[head], tail)
            return []
        elif isinstance(current, list):
            if isinstance(head, int):
                if 0 <= head < len(current):
                    return resolve(current[head], tail)
                return []
            elif head == '*':
                results = []
                for item in current:
                    results.extend(resolve(item, tail))
                return results
        return []

    return resolve(obj, tokens)


def check_filter(val: Any, filter_spec: Dict[str, Any]) -> bool:
    """Validates a resolved field value against a JSON Schema filter."""
    if not filter_spec:
        return True

    if "const" in filter_spec and val != filter_spec["const"]:
        return False

    if "enum" in filter_spec and val not in filter_spec["enum"]:
        return False

    if "type" in filter_spec:
        expected = filter_spec["type"]
        if expected == "string" and not isinstance(val, str):
            return False
        elif expected == "number" and not isinstance(val, (int, float)):
            return False
        elif expected == "boolean" and not isinstance(val, bool):
            return False
        elif expected == "array" and not isinstance(val, list):
            return False
        elif expected == "object" and not isinstance(val, dict):
            return False

    if isinstance(val, str):
        if "pattern" in filter_spec:
            try:
                if not re.search(filter_spec["pattern"], val):
                    return False
            except Exception:
                return False
        if "minLength" in filter_spec and len(val) < filter_spec["minLength"]:
            return False
        if "maxLength" in filter_spec and len(val) > filter_spec["maxLength"]:
            return False

    if isinstance(val, (int, float)):
        if "minimum" in filter_spec and val < filter_spec["minimum"]:
            return False
        if "maximum" in filter_spec and val > filter_spec["maximum"]:
            return False

    return True


class PresentationExchangeEngine:
    @classmethod
    def create_definition(
        cls,
        definition_id: str,
        input_descriptors: List[Dict[str, Any]],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        options = options or {}
        definition = {
            "id": definition_id,
            "input_descriptors": input_descriptors
        }
        if "name" in options:
            definition["name"] = options["name"]
        if "purpose" in options:
            definition["purpose"] = options["purpose"]
        return definition

    @classmethod
    def create_submission(
        cls,
        submission_id: str,
        definition_id: str,
        descriptor_map: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {
            "id": submission_id,
            "definition_id": definition_id,
            "descriptor_map": descriptor_map
        }

    @classmethod
    def evaluate_presentation(
        cls,
        presentation: Dict[str, Any],
        definition: Dict[str, Any],
        submission: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        errors: List[str] = []
        matched_descriptors: List[str] = []
        matched_credentials: List[Dict[str, Any]] = []

        if not definition or "id" not in definition:
            return {"valid": False, "errors": ["Invalid presentation definition: missing id."]}

        if submission and submission.get("definition_id") != definition["id"]:
            errors.append(f"Submission definition_id '{submission.get('definition_id')}' does not match '{definition['id']}'.")

        # Collect credentials
        creds = presentation.get("verifiableCredential", [])
        if isinstance(creds, dict):
            creds = [creds]
        elif not isinstance(creds, list):
            creds = []

        descriptors = definition.get("input_descriptors", [])

        for desc in descriptors:
            desc_id = desc.get("id")
            matched = False

            for idx, cred in enumerate(creds):
                # 1. Schema / Type matching
                if "schema" in desc:
                    schema_match = False
                    for s in desc["schema"]:
                        uri = s.get("uri")
                        cred_types = cred.get("type", [])
                        if isinstance(cred_types, str):
                            cred_types = [cred_types]
                        if uri in cred_types or cred.get("credentialSchema", {}).get("id") == uri:
                            schema_match = True
                            break
                    if not schema_match:
                        continue

                # 2. Constraints matching
                constraints = desc.get("constraints", {})
                fields = constraints.get("fields", [])
                field_errors: List[str] = []

                for field in fields:
                    paths = field.get("path", [])
                    filter_spec = field.get("filter")
                    predicate = field.get("predicate")

                    path_matched = False
                    for p in paths:
                        values = json_path_query(cred, p)
                        if values:
                            if filter_spec:
                                if any(check_filter(v, filter_spec) for v in values):
                                    path_matched = True
                                    break
                            else:
                                path_matched = True
                                break

                    if not path_matched:
                        field_errors.append(f"Descriptor {desc_id}: Field path {paths} not satisfied.")

                if not field_errors:
                    matched = True
                    matched_descriptors.append(desc_id)
                    matched_credentials.append({
                        "descriptor_id": desc_id,
                        "credential_index": idx,
                        "credential_id": cred.get("id")
                    })
                    break

            if not matched:
                errors.append(f"No matching credential found for input_descriptor: '{desc_id}'.")

        audit_data = f"{definition['id']}:{len(matched_descriptors)}:{len(errors)}"
        audit_hash = sha256_hex(audit_data)

        return {
            "valid": len(errors) == 0,
            "matched_descriptors": matched_descriptors,
            "matched_credentials": matched_credentials,
            "audit_hash": audit_hash,
            "errors": errors
        }
