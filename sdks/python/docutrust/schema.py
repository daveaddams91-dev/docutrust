"""
DocuTrust W3C Credential Schema & Strict JSON Schema Validation Engine (Python Parity)
Supports draft-07 and 2020-12 sub-specifications with RFC 8785 canonical digest computation.
"""

import re
from typing import Any, Dict, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex


class SchemaValidator:
    @staticmethod
    def compute_schema_hash(schema: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 digest of a JSON schema using canonicalization."""
        canonical = canonicalize_json(schema)
        return sha256_hex(canonical)

    @staticmethod
    def create_credential_schema(
        schema_id: str,
        schema: Dict[str, Any],
        schema_type: str = "JsonSchemaValidator2026"
    ) -> Dict[str, str]:
        """Constructs standard W3C VC 2.0 credentialSchema metadata block."""
        return {
            "id": schema_id,
            "type": schema_type,
            "digest": SchemaValidator.compute_schema_hash(schema)
        }

    @staticmethod
    def validate(
        data: Any,
        schema: Dict[str, Any],
        path: str = "$"
    ) -> Dict[str, Any]:
        """Validates target data against a JSON schema."""
        errors: List[str] = []
        schema_hash = (
            SchemaValidator.compute_schema_hash(schema)
            if "type" in schema and "$id" in schema
            else sha256_hex(canonicalize_json(schema))
        )

        SchemaValidator._validate_node(data, schema, path, errors)

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "schema_hash": schema_hash
        }

    @staticmethod
    def validate_credential_subject(
        credential: Dict[str, Any],
        schema: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validates credentialSubject of a W3C Verifiable Credential against a given JSON Schema."""
        if not isinstance(credential, dict):
            return {
                "valid": False,
                "errors": ["Invalid credential object."],
                "schema_hash": SchemaValidator.compute_schema_hash(schema)
            }

        subject = credential.get("credentialSubject")
        if not isinstance(subject, dict):
            return {
                "valid": False,
                "errors": ["Credential missing credentialSubject object."],
                "schema_hash": SchemaValidator.compute_schema_hash(schema)
            }

        return SchemaValidator.validate(subject, schema, "$.credentialSubject")

    @classmethod
    def _resolve_ref(cls, ref: str, root_schema: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not ref.startswith("#/"):
            return None
        parts = ref[2:].split("/")
        current = root_schema
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current if isinstance(current, dict) else None

    @classmethod
    def _validate_node(
        cls,
        value: Any,
        prop: Dict[str, Any],
        path: str,
        errors: List[str],
        root_schema: Optional[Dict[str, Any]] = None
    ) -> None:
        root = root_schema or prop

        # Resolve $ref pointer
        if "$ref" in prop and isinstance(prop["$ref"], str):
            resolved = cls._resolve_ref(prop["$ref"], root)
            if resolved:
                cls._validate_node(value, resolved, path, errors, root)
                return
            else:
                errors.append(f"{path}: unresolved schema $ref pointer '{prop['$ref']}'")
                return

        # Combinators: allOf, anyOf, oneOf, not
        if "allOf" in prop and isinstance(prop["allOf"], list):
            for idx, sub_schema in enumerate(prop["allOf"]):
                sub_errors: List[str] = []
                cls._validate_node(value, sub_schema, f"{path}.allOf[{idx}]", sub_errors, root)
                errors.extend(sub_errors)

        if "anyOf" in prop and isinstance(prop["anyOf"], list):
            matched_any = False
            for idx, sub_schema in enumerate(prop["anyOf"]):
                sub_errors: List[str] = []
                cls._validate_node(value, sub_schema, f"{path}.anyOf[{idx}]", sub_errors, root)
                if len(sub_errors) == 0:
                    matched_any = True
                    break
            if not matched_any:
                errors.append(f"{path}: value failed to match any schema in 'anyOf'")

        if "oneOf" in prop and isinstance(prop["oneOf"], list):
            matched_count = 0
            for idx, sub_schema in enumerate(prop["oneOf"]):
                sub_errors: List[str] = []
                cls._validate_node(value, sub_schema, f"{path}.oneOf[{idx}]", sub_errors, root)
                if len(sub_errors) == 0:
                    matched_count += 1
            if matched_count != 1:
                errors.append(f"{path}: expected exactly 1 match for 'oneOf', but matched {matched_count}")

        if "not" in prop and isinstance(prop["not"], dict):
            sub_errors: List[str] = []
            cls._validate_node(value, prop["not"], path, sub_errors, root)
            if len(sub_errors) == 0:
                errors.append(f"{path}: value matched disallowed 'not' schema condition")

        if value is None:
            return

        # 1. Type check
        expected_types = prop.get("type")
        if expected_types:
            if not isinstance(expected_types, list):
                expected_types = [expected_types]

            type_matches = False
            for t in expected_types:
                if t == "integer" and isinstance(value, int) and not isinstance(value, bool):
                    type_matches = True
                elif t == "number" and (isinstance(value, (int, float)) and not isinstance(value, bool)):
                    type_matches = True
                elif t == "string" and isinstance(value, str):
                    type_matches = True
                elif t == "boolean" and isinstance(value, bool):
                    type_matches = True
                elif t == "array" and isinstance(value, list):
                    type_matches = True
                elif t == "object" and isinstance(value, dict):
                    type_matches = True
                elif t == "null" and value is None:
                    type_matches = True

            if not type_matches and value is not None:
                actual_type = "null" if value is None else "array" if isinstance(value, list) else type(value).__name__
                errors.append(f"{path}: expected type {' | '.join(expected_types)}, got {actual_type}")
                return

        # 2. Enum check
        if "enum" in prop and isinstance(prop["enum"], list):
            if value not in prop["enum"]:
                errors.append(f"{path}: value {value} is not in enum {prop['enum']}")

        # 3. String validations
        if isinstance(value, str):
            if "minLength" in prop and len(value) < prop["minLength"]:
                errors.append(f"{path}: length {len(value)} is less than minLength {prop['minLength']}")
            if "maxLength" in prop and len(value) > prop["maxLength"]:
                errors.append(f"{path}: length {len(value)} exceeds maxLength {prop['maxLength']}")
            if "pattern" in prop:
                try:
                    if not re.search(prop["pattern"], value):
                        errors.append(f"{path}: value does not match regex pattern {prop['pattern']}")
                except Exception:
                    pass
            if "format" in prop:
                cls._validate_format(value, prop["format"], path, errors)

        # 4. Number validations
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in prop and value < prop["minimum"]:
                errors.append(f"{path}: value {value} is less than minimum {prop['minimum']}")
            if "maximum" in prop and value > prop["maximum"]:
                errors.append(f"{path}: value {value} is greater than maximum {prop['maximum']}")
            if "exclusiveMinimum" in prop and value <= prop["exclusiveMinimum"]:
                errors.append(f"{path}: value {value} must be strictly greater than {prop['exclusiveMinimum']}")
            if "exclusiveMaximum" in prop and value >= prop["exclusiveMaximum"]:
                errors.append(f"{path}: value {value} must be strictly less than {prop['exclusiveMaximum']}")

        # 5. Array validations
        if isinstance(value, list):
            if "minItems" in prop and len(value) < prop["minItems"]:
                errors.append(f"{path}: array length {len(value)} is less than minItems {prop['minItems']}")
            if "maxItems" in prop and len(value) > prop["maxItems"]:
                errors.append(f"{path}: array length {len(value)} exceeds maxItems {prop['maxItems']}")
            if "items" in prop and isinstance(prop["items"], dict):
                for idx, item in enumerate(value):
                    cls._validate_node(item, prop["items"], f"{path}[{idx}]", errors, root)

        # 6. Object validations
        if isinstance(value, dict):
            if "required" in prop and isinstance(prop["required"], list):
                for req_key in prop["required"]:
                    if req_key not in value or value[req_key] is None:
                        errors.append(f"{path}.{req_key}: required property is missing")

            if "properties" in prop and isinstance(prop["properties"], dict):
                for k, sub_prop in prop["properties"].items():
                    if k in value:
                        cls._validate_node(value[k], sub_prop, f"{path}.{k}", errors, root)

            if prop.get("additionalProperties") is False and "properties" in prop:
                declared_keys = set(prop["properties"].keys())
                for k in value.keys():
                    if k not in declared_keys:
                        errors.append(f"{path}.{k}: unexpected property not allowed by schema")
            elif isinstance(prop.get("additionalProperties"), dict):
                declared_keys = set(prop.get("properties", {}).keys())
                for k, v in value.items():
                    if k not in declared_keys:
                        cls._validate_node(v, prop["additionalProperties"], f"{path}.{k}", errors, root)

    @classmethod
    def _validate_format(cls, val: str, fmt: str, path: str, errors: List[str]) -> None:
        if fmt == "email":
            if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", val):
                errors.append(f"{path}: value is not a valid email address")
        elif fmt == "uri":
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:[^\s]*$", val):
                errors.append(f"{path}: value is not a valid URI")
        elif fmt == "uri-reference":
            if not re.match(r"^[a-zA-Z0-9+.-]*:[^\s]*|^(\/[^\s]*)?$", val):
                errors.append(f"{path}: value is not a valid URI reference")
        elif fmt == "did":
            if not re.match(r"^did:[a-z0-9]+:[a-zA-Z0-9.\-_:%]+$", val):
                errors.append(f"{path}: value is not a valid W3C DID string")
        elif fmt == "uuid":
            if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", val):
                errors.append(f"{path}: value is not a valid UUID")
        elif fmt == "ipv4":
            if not re.match(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$", val):
                errors.append(f"{path}: value is not a valid IPv4 address")
        elif fmt == "ipv6":
            if not re.match(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$", val):
                errors.append(f"{path}: value is not a valid IPv6 address")
        elif fmt == "hostname":
            if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", val):
                errors.append(f"{path}: value is not a valid hostname")
        elif fmt == "date":
            if not re.match(r"^\d{4}-\d{2}-\d{2}$", val):
                errors.append(f"{path}: value is not a valid YYYY-MM-DD date")
        elif fmt == "time":
            if not re.match(r"^\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$", val):
                errors.append(f"{path}: value is not a valid time string")
        elif fmt == "date-time":
            if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", val):
                errors.append(f"{path}: value is not a valid ISO 8601 date-time string")
