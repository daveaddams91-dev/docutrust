from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class ValidateMixin:

    def validate_schema(
        self,
        data: Any,
        schema: Dict[str, Any],
        path: str = "$"
    ) -> Dict[str, Any]:
        """Validates arbitrary data against a JSON schema."""
        from .schema import SchemaValidator
        return SchemaValidator.validate(data, schema, path)

    def validate_credential_subject_schema(
        self,
        credential: Dict[str, Any],
        schema: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validates W3C VC credentialSubject against a JSON Schema."""
        from .schema import SchemaValidator
        return SchemaValidator.validate_credential_subject(credential, schema)
