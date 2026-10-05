from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class ComputeMixin:

    def compute_schema_hash(self, schema: Dict[str, Any]) -> str:
        """Computes deterministic RFC 8785 canonical hash of a schema."""
        from .schema import SchemaValidator
        return SchemaValidator.compute_schema_hash(schema)
