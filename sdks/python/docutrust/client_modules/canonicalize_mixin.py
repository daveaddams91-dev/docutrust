from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class CanonicalizeMixin:

    def canonicalize_jsonld(self, doc: Dict[str, Any]) -> str:
        """Canonicalizes a JSON-LD document into deterministic URDNA2015 N-Quads."""
        from .jsonld import JsonLdCanonicalizationEngine
        return JsonLdCanonicalizationEngine.canonicalize(doc)
