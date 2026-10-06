from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class ResolveMixin:

    def resolve_did(self, did: str) -> Dict[str, Any]:
        """Resolves a DID string to its complete W3C DID Document."""
        from .did import DIDResolver
        return DIDResolver.resolve(did)
