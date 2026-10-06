from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class KemMixin:

    def kem_generate_keys(self) -> Dict[str, Any]:
        """Generates Post-Quantum ML-KEM-768 hybrid keys."""
        url = f"{self.api_url}/kem/generate-keys"
        res = self.session.post(url, json={})
        res.raise_for_status()
        return res.json()
