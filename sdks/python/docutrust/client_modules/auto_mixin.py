from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class AutoMixin:

    def auto_anchor_vault(self) -> Dict[str, Any]:
        """Triggers batch auto-anchoring worker on unanchored credentials."""
        url = f"{self.api_url}/vault/auto-anchor"
        res = self.session.post(url, json={})
        res.raise_for_status()
        return res.json()
