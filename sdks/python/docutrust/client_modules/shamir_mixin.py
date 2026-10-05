from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class ShamirMixin:

    def shamir_split(self, secret: str, total_shares: int = 5, threshold: int = 3) -> Dict[str, Any]:
        """Splits a secret into K-of-N Shamir shares."""
        url = f"{self.api_url}/keys/shamir/split"
        res = self.session.post(url, json={"secret": secret, "totalShares": total_shares, "threshold": threshold})
        res.raise_for_status()
        return res.json()

    def shamir_combine(self, shares: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Reconstructs a secret from Shamir shares."""
        url = f"{self.api_url}/keys/shamir/combine"
        res = self.session.post(url, json={"shares": shares})
        res.raise_for_status()
        return res.json()
