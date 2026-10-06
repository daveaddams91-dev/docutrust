from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class MmrMixin:

    def mmr_append(self, leaf: str) -> Dict[str, Any]:
        """Appends a leaf to the streaming Merkle Mountain Range ledger."""
        url = f"{self.api_url}/ledger/mmr/append"
        res = self.session.post(url, json={"leaf": leaf})
        res.raise_for_status()
        return res.json()

    def mmr_get_peaks(self) -> Dict[str, Any]:
        """Retrieves peaks and bagged root of Merkle Mountain Range."""
        url = f"{self.api_url}/ledger/mmr"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def mmr_get_proof(self, element_index: int) -> Dict[str, Any]:
        """Gets Merkle Mountain Range peak inclusion proof."""
        url = f"{self.api_url}/ledger/mmr/proof"
        res = self.session.post(url, json={"elementIndex": element_index})
        res.raise_for_status()
        return res.json()

    def mmr_verify_proof(self, proof: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies Merkle Mountain Range peak inclusion proof."""
        url = f"{self.api_url}/ledger/mmr/verify"
        res = self.session.post(url, json={"proof": proof})
        res.raise_for_status()
        return res.json()
