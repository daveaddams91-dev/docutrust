from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class CheckMixin:

    def check_bloom_filter(self, signed_filter: Dict[str, Any], credential_id: str) -> Dict[str, Any]:
        """Checks revocation status against a signed Bloom filter."""
        url = f"{self.api_url}/revocation/bloom/check"
        res = self.session.post(url, json={"signedFilter": signed_filter, "credentialId": credential_id})
        res.raise_for_status()
        return res.json()

    def check_status_list_2024(
        self,
        encoded_list: str,
        index: int,
        status_size: int = 1,
        length: Optional[int] = None
    ) -> Dict[str, Any]:
        """Decodes and checks status at index in a BitstringStatusList2024."""
        from .status_list import BitstringStatusList2024
        opts = {"status_size": status_size}
        if length:
            opts["length"] = length
        list_inst = BitstringStatusList2024.decode(encoded_list, opts)
        status_val = list_inst.get_status(index)
        return {
            "index": index,
            "status": status_val,
            "statusSize": status_size,
            "isValid": list_inst.is_valid(index),
            "isRevoked": list_inst.is_revoked(index),
            "isSuspended": list_inst.is_suspended(index)
        }
