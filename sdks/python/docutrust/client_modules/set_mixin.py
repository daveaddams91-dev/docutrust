from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class SetMixin:

    def set_smt_leaf(self, key: str, value: str) -> Dict[str, Any]:
        """Sets or updates a leaf in a 256-bit Sparse Merkle Tree via REST API."""
        return self._request("/smt/set", method="POST", json_data={"key": key, "value": value})
