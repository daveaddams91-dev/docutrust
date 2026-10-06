from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class UpdateMixin:

    def update_status_list_2024(
        self,
        encoded_list: str,
        index: int,
        status: int,
        status_size: int = 1,
        length: Optional[int] = None
    ) -> Dict[str, Any]:
        """Updates status at index in a BitstringStatusList2024."""
        from .status_list import BitstringStatusList2024
        opts = {"status_size": status_size}
        if length:
            opts["length"] = length
        list_inst = BitstringStatusList2024.decode(encoded_list, opts)
        list_inst.set_status(index, status)
        new_encoded = list_inst.encode(True)
        return {
            "index": index,
            "status": status,
            "encodedList": new_encoded
        }
