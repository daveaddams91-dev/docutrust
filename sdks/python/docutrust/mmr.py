from __future__ import annotations
import hashlib
import math
from typing import List, Dict, Any, Union

class MerkleMountainRange:
    """Merkle Mountain Range (MMR) high-throughput append-only ledger."""
    def __init__(self, initial_leaves: Optional[List[str]] = None):
        self.leaves: List[str] = []
        if initial_leaves:
            for leaf in initial_leaves:
                self.append(leaf)

    def append(self, leaf: Union[str, bytes]) -> Dict[str, Any]:
        leaf_bytes = leaf.encode('utf-8') if isinstance(leaf, str) else leaf
        leaf_hash = hashlib.sha256(b"\x00" + leaf_bytes).hexdigest()
        idx = len(self.leaves)
        self.leaves.append(leaf_hash)
        return {
            "index": idx,
            "hash": leaf_hash,
            "peakRoot": self.get_bagged_peak_root()
        }

    def get_peaks(self) -> List[str]:
        if not self.leaves:
            return []
        peaks: List[str] = []
        remaining = len(self.leaves)
        offset = 0

        while remaining > 0:
            power = 1 << int(math.floor(math.log2(remaining)))
            sub = self.leaves[offset:offset + power]
            layer = sub
            while len(layer) > 1:
                nxt = []
                for i in range(0, len(layer), 2):
                    h = hashlib.sha256(b"\x01" + bytes.fromhex(layer[i]) + bytes.fromhex(layer[i + 1])).hexdigest()
                    nxt.append(h)
                layer = nxt
            peaks.append(layer[0])
            offset += power
            remaining -= power
        return peaks

    def get_bagged_peak_root(self) -> str:
        peaks = self.get_peaks()
        if not peaks:
            return "0x" + "0" * 64
        if len(peaks) == 1:
            return peaks[0]
        root = peaks[-1]
        for i in range(len(peaks) - 2, -1, -1):
            root = hashlib.sha256(b"\x02" + bytes.fromhex(peaks[i]) + bytes.fromhex(root)).hexdigest()
        return root

    def get_proof(self, element_index: int) -> Dict[str, Any]:
        if element_index < 0 or element_index >= len(self.leaves):
            raise IndexError(f"Index {element_index} out of bounds.")

        peaks = self.get_peaks()
        element_hash = self.leaves[element_index]
        bagged_peak_root = self.get_bagged_peak_root()

        siblings: List[str] = []
        remaining = len(self.leaves)
        offset = 0

        while remaining > 0:
            power = 1 << int(math.floor(math.log2(remaining)))
            if offset <= element_index < offset + power:
                local_idx = element_index - offset
                layer = self.leaves[offset:offset + power]
                while len(layer) > 1:
                    is_right = (local_idx % 2 == 1)
                    sib_idx = local_idx - 1 if is_right else local_idx + 1
                    pos = 'L' if is_right else 'R'
                    siblings.append(f"{pos}:{layer[sib_idx]}")
                    nxt = []
                    for i in range(0, len(layer), 2):
                        h = hashlib.sha256(b"\x01" + bytes.fromhex(layer[i]) + bytes.fromhex(layer[i + 1])).hexdigest()
                        nxt.append(h)
                    layer = nxt
                    local_idx = local_idx // 2
                break
            offset += power
            remaining -= power

        return {
            "elementIndex": element_index,
            "elementHash": element_hash,
            "peakHashes": peaks,
            "siblings": siblings,
            "baggedPeakRoot": bagged_peak_root,
            "size": len(self.leaves)
        }

    @staticmethod
    def verify_proof(proof: Dict[str, Any]) -> bool:
        peaks = proof.get("peakHashes", [])
        if not peaks:
            return False

        # If siblings are provided, verify elementHash leads to one of the peaks
        siblings = proof.get("siblings", [])
        if siblings:
            curr = proof["elementHash"]
            for sib in siblings:
                is_left = sib.startswith("L:")
                sib_hash = sib[2:] if ":" in sib else sib
                left_buf = bytes.fromhex(sib_hash if is_left else curr)
                right_buf = bytes.fromhex(curr if is_left else sib_hash)
                curr = hashlib.sha256(b"\x01" + left_buf + right_buf).hexdigest()
            if curr not in peaks:
                return False
        elif proof.get("elementHash") and proof.get("size") == 1:
            if proof["elementHash"] not in peaks:
                return False

        root = peaks[-1]
        for i in range(len(peaks) - 2, -1, -1):
            root = hashlib.sha256(b"\x02" + bytes.fromhex(peaks[i]) + bytes.fromhex(root)).hexdigest()
        return root == proof.get("baggedPeakRoot")

    @property
    def size(self) -> int:
        return len(self.leaves)
