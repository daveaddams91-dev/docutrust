from __future__ import annotations
import hashlib
import json
import os
from typing import Dict, Any, List, Tuple, Optional, Union

def canonicalize_json(obj: Any) -> str:
    """RFC 8785 JSON Canonicalization Scheme."""
    if obj is None or isinstance(obj, (int, float, bool, str)):
        return json.dumps(obj, separators=(',', ':'), ensure_ascii=False)
    if isinstance(obj, list):
        return '[' + ','.join(canonicalize_json(x) for x in obj) + ']'
    if isinstance(obj, dict):
        sorted_keys = sorted(obj.keys())
        return '{' + ','.join(f'{json.dumps(k)}:{canonicalize_json(obj[k])}' for k in sorted_keys) + '}'
    return json.dumps(obj)

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def encode_base58(buffer: bytes) -> str:
    """Base58 encoding helper."""
    if not buffer:
        return ""
    leading_zeros = 0
    for byte in buffer:
        if byte == 0:
            leading_zeros += 1
        else:
            break
    num = int.from_bytes(buffer, 'big')
    encoded = []
    while num > 0:
        num, rem = divmod(num, 58)
        encoded.append(BASE58_ALPHABET[rem])
    return ('1' * leading_zeros) + ''.join(reversed(encoded))

def decode_base58(s: str) -> bytes:
    """Base58 decoding helper."""
    if not s:
        return b""
    leading_ones = 0
    for char in s:
        if char == '1':
            leading_ones += 1
        else:
            break
    num = 0
    for char in s:
        num = num * 58 + BASE58_ALPHABET.index(char)
    num_bytes = []
    while num > 0:
        num, rem = divmod(num, 256)
        num_bytes.append(rem)
    return (b'\x00' * leading_ones) + bytes(reversed(num_bytes))


def sha256_hex(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

class MerkleTree:
    """Merkle Tree with Domain Separation (0x00 for leaves, 0x01 for interior nodes)."""
    def __init__(self, leaves: List[Union[str, bytes]]):
        if not leaves:
            raise ValueError("Leaves cannot be empty")
        self.leaves = [
            hashlib.sha256(b"\x00" + (leaf.encode('utf-8') if isinstance(leaf, str) else leaf)).hexdigest()
            for leaf in leaves
        ]
        self.layers = [self.leaves]
        self._build_tree()

    def _hash_pair(self, left_hex: str, right_hex: str) -> str:
        left_buf = bytes.fromhex(left_hex)
        right_buf = bytes.fromhex(right_hex)
        return hashlib.sha256(b"\x01" + left_buf + right_buf).hexdigest()

    def _build_tree(self):
        current = self.leaves
        while len(current) > 1:
            next_layer = []
            for i in range(0, len(current), 2):
                left = current[i]
                if i + 1 < len(current):
                    right = current[i + 1]
                    next_layer.append(self._hash_pair(left, right))
                else:
                    next_layer.append(self._hash_pair(left, left))
            self.layers.append(next_layer)
            current = next_layer

    def get_root(self) -> str:
        return self.layers[-1][0]

    def get_proof(self, leaf_index: int) -> Dict[str, Any]:
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError("Leaf index out of range")
        audit_path = []
        idx = leaf_index
        for layer in self.layers[:-1]:
            is_right = (idx % 2 == 1)
            pair_idx = idx - 1 if is_right else idx + 1
            if pair_idx < len(layer):
                audit_path.append({
                    "position": "left" if is_right else "right",
                    "data": layer[pair_idx]
                })
            else:
                audit_path.append({
                    "position": "right",
                    "data": layer[idx]
                })
            idx = idx // 2
        return {
            "leafHash": self.leaves[leaf_index],
            "leafIndex": leaf_index,
            "rootHash": self.get_root(),
            "totalLeaves": len(self.leaves),
            "auditPath": audit_path
        }

    @staticmethod
    def verify_proof(raw_leaf_data: Optional[Union[str, bytes]], proof: Dict[str, Any], expected_root: Optional[str] = None) -> bool:
        root = expected_root or proof["rootHash"]
        if raw_leaf_data is not None:
            buf = raw_leaf_data.encode('utf-8') if isinstance(raw_leaf_data, str) else raw_leaf_data
            current_hash = hashlib.sha256(b"\x00" + buf).hexdigest()
            if current_hash != proof["leafHash"]:
                return False
        else:
            current_hash = proof["leafHash"]

        for step in proof["auditPath"]:
            step_buf = bytes.fromhex(step["data"])
            curr_buf = bytes.fromhex(current_hash)
            if step["position"] == "left":
                current_hash = hashlib.sha256(b"\x01" + step_buf + curr_buf).hexdigest()
            else:
                current_hash = hashlib.sha256(b"\x01" + curr_buf + step_buf).hexdigest()

        return current_hash.lower() == root.lower()
