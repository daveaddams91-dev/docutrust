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
    digits = [0]
    for byte in buffer:
        for j in range(len(digits)):
            digits[j] <<= 8
        digits[0] += byte
        carry = 0
        for j in range(len(digits)):
            digits[j] += carry
            carry = digits[j] // 58
            digits[j] %= 58
        while carry > 0:
            digits.append(carry % 58)
            carry = carry // 58
    for byte in buffer:
        if byte == 0:
            digits.append(0)
        else:
            break
    return ''.join(BASE58_ALPHABET[d] for d in reversed(digits))

def decode_base58(s: str) -> bytes:
    """Base58 decoding helper."""
    bytes_arr = [0]
    for char in s:
        value = BASE58_ALPHABET.index(char)
        for j in range(len(bytes_arr)):
            bytes_arr[j] *= 58
        bytes_arr[0] += value
        carry = 0
        for j in range(len(bytes_arr)):
            bytes_arr[j] += carry
            carry = bytes_arr[j] >> 8
            bytes_arr[j] &= 0xFF
        while carry > 0:
            bytes_arr.append(carry & 0xFF)
            carry >>= 8
    for char in s:
        if char == '1':
            bytes_arr.append(0)
        else:
            break
    return bytes(reversed(bytes_arr))

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
