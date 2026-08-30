from __future__ import annotations
import hashlib
from typing import Dict, Any, List, Optional, Union
from .crypto import sha256_hex

class SparseMerkleTree:
    """256-bit Sparse Merkle Tree (SMT) for Python (DocuTrust v10.0.0)."""

    def __init__(self, depth: int = 256):
        self.depth = depth
        self.db: Dict[str, str] = {}
        self.leaf_db: Dict[str, str] = {}
        self.default_hashes: List[str] = self._compute_default_hashes(depth)

    def _compute_default_hashes(self, depth: int) -> List[str]:
        defaults = ['0' * 64] * (depth + 1)
        for d in range(1, depth + 1):
            prev = defaults[d - 1]
            defaults[d] = self._hash_children(prev, prev)
        return defaults

    def _hash_children(self, left: str, right: str) -> str:
        combined = bytes.fromhex(left) + bytes.fromhex(right)
        return hashlib.sha256(combined).hexdigest()

    @staticmethod
    def normalize_key(key: str) -> str:
        clean = key.replace('0x', '').strip()
        if len(clean) == 64 and all(c in '0123456789abcdefABCDEF' for c in clean):
            return clean.lower()
        return hashlib.sha256(key.encode('utf-8')).hexdigest().lower()

    @staticmethod
    def hash_leaf(key_hex: str, value_hex: str) -> str:
        clean_key = SparseMerkleTree.normalize_key(key_hex)
        clean_val = value_hex.replace('0x', '').lower()
        payload = f'SMT_LEAF:{clean_key}:{clean_val}'.encode('utf-8')
        return hashlib.sha256(payload).hexdigest()

    def _key_to_bits(self, key_hex: str) -> str:
        clean = SparseMerkleTree.normalize_key(key_hex)
        bits = []
        for ch in clean:
            nibble = int(ch, 16)
            bits.append(bin(nibble)[2:].rjust(4, '0'))
        return ''.join(bits)[:self.depth]

    def set(self, key_hex: str, value_hex: str) -> None:
        clean_key = SparseMerkleTree.normalize_key(key_hex)
        clean_val = value_hex.replace('0x', '').lower()

        if clean_val in ('', '00', '0' * 64):
            self.leaf_db.pop(clean_key, None)
        else:
            self.leaf_db[clean_key] = clean_val

        bits = self._key_to_bits(clean_key)
        current_hash = self.hash_leaf(clean_key, self.leaf_db[clean_key]) if clean_key in self.leaf_db else self.default_hashes[0]

        path_prefix = bits
        self.db[path_prefix] = current_hash

        for d in range(1, self.depth + 1):
            bit = bits[self.depth - d]
            parent_prefix = bits[:self.depth - d]
            sibling_bit = '1' if bit == '0' else '0'
            sibling_prefix = parent_prefix + sibling_bit

            sibling_hash = self.db.get(sibling_prefix, self.default_hashes[d - 1])

            if bit == '0':
                current_hash = self._hash_children(current_hash, sibling_hash)
            else:
                current_hash = self._hash_children(sibling_hash, current_hash)

            self.db[parent_prefix] = current_hash

    def get(self, key_hex: str) -> Optional[str]:
        clean_key = SparseMerkleTree.normalize_key(key_hex)
        return self.leaf_db.get(clean_key)

    def get_root(self) -> str:
        return self.db.get('', self.default_hashes[self.depth])

    def prove(self, key_hex: str) -> Dict[str, Any]:
        clean_key = SparseMerkleTree.normalize_key(key_hex)
        value = self.leaf_db.get(clean_key, '0' * 64)
        exists = clean_key in self.leaf_db
        bits = self._key_to_bits(clean_key)

        siblings = []
        for d in range(1, self.depth + 1):
            bit = bits[self.depth - d]
            parent_prefix = bits[:self.depth - d]
            sibling_bit = '1' if bit == '0' else '0'
            sibling_prefix = parent_prefix + sibling_bit

            sibling_hash = self.db.get(sibling_prefix, self.default_hashes[d - 1])
            siblings.append({
                'depth': d,
                'hash': sibling_hash,
                'isRight': bit == '0'
            })

        return {
            'type': 'DocuTrustSparseMerkleProof2026',
            'root': self.get_root(),
            'key': clean_key,
            'value': value,
            'exists': exists,
            'siblings': siblings
        }

    @staticmethod
    def verify_proof(proof: Dict[str, Any], expected_root: Optional[str] = None) -> bool:
        if not proof or proof.get('type') != 'DocuTrustSparseMerkleProof2026':
            return False

        clean_key = SparseMerkleTree.normalize_key(proof.get('key', ''))
        clean_val = proof.get('value', '').replace('0x', '').lower()
        target_root = (expected_root or proof.get('root', '')).replace('0x', '').lower()

        current_hash = SparseMerkleTree.hash_leaf(clean_key, clean_val) if proof.get('exists') else ('0' * 64)

        for sib in proof.get('siblings', []):
            sib_hash = sib.get('hash', '')
            if sib.get('isRight'):
                combined = bytes.fromhex(current_hash) + bytes.fromhex(sib_hash)
            else:
                combined = bytes.fromhex(sib_hash) + bytes.fromhex(current_hash)
            current_hash = hashlib.sha256(combined).hexdigest()

        return current_hash.lower() == target_root
