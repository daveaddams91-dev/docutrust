import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from docutrust.crypto import canonicalize_json, sha256_hex, MerkleTree

class TestDocuTrustPython(unittest.TestCase):
    def test_canonicalize_json(self):
        obj1 = {"z": 10, "a": "hello", "m": [3, 2, 1]}
        obj2 = {"a": "hello", "m": [3, 2, 1], "z": 10}
        self.assertEqual(canonicalize_json(obj1), canonicalize_json(obj2))

    def test_merkle_tree(self):
        leaves = ["degree_001", "degree_002", "degree_003", "degree_004"]
        tree = MerkleTree(leaves)
        root = tree.get_root()
        self.assertEqual(len(root), 64)

        for i, leaf in enumerate(leaves):
            proof = tree.get_proof(i)
            self.assertTrue(MerkleTree.verify_proof(leaf, proof, root))
            self.assertFalse(MerkleTree.verify_proof(leaf + "_tampered", proof, root))

if __name__ == '__main__':
    unittest.main()
