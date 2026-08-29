from __future__ import annotations
import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from docutrust.crypto import canonicalize_json, sha256_hex, MerkleTree
from docutrust.pqc import generate_pqc_hybrid_keys, shake256_sponge_hex
from docutrust.client import DocuTrustClient

class TestDocuTrustPython(unittest.TestCase):
    def test_canonicalize_json(self):
        obj1 = {"z": 10, "a": "hello", "m": [3, 2, 1]}
        obj2 = {"a": "hello", "m": [3, 2, 1], "z": 10}
        self.assertEqual(canonicalize_json(obj1), canonicalize_json(obj2))
        self.assertEqual(canonicalize_json(None), "null")
        self.assertEqual(canonicalize_json(True), "true")

    def test_merkle_tree(self):
        leaves = ["degree_001", "degree_002", "degree_003", "degree_004"]
        tree = MerkleTree(leaves)
        root = tree.get_root()
        self.assertEqual(len(root), 64)

        for i, leaf in enumerate(leaves):
            proof = tree.get_proof(i)
            self.assertTrue(MerkleTree.verify_proof(leaf, proof, root))
            self.assertFalse(MerkleTree.verify_proof(leaf + "_tampered", proof, root))

    def test_merkle_tree_empty_error(self):
        with self.assertRaises(ValueError):
            MerkleTree([])

    def test_merkle_tree_invalid_index(self):
        tree = MerkleTree(["a", "b"])
        with self.assertRaises(IndexError):
            tree.get_proof(10)

    def test_pqc_generation(self):
        keys = generate_pqc_hybrid_keys()
        self.assertIn("pqcPublicKeyHex", keys)
        self.assertEqual(len(keys["pqcPublicKeyHex"]), 64)
        self.assertEqual(keys["algorithm"], "ML-DSA-65-Ed25519-Hybrid")

    def test_shake256_sponge(self):
        h = shake256_sponge_hex("test", 32)
        self.assertEqual(len(h), 64)

    @patch('requests.Session.post')
    def test_client_issue(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"success": True, "credential": {"id": "urn:uuid:123"}}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        client = DocuTrustClient(api_url="https://api.docutrust.org/api/v1", api_key="test-key")
        result = client.issue_credential({"name": "Elena"}, "UniversityDegreeCredential")
        self.assertTrue(result["success"])
        self.assertEqual(result["credential"]["id"], "urn:uuid:123")

    @patch('requests.Session.post')
    def test_client_verify(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"valid": True, "signatureValid": True}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        client = DocuTrustClient()
        result = client.verify_credential({"id": "urn:uuid:123"})
        self.assertTrue(result["valid"])

    @patch('requests.Session.post')
    def test_client_verify_pdf(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"valid": True, "recipientName": "Elena"}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        client = DocuTrustClient()
        result = client.verify_pdf(b"%PDF-1.7 ...")
        self.assertTrue(result["valid"])
        self.assertEqual(result["recipientName"], "Elena")

    @patch('requests.Session.post')
    def test_client_batch_issue(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"success": True, "totalIssued": 2}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        client = DocuTrustClient()
        result = client.batch_issue([{"name": "Alice"}, {"name": "Bob"}])
        self.assertEqual(result["totalIssued"], 2)

    @patch('requests.Session.post')
    def test_client_selective_disclosure(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"success": True, "disclosedClaims": [{"key": "name"}]}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        client = DocuTrustClient()
        result = client.generate_selective_disclosure({"credentialSubject": {"name": "Alice"}}, ["name"])
        self.assertTrue(result["success"])

if __name__ == '__main__':
    unittest.main()

