from __future__ import annotations
import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from docutrust.crypto import canonicalize_json, sha256_hex, MerkleTree, encode_base58, decode_base58
from docutrust.pqc import generate_pqc_hybrid_keys, shake256_sponge_hex
from docutrust.client import DocuTrustClient
from docutrust.encryption import encrypt_aes_gcm, decrypt_aes_gcm
from docutrust.zk_predicates import (
    prove_range,
    verify_range_proof,
    create_commitment,
    prove_age_above,
    verify_age_proof,
    prove_date_range,
    verify_date_range_proof,
    prove_set_membership,
    verify_set_membership_proof,
    prove_set_non_membership,
    verify_set_non_membership_proof,
    prove_composite_predicate,
    verify_composite_predicate
)
from docutrust.kem import generate_kem_keypair
from docutrust.shamir import split_secret, combine_shares
from docutrust.bbs import generate_bbs_keypair, sign_bbs, derive_bbs_proof, verify_bbs_proof
from docutrust.oracle import issue_timestamp_token, verify_timestamp_token
from docutrust.didcomm import pack_didcomm_message, unpack_didcomm_message
from docutrust.mmr import MerkleMountainRange
from docutrust.eip712 import generate_secp256k1_key_pair, sign_vc_eip712, verify_vc_eip712
from docutrust.social_recovery import SocialRecoveryEngine
from docutrust.multichain import MultiChainLedgerAnchor

class TestDocuTrustPython(unittest.TestCase):
    def test_didcomm_messaging(self):
        msg = {"id": "msg-py-01", "body": {"greeting": "Python Zero-Trust"}}
        rec_pub = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
        rec_did = "did:key:zBob"
        sender_did = "did:key:zAlice"

        env = pack_didcomm_message(msg, sender_did, rec_pub, rec_did)
        self.assertTrue("ciphertext" in env)

        unpacked = unpack_didcomm_message(env, rec_pub, sender_did)
        self.assertTrue(unpacked["valid"])
        self.assertEqual(unpacked["message"]["body"]["greeting"], "Python Zero-Trust")

    def test_merkle_mountain_range(self):
        mmr = MerkleMountainRange()
        mmr.append("Block #1")
        mmr.append("Block #2")
        mmr.append("Block #3")
        self.assertEqual(mmr.size, 3)

        proof = mmr.get_proof(1)
        self.assertTrue(MerkleMountainRange.verify_proof(proof))

        # Tampered proof should fail
        tampered_proof = dict(proof)
        tampered_proof["elementHash"] = tampered_proof["elementHash"][:-2] + "ff"
        self.assertFalse(MerkleMountainRange.verify_proof(tampered_proof))
    def test_bbs_signatures_and_zk_proofs(self):
        kp = generate_bbs_keypair(5)
        self.assertTrue(kp["did"].startswith("did:bbs:z"))
        messages = ["Alice", "MIT", "Ph.D."]
        sig = sign_bbs(messages, kp)
        self.assertEqual(sig["messageCount"], 3)

        proof = derive_bbs_proof(sig, messages, [1, 2], kp)
        audit = verify_bbs_proof(proof, kp["did"])
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["disclosedMessages"][1], "MIT")

    def test_tsa_oracle_token(self):
        data = "Blockchain Record 2026"
        token = issue_timestamp_token(data)
        self.assertEqual(token["type"], "DocuTrustTimestampToken2026")
        audit = verify_timestamp_token(token, data)
        self.assertTrue(audit["valid"])
        self.assertGreaterEqual(audit["ageSeconds"], 0)

    def test_shamir_secret_sharing(self):
        secret = "MasterSecretKeyForPythonSDK2026!"
        shares = split_secret(secret, 5, 3)
        self.assertEqual(len(shares), 5)
        self.assertEqual(shares[0]["threshold"], 3)

        reconstructed = combine_shares([shares[0], shares[2], shares[4]])
        self.assertEqual(reconstructed.decode('utf-8'), secret)

        with self.assertRaises(ValueError):
            combine_shares([shares[0], shares[1]])
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

    def test_aes_gcm_envelope_encryption(self):
        secret = "Diplomatic Grade Secret VC 2026"
        passphrase = "UltraVaultPassphrase2026!"
        encrypted = encrypt_aes_gcm(secret, passphrase)
        self.assertEqual(encrypted["algorithm"], "AES-256-GCM")
        self.assertEqual(len(encrypted["authTag"]), 32)

        decrypted = decrypt_aes_gcm(encrypted, passphrase)
        self.assertEqual(decrypted.decode('utf-8'), secret)

    def test_zk_range_proof(self):
        actual_gpa = 3.92
        comm = create_commitment(actual_gpa)
        proof = prove_range("gpa", actual_gpa, comm["salt"], 3.5, 4.0)
        self.assertEqual(proof["type"], "ZKRangePredicateProof2026")

        audit = verify_range_proof(proof, comm["commitment"])
        self.assertTrue(audit["valid"])

    def test_zk_age_proof(self):
        proof = prove_age_above("birthDate", "2000-01-01", 21, reference_date_str="2026-08-29")
        self.assertEqual(proof["type"], "ZKAgePredicateProof2026")
        self.assertEqual(proof["minimumAgeYears"], 21)
        audit = verify_age_proof(proof, proof["commitment"])
        self.assertTrue(audit["valid"])

        with self.assertRaises(ValueError):
            prove_age_above("birthDate", "2015-01-01", 21, reference_date_str="2026-08-29")

    def test_zk_date_range_proof(self):
        proof = prove_date_range("graduationDate", "2024-06-15", "2020-01-01", "2026-12-31")
        self.assertEqual(proof["type"], "ZKDatePredicateProof2026")
        audit = verify_date_range_proof(proof, proof["commitment"])
        self.assertTrue(audit["valid"])

        with self.assertRaises(ValueError):
            prove_date_range("graduationDate", "2019-01-01", "2020-01-01", "2026-12-31")

    def test_kem_key_generation(self):
        keys = generate_kem_keypair()
        self.assertTrue(keys["hybridRecipientId"].startswith("did:kem:z"))
        self.assertEqual(len(keys["publicKeyHex"]), 64)

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

    @patch('requests.Session.post')
    def test_client_encrypt_decrypt(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"success": True, "encrypted": {"ciphertext": "abc"}}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        client = DocuTrustClient()
        res = client.encrypt_data({"secret": 123}, "pass")
        self.assertTrue(res["success"])

    @patch('requests.Session.post')
    def test_client_zk_and_pop(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"success": True, "challenge": {"challengeId": "pop_123"}}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        client = DocuTrustClient()
        res = client.create_pop_challenge()
        self.assertTrue(res["success"])

    @patch('requests.Session.post')
    def test_client_extended_features(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"success": True}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        client = DocuTrustClient()
        self.assertTrue(client.shamir_split("secret")["success"])
        self.assertTrue(client.shamir_combine([{"index": 1}])["success"])
        self.assertTrue(client.issue_sd_jwt({"gpa": 3.9})["success"])
        self.assertTrue(client.verify_sd_jwt("token")["success"])
        self.assertTrue(client.verify_trust_issuer("did:key:123", "Degree")["success"])
        self.assertTrue(client.create_bloom_filter(["id1"])["success"])
        self.assertTrue(client.check_bloom_filter({}, "id1")["success"])
        self.assertTrue(client.bbs_generate_keys()["success"])
        self.assertTrue(client.bbs_issue(["msg1"])["success"])
        self.assertTrue(client.bbs_derive_proof({}, ["msg1"], [0])["success"])
        self.assertTrue(client.bbs_verify_proof({})["success"])
        self.assertTrue(client.issue_timestamp_token("data")["success"])
        self.assertTrue(client.verify_timestamp_token({})["success"])
        self.assertTrue(client.didcomm_pack({}, "pub", "did")["success"])
        self.assertTrue(client.didcomm_unpack({}, {})["success"])
        self.assertTrue(client.mmr_append("leaf")["success"])
        self.assertTrue(client.mmr_get_proof(0)["success"])
        self.assertTrue(client.mmr_verify_proof({})["success"])
        self.assertTrue(client.auto_anchor_vault()["success"])
        self.assertTrue(client.prove_zk_age("2000-01-01", 18)["success"])
        self.assertTrue(client.verify_zk_age({})["success"])
        self.assertTrue(client.prove_zk_date("2024-06-15", "2020-01-01", "2026-12-31")["success"])
        self.assertTrue(client.verify_zk_date({})["success"])
        self.assertTrue(client.prove_zk_membership("degree", "Computer Science", ["Computer Science", "Physics"])["success"])
        self.assertTrue(client.verify_zk_membership({}, ["Computer Science", "Physics"])["success"])

    def test_zk_set_membership_proof(self):
        allowed = ["Stanford", "MIT", "Oxford", "Cambridge"]
        secret = "MIT"
        salt = os.urandom(16).hex()
        proof = prove_set_membership("university", secret, salt, allowed)
        self.assertEqual(proof["type"], "ZKSetMembershipProof2026")
        audit = verify_set_membership_proof(proof, allowed, proof["commitment"])
        self.assertTrue(audit["valid"])

        # Secret not in allowed set
        with self.assertRaises(ValueError):
            prove_set_membership("university", "Harvard", salt, allowed)

        # Mismatched allowed set during verification
        audit_tampered = verify_set_membership_proof(proof, ["Stanford", "MIT"])
        self.assertFalse(audit_tampered["valid"])

    def test_base58_edge_cases(self):
        self.assertEqual(encode_base58(b""), "")
        self.assertEqual(decode_base58(""), b"")
        raw = b"DocuTrust 2026"
        self.assertEqual(decode_base58(encode_base58(raw)), raw)

    def test_shamir_duplicate_and_length_validation(self):
        secret = "PythonShamirSecret2026"
        shares = split_secret(secret, 5, 3)
        self.assertEqual(len(shares), 5)
        reconstructed = combine_shares([shares[0], shares[2], shares[4]])
        self.assertEqual(reconstructed.decode('utf-8'), secret)

        # Duplicate shares
        with self.assertRaises(ValueError):
            combine_shares([shares[0], shares[0], shares[1]])

        # Mismatched share length
        corrupted = {**shares[2], "shareHex": shares[2]["shareHex"][:8]}
        with self.assertRaises(ValueError):
            combine_shares([shares[0], shares[1], corrupted])

    def test_tsa_oracle_verification(self):
        data = "Government Issued Patent Claim #98124"
        token = issue_timestamp_token(data)
        self.assertEqual(token["type"], "DocuTrustTimestampToken2026")
        self.assertEqual(token["version"], "2.1.1")
        audit = verify_timestamp_token(token, data)
        self.assertTrue(audit["valid"])
        self.assertGreaterEqual(audit["ageSeconds"], 0)

        # Hash mismatch
        audit_bad = verify_timestamp_token(token, data + " tampered")
        self.assertFalse(audit_bad["valid"])

    @patch('requests.Session.get')
    def test_client_get_endpoints(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"success": True}
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        client = DocuTrustClient()
        self.assertTrue(client.mmr_get_peaks()["success"])
        self.assertTrue(client.get_hashchain()["success"])
        self.assertTrue(client.get_vault_metrics()["success"])

    def test_eip712_signing_and_verification(self):
        eth_key = generate_secp256k1_key_pair(1)
        self.assertTrue(eth_key["did"].startswith("did:pkh:eip155:1:0x"))
        self.assertTrue(eth_key["ethereumAddress"].startswith("0x"))

        vc = {
            "id": "urn:uuid:py-eth-vc-01",
            "issuer": eth_key["did"],
            "credentialSubject": {"degree": "Python Quantum Master", "gpa": 4.0}
        }
        signed = sign_vc_eip712(vc, eth_key)
        self.assertEqual(signed["proof"]["type"], "EthereumEip712Signature2026")
        self.assertTrue(signed["proof"]["signature"].startswith("0x"))

        audit = verify_vc_eip712(signed, eth_key["ethereumAddress"])
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["signerAddress"], eth_key["ethereumAddress"].lower())

    def test_social_recovery_and_veto(self):
        secret = "PythonRootSecretKeyHex12345678"
        owner_did = "did:key:zOwner"
        guardians = [
            {"did": "did:key:zG1", "name": "Guardian 1"},
            {"did": "did:key:zG2", "name": "Guardian 2"},
            {"did": "did:key:zG3", "name": "Guardian 3"}
        ]
        setup = SocialRecoveryEngine.setup_recovery(owner_did, secret, guardians, 2, 24)
        self.assertEqual(len(setup["guardians"]), 3)

        session = SocialRecoveryEngine.initiate_recovery(owner_did, "did:key:zReq", setup["config"])
        session = SocialRecoveryEngine.cast_vote(session, guardians[0]["did"], setup["rawShares"][0]["index"], setup["rawShares"][0]["shareHex"])
        session = SocialRecoveryEngine.cast_vote(session, guardians[1]["did"], setup["rawShares"][1]["index"], setup["rawShares"][1]["shareHex"])

        final = SocialRecoveryEngine.finalize_recovery(session, force_timelock_override=True)
        self.assertEqual(final["status"], "SUCCESS")
        self.assertEqual(final["reconstructedSecret"], secret)

        # Test Veto
        veto_session = SocialRecoveryEngine.initiate_recovery(owner_did, "did:key:zMal", setup["config"])
        veto_session = SocialRecoveryEngine.veto_recovery(veto_session, "Unauthorized access detected")
        self.assertEqual(veto_session["status"], "VETOED_BY_OWNER")
        veto_res = SocialRecoveryEngine.finalize_recovery(veto_session, force_timelock_override=True)
        self.assertEqual(veto_res["status"], "VETOED")

    def test_zk_non_membership_and_composite(self):
        secret_id = "USER-CLEARED-99"
        comm = create_commitment(secret_id)
        restricted = ["SANCTIONED-A", "SANCTIONED-B"]

        proof = prove_set_non_membership("userId", secret_id, comm["salt"], restricted)
        self.assertEqual(proof["type"], "ZKSetNonMembershipProof2026")
        audit = verify_set_non_membership_proof(proof, restricted)
        self.assertTrue(audit["valid"])

        # Composite predicate
        age_p = prove_age_above("birthDate", "2000-01-01", 21, reference_date_str="2026-08-29")
        comp = prove_composite_predicate([proof, age_p])
        comp_audit = verify_composite_predicate(comp, {"restrictedSets": {"userId": restricted}})
        self.assertTrue(comp_audit["valid"])
        self.assertEqual(comp_audit["verifiedCount"], 2)

    def test_multichain_anchor_generation(self):
        root = "0x1122334455667788990011223344556677889900112233445566778899001122"
        eth = MultiChainLedgerAnchor.format_anchor("ethereum", root, 500)
        self.assertTrue(eth["calldataHex"].startswith("0x892a4b12"))

        btc = MultiChainLedgerAnchor.format_anchor("bitcoin", root, 500)
        self.assertTrue(btc["opReturnHex"].startswith("0x6a28"))

        sol = MultiChainLedgerAnchor.format_anchor("solana", root, 500)
        self.assertTrue(sol["instructionDataHex"].startswith("0x"))

if __name__ == '__main__':
    unittest.main()


