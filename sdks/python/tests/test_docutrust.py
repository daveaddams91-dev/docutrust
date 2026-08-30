from __future__ import annotations
import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import json
import hashlib

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
from docutrust.anoncreds import AnonCredsEngine
from docutrust.dkg import DKGEngine
from docutrust.solidity import SolidityEngine
from docutrust.bundle import AuditBundleEngine
from docutrust.dataintegrity import DataIntegrityEngine
from docutrust.confidential import PaillierCryptosystem, ConfidentialClaimsEngine
from docutrust.jsonld import JsonLdCanonicalizationEngine
from docutrust.accumulator import CryptographicAccumulator
from docutrust.trustchain import TrustChainEngine
from docutrust.quantum_armor import DualHybridKEMEngine
from docutrust.badge import BadgeEngine
from docutrust.did import DIDResolver

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

    def test_schema_validator(self):
        from docutrust.schema import SchemaValidator
        schema = {
            "$id": "https://schema.docutrust.org/student.json",
            "type": "object",
            "required": ["studentId", "gpa"],
            "properties": {
                "studentId": {"type": "string", "pattern": r"^STU-\d{4}$"},
                "gpa": {"type": "number", "minimum": 0.0, "maximum": 4.0}
            },
            "additionalProperties": False
        }
        schema_hash = SchemaValidator.compute_schema_hash(schema)
        self.assertEqual(len(schema_hash), 64)

        valid_subject = {"studentId": "STU-9901", "gpa": 3.95}
        res_valid = SchemaValidator.validate(valid_subject, schema)
        self.assertTrue(res_valid["valid"])

        invalid_subject = {"studentId": "BAD_ID", "gpa": 4.5, "extra": True}
        res_invalid = SchemaValidator.validate(invalid_subject, schema)
        self.assertFalse(res_invalid["valid"])
        self.assertGreaterEqual(len(res_invalid["errors"]), 3)

        vc = {
            "id": "urn:uuid:vc-test",
            "type": ["VerifiableCredential"],
            "credentialSubject": valid_subject
        }
        self.assertTrue(SchemaValidator.validate_credential_subject(vc, schema)["valid"])

    def test_cryptographic_accumulator(self):
        from docutrust.accumulator import CryptographicAccumulator
        acc = CryptographicAccumulator("acc-py-01")
        m1 = "did:key:z6Mku1111111111111111111111111111111111111111111"
        m2 = "did:key:z6Mku2222222222222222222222222222222222222222222"
        m3 = "did:key:z6Mku3333333333333333333333333333333333333333333"

        acc.add(m1)
        acc.add_batch([m2, m3])
        state = acc.export_state()
        self.assertEqual(state["member_count"], 3)

        w2 = acc.create_witness(m2)
        self.assertTrue(CryptographicAccumulator.verify_witness(w2, state["accumulator"]))

        acc.delete(m2)
        state_after = acc.export_state()
        self.assertEqual(state_after["member_count"], 2)
        self.assertFalse(CryptographicAccumulator.verify_witness(w2, state_after["accumulator"]))

        w1 = acc.create_witness(m1)
        self.assertTrue(CryptographicAccumulator.verify_witness(w1, state_after["accumulator"]))

    def test_multi_recipient_jwe(self):
        from docutrust.jwe import MultiRecipientJWE
        r1 = MultiRecipientJWE.generate_recipient_keypair()
        r2 = MultiRecipientJWE.generate_recipient_keypair()
        outsider = MultiRecipientJWE.generate_recipient_keypair()

        payload = {"confidentialAudit": "TOP-SECRET-RECORD-2026", "score": 99}
        recipients = [
            {"did": r1["did"], "publicKey": r1["publicKeyHex"]},
            {"did": r2["did"], "publicKey": r2["publicKeyHex"]}
        ]

        jwe = MultiRecipientJWE.encrypt(payload, recipients)
        self.assertIn("ciphertext", jwe)
        self.assertEqual(len(jwe["recipients"]), 2)

        dec1 = MultiRecipientJWE.decrypt(jwe, r1["did"], r1["privateKeyHex"])
        self.assertEqual(dec1["parsed_json"], payload)

        dec2 = MultiRecipientJWE.decrypt(jwe, r2["did"], r2["privateKeyHex"])
        self.assertEqual(dec2["parsed_json"], payload)

        with self.assertRaises(ValueError):
            MultiRecipientJWE.decrypt(jwe, outsider["did"], outsider["privateKeyHex"])

    def test_zk_set_intersection_and_composite(self):
        from docutrust.zk_predicates import prove_set_intersection, verify_set_intersection_proof, prove_composite_predicate, verify_composite_predicate
        secret_badge = "SECURITY-CLEARANCE-LEVEL-4"
        salt = os.urandom(16).hex()
        recognized = ["SECURITY-CLEARANCE-LEVEL-3", "SECURITY-CLEARANCE-LEVEL-4", "SECURITY-CLEARANCE-LEVEL-5"]

        proof = prove_set_intersection("clearance", secret_badge, salt, recognized)
        self.assertEqual(proof["type"], "ZKSetIntersectionProof2026")

        audit = verify_set_intersection_proof(proof, recognized)
        self.assertTrue(audit["valid"])

    def test_accumulator_non_membership(self):
        from docutrust.accumulator import CryptographicAccumulator
        acc = CryptographicAccumulator("acc-py-non-mem")
        m1 = "did:key:z6Mku1111111111111111111111111111111111111111111"
        m2 = "did:key:z6Mku2222222222222222222222222222222222222222222"
        outsider = "did:key:z6Mku9999999999999999999999999999999999999999999"

        acc.add_batch([m1, m2])
        state = acc.export_state()

        witness = acc.create_non_membership_witness(outsider)
        self.assertEqual(witness["element"], outsider)
        self.assertTrue(CryptographicAccumulator.verify_non_membership_witness(witness, state["accumulator"]))

        # Creating witness for member should raise
        with self.assertRaises(ValueError):
            acc.create_non_membership_witness(m1)

    def test_bitstring_status_list_2024(self):
        from docutrust.status_list import BitstringStatusList2024
        sl = BitstringStatusList2024(length=1000, status_size=2, status_purpose="revocation")
        self.assertEqual(sl.get_status(15), 0)
        self.assertTrue(sl.is_valid(15))

        sl.set_status(15, 1)  # REVOKED
        self.assertEqual(sl.get_status(15), 1)
        self.assertTrue(sl.is_revoked(15))

        sl.set_status(20, 2)  # SUSPENDED
        self.assertTrue(sl.is_suspended(20))

        encoded = sl.encode(True)
        self.assertTrue(encoded.startswith("u"))

        decoded = BitstringStatusList2024.decode(encoded, {"length": 1000, "status_size": 2})
        self.assertTrue(decoded.is_revoked(15))
        self.assertTrue(decoded.is_suspended(20))
        self.assertTrue(decoded.is_valid(0))

        vc = sl.generate_credential("urn:uuid:status-list-01", "did:key:zIssuer")
        self.assertEqual(vc["type"], ["VerifiableCredential", "StatusList2024Credential"])

    def test_presentation_exchange_20(self):
        from docutrust.presentation_exchange import PresentationExchangeEngine
        desc = [
            {
                "id": "university_degree_desc",
                "schema": [{"uri": "UniversityDegreeCredential"}],
                "constraints": {
                    "fields": [
                        {"path": ["$.credentialSubject.degree"], "filter": {"type": "string", "pattern": "Cybersecurity"}}
                    ]
                }
            }
        ]
        definition = PresentationExchangeEngine.create_definition("employment_check", desc, {"name": "Security Check"})

        pres_valid = {
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [
                {
                    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                    "credentialSubject": {"degree": "M.Sc. Cybersecurity", "gpa": 3.9}
                }
            ]
        }
        res_valid = PresentationExchangeEngine.evaluate_presentation(pres_valid, definition)
        self.assertTrue(res_valid["valid"])
        self.assertEqual(res_valid["matched_descriptors"], ["university_degree_desc"])

        pres_invalid = {
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [
                {
                    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                    "credentialSubject": {"degree": "B.A. Literature"}
                }
            ]
        }
        res_invalid = PresentationExchangeEngine.evaluate_presentation(pres_invalid, definition)
        self.assertFalse(res_invalid["valid"])

    def test_zk_predicate_graph(self):
        from docutrust.zk_predicates import (
            prove_set_membership,
            prove_range,
            create_commitment,
            prove_predicate_graph,
            verify_predicate_graph
        )

        role = "AUDITOR"
        comm1 = create_commitment(role)
        allowed = ["ADMIN", "AUDITOR", "DEV"]
        mem_proof = prove_set_membership("role", role, comm1["salt"], allowed)

        gpa = 3.8
        comm2 = create_commitment(gpa)
        range_proof = prove_range("gpa", gpa, comm2["salt"], 3.5, 4.0)

        tree = {
            "id": "root_policy",
            "operator": "AND",
            "children": [
                {"id": "leaf_mem", "proof": mem_proof},
                {"id": "leaf_range", "proof": range_proof}
            ]
        }

        graph_proof = prove_predicate_graph("graph-py-01", tree)
        self.assertEqual(graph_proof["type"], "ZKPredicateGraphProof2026")

        audit = verify_predicate_graph(graph_proof, {"allowedSets": {"role": allowed}})
        self.assertTrue(audit["valid"])
        self.assertGreaterEqual(audit["verifiedCount"], 2)

    def test_schema_validator_advanced(self):
        from docutrust.schema import SchemaValidator
        advanced_schema = {
            "$id": "https://schema.docutrust.org/advanced.json",
            "$defs": {
                "uuidFormat": {"type": "string", "format": "uuid"}
            },
            "type": "object",
            "required": ["id", "serverIp", "website"],
            "properties": {
                "id": {"$ref": "#/$defs/uuidFormat"},
                "serverIp": {"type": "string", "format": "ipv4"},
                "website": {"type": "string", "format": "hostname"}
            }
        }

        data_valid = {
            "id": "12345678-1234-1234-1234-123456789abc",
            "serverIp": "192.168.1.1",
            "website": "vault.docutrust.org"
        }
        res = SchemaValidator.validate(data_valid, advanced_schema)
        self.assertTrue(res["valid"])

        data_invalid = {
            "id": "not-a-uuid",
            "serverIp": "999.999.999.999",
            "website": "invalid..host"
        }
        res_bad = SchemaValidator.validate(data_invalid, advanced_schema)
        self.assertFalse(res_bad["valid"])
        self.assertEqual(len(res_bad["errors"]), 3)

    def test_multisig_threshold_engine(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from docutrust.crypto import encode_base58
        from docutrust.multisig import MultiSigEngine

        # Generate 2 signer keys
        sk1 = ed25519.Ed25519PrivateKey.generate()
        pk1_bytes = sk1.public_key().public_bytes_raw()
        did1 = f"did:key:z{encode_base58(bytes([0xed, 0x01]) + pk1_bytes)}"

        sk2 = ed25519.Ed25519PrivateKey.generate()
        pk2_bytes = sk2.public_key().public_bytes_raw()
        did2 = f"did:key:z{encode_base58(bytes([0xed, 0x01]) + pk2_bytes)}"

        policy = {
            "policyId": "policy-phd-2026",
            "threshold": 2,
            "authorities": [
                {"did": did1, "role": "Dean"},
                {"did": did2, "role": "Registrar"}
            ]
        }

        cred = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:py-multisig-001",
            "type": ["VerifiableCredential", "PhDDiploma"],
            "issuer": "did:org:stanford",
            "credentialSubject": {"recipient": "Dave", "degree": "Computer Science"}
        }

        draft = MultiSigEngine.create_multisig_draft(cred, policy)
        self.assertTrue(bool(draft["canonicalHash"]))

        sig1 = MultiSigEngine.sign_as_authority(
            draft["canonicalHash"],
            did1,
            "Dean",
            sk1.private_bytes_raw().hex()
        )
        sig2 = MultiSigEngine.sign_as_authority(
            draft["canonicalHash"],
            did2,
            "Registrar",
            sk2.private_bytes_raw().hex()
        )

        assembled = MultiSigEngine.assemble_multisig_credential(cred, policy, [sig1, sig2])
        self.assertIn("proof", assembled)
        self.assertEqual(assembled["proof"]["type"], "MultiSigThresholdSignature2026")

        verify_res = MultiSigEngine.verify_multisig_credential(assembled, policy)
        self.assertTrue(verify_res["valid"])
        self.assertEqual(verify_res["validSignaturesCount"], 2)

    def test_did_resolver(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from docutrust.crypto import encode_base58
        from docutrust.did import DIDResolver

        sk = ed25519.Ed25519PrivateKey.generate()
        pk_bytes = sk.public_key().public_bytes_raw()
        did = f"did:key:z{encode_base58(bytes([0xed, 0x01]) + pk_bytes)}"

        doc = DIDResolver.resolve(did)
        self.assertEqual(doc["id"], did)
        self.assertEqual(len(doc["verificationMethod"]), 1)
        self.assertEqual(doc["verificationMethod"][0]["publicKeyHex"], pk_bytes.hex())

        pkh_doc = DIDResolver.resolve("did:pkh:eip155:1:0x71C83638379321e0b51B8d6Ac7b6C81204d80916")
        self.assertEqual(pkh_doc["id"], "did:pkh:eip155:1:0x71C83638379321e0b51B8d6Ac7b6C81204d80916")

    # ==========================================
    # v5.0.0 AnonCreds 2.0 Tests
    # ==========================================

    def test_anoncreds_engine_lifecycle(self):
        master_secret_obj = AnonCredsEngine.generate_holder_master_secret()
        master_secret = master_secret_obj["masterSecret"]
        schema_id = "schema:docutrust:citizenship:2026"
        issuer_did = "did:key:zGovernment"

        req_res = AnonCredsEngine.create_blind_request(master_secret, schema_id, issuer_did)
        request = req_res["request"]
        blinding_factor = req_res["blindingFactor"]

        self.assertTrue(AnonCredsEngine.verify_blind_request(request))

        claims = {"name": "Alice Doe", "age": 28, "country": "US"}
        blind_cred = AnonCredsEngine.issue_blind_credential(request, claims)
        self.assertEqual(blind_cred["type"], "AnonCredsBlindCredential2026")

        cred = AnonCredsEngine.unblind_credential(blind_cred, master_secret, blinding_factor)
        self.assertEqual(cred["claims"]["country"], "US")

        # Selective disclosure presentation revealing only country
        verifier_nonce = os.urandom(16).hex()
        pres = AnonCredsEngine.create_presentation(cred, master_secret, ["country"], verifier_nonce)
        self.assertIn("country", pres["disclosedClaims"])
        self.assertNotIn("name", pres["disclosedClaims"])

        result = AnonCredsEngine.verify_presentation(pres, verifier_nonce, cred["issuer"])
        self.assertTrue(result["valid"])
        self.assertEqual(result["disclosedClaims"]["country"], "US")

    # ==========================================
    # v5.0.0 FROST DKG Tests
    # ==========================================

    def test_frost_dkg_ceremony_and_signing(self):
        participants = [
            {"name": "Signer-1"},
            {"name": "Signer-2"},
            {"name": "Signer-3"}
        ]
        threshold = 2
        setup = DKGEngine.run_dkg_ceremony(participants, threshold)
        self.assertEqual(setup["threshold"], 2)
        self.assertEqual(len(setup["participants"]), 3)

        msg = "Execute Multi-Party Treasury Transfer #1001"
        share1 = DKGEngine.sign_share(
            setup["participants"][0]["id"],
            setup["participants"][0]["privateShareHex"],
            setup["participants"][0]["did"],
            msg
        )
        share2 = DKGEngine.sign_share(
            setup["participants"][1]["id"],
            setup["participants"][1]["privateShareHex"],
            setup["participants"][1]["did"],
            msg
        )

        agg_sig = DKGEngine.aggregate_signatures(
            setup["groupPublicKeyHex"],
            setup["groupDid"],
            threshold,
            [share1, share2]
        )
        self.assertEqual(agg_sig["type"], "DKGThresholdEd25519Signature2026")

        verify_res = DKGEngine.verify_aggregated_signature(agg_sig, msg, setup["groupPublicKeyHex"])
        self.assertTrue(verify_res["valid"])

    # ==========================================
    # v5.0.0 Solidity EVM Verifier Tests
    # ==========================================

    def test_solidity_engine_code_and_calldata(self):
        source = SolidityEngine.generate_verifier_contract("DocuTrustVerifier")
        self.assertIn("contract DocuTrustVerifier", source)
        self.assertIn("verifyCredentialOnChain", source)

        leaves = ["cred1", "cred2", "cred3", "cred4"]
        tree = MerkleTree(leaves)
        proof = tree.get_proof(0)
        proof_array = [step["data"] for step in proof["auditPath"]]

        calldata = SolidityEngine.encode_verification_calldata(proof["leafHash"], proof_array, tree.get_root())
        self.assertTrue(calldata["calldataHex"].startswith("0x"))
        self.assertEqual(calldata["methodSignature"], "verifyCredentialOnChain(bytes32,bytes32[],bytes32)")

        # Verify EVM sorted tree semantics
        leaf1 = hashlib.sha256(b"leaf_data_1").hexdigest()
        leaf2 = hashlib.sha256(b"leaf_data_2").hexdigest()
        b1, b2 = bytes.fromhex(leaf1), bytes.fromhex(leaf2)
        root_hex = hashlib.sha256((b1 + b2) if b1 <= b2 else (b2 + b1)).hexdigest()
        evm_valid = SolidityEngine.verify_merkle_proof_evm(leaf1, [leaf2], root_hex)
        self.assertTrue(evm_valid)

    # ==========================================
    # v5.0.0 Cryptographic Audit Bundle Tests
    # ==========================================

    def test_audit_bundle_engine(self):
        mmr = MerkleMountainRange()
        mmr.append("Log Item 1")
        mmr.append("Log Item 2")

        bundle = AuditBundleEngine.create_audit_bundle(
            organization="Sovereign Test Org",
            credentials=[{"id": "urn:uuid:c1", "jcsCanonicalHash": "a" * 64}],
            mmr=mmr
        )
        self.assertEqual(bundle["type"], "DocuTrustAuditBundle2026")
        self.assertEqual(bundle["manifest"]["version"], "8.0.0")

        verify_res = AuditBundleEngine.verify_audit_bundle(bundle)
        self.assertTrue(verify_res["valid"])
        self.assertTrue(verify_res["signatureValid"])
        self.assertTrue(verify_res["mmrValid"])
        self.assertTrue(verify_res["tsaTimestampValid"])

        report = AuditBundleEngine.generate_compliance_report(bundle, verify_res)
        self.assertIn("DocuTrust Sovereign Compliance & Cryptographic Audit Report", report)
        self.assertIn("PASSED", report)

    # ==========================================
    # v5.0.0 W3C DataIntegrityProof Tests
    # ==========================================

    def test_data_integrity_proof(self):
        key_pair = {
            "privateKeyHex": os.urandom(32).hex(),
            "publicKeyHex": os.urandom(32).hex(),
            "keyId": "did:key:zIssuer#key-1"
        }
        subject = {"id": "did:key:zHolder", "degree": "PostQuantumCryptography"}

        # Classical eddsa-jcs-2022
        cred_eddsa = DataIntegrityEngine.issue(
            credential_subject=subject,
            issuer="did:key:zIssuer",
            key_pair=key_pair,
            cryptosuite="eddsa-jcs-2022"
        )
        self.assertEqual(cred_eddsa["proof"]["cryptosuite"], "eddsa-jcs-2022")
        res_eddsa = DataIntegrityEngine.verify(cred_eddsa)
        self.assertTrue(res_eddsa["valid"])
        self.assertFalse(res_eddsa["isQuantumSafe"])

        # Post-quantum ml-dsa-65-2026
        cred_pqc = DataIntegrityEngine.issue(
            credential_subject=subject,
            issuer="did:key:zIssuer",
            key_pair=key_pair,
            cryptosuite="ml-dsa-65-2026"
        )
        self.assertEqual(cred_pqc["proof"]["cryptosuite"], "ml-dsa-65-2026")
        res_pqc = DataIntegrityEngine.verify(cred_pqc)
        self.assertTrue(res_pqc["valid"])
        self.assertTrue(res_pqc["isQuantumSafe"])

    # ==========================================
    # v5.0.0 Client Methods Tests
    # ==========================================

    @patch('requests.Session.get')
    def test_client_v5_get_requests(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"success": True, "issuers": ["did:key:z1"]}
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        client = DocuTrustClient()
        issuers = client.get_trust_registry_issuers()
        self.assertTrue(issuers["success"])

        vault_creds = client.get_vault_credentials(search="Elena", limit=10)
        self.assertTrue(vault_creds["success"])

    # ==========================================
    # v6.0.0 Engine Unit Tests
    # ==========================================

    def test_paillier_and_confidential_claims(self):
        keys = PaillierCryptosystem.generate_key_pair(128)
        self.assertIn("publicKey", keys)
        self.assertIn("privateKey", keys)

        # Encrypt two claims
        c1 = ConfidentialClaimsEngine.encrypt_claim("salary", 75000, keys["publicKey"])
        c2 = ConfidentialClaimsEngine.encrypt_claim("bonus", 25000, keys["publicKey"])

        # Homomorphic addition
        sum_res = ConfidentialClaimsEngine.homomorphic_sum([c1["ciphertextHex"], c2["ciphertextHex"]], keys["publicKey"])
        decrypted_sum = PaillierCryptosystem.decrypt(sum_res["sumCiphertextHex"], keys["privateKey"], keys["publicKey"])
        self.assertEqual(decrypted_sum, 100000)

        # Zero-Knowledge Threshold Proof
        proof = ConfidentialClaimsEngine.prove_threshold("salary", 75000, 50000, "gte", keys["publicKey"])
        verify_res = ConfidentialClaimsEngine.verify_threshold_proof(proof)
        self.assertTrue(verify_res)

    def test_jsonld_canonicalization_and_signing(self):
        doc = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": "urn:uuid:py-jsonld-test",
            "type": ["VerifiableCredential"],
            "issuer": "did:key:z6MkuTestIssuer",
            "credentialSubject": {"degree": "Ph.D. Cryptography", "year": 2026}
        }
        canonical = JsonLdCanonicalizationEngine.canonicalize(doc)
        digest = JsonLdCanonicalizationEngine.digest(doc)
        self.assertTrue(isinstance(canonical, str))
        self.assertEqual(len(digest), 64)

        key_pair = {
            "privateKeyHex": os.urandom(32).hex(),
            "publicKeyHex": os.urandom(32).hex(),
            "did": "did:key:z6MkuTestIssuer"
        }
        signed = JsonLdCanonicalizationEngine.sign_json_ld(doc, key_pair)
        self.assertIn("proof", signed)
        verify_res = JsonLdCanonicalizationEngine.verify_json_ld(signed, key_pair["publicKeyHex"])
        self.assertTrue(verify_res["valid"])

    def test_trust_chain_engine(self):
        root_priv = os.urandom(32).hex()
        root_pub = os.urandom(32).hex()
        root_did = f"did:key:z{encode_base58(bytes([0xed, 0x01]) + bytes.fromhex(root_pub))}"
        root_keys = {"privateKeyHex": root_priv, "publicKeyHex": root_pub, "did": root_did}

        inter_priv = os.urandom(32).hex()
        inter_pub = os.urandom(32).hex()
        inter_did = f"did:key:z{encode_base58(bytes([0xed, 0x01]) + bytes.fromhex(inter_pub))}"
        inter_keys = {"privateKeyHex": inter_priv, "publicKeyHex": inter_pub, "did": inter_did}

        leaf_priv = os.urandom(32).hex()
        leaf_pub = os.urandom(32).hex()
        leaf_did = f"did:key:z{encode_base58(bytes([0xed, 0x01]) + bytes.fromhex(leaf_pub))}"
        leaf_keys = {"privateKeyHex": leaf_priv, "publicKeyHex": leaf_pub, "did": leaf_did}

        # Step 1: Root delegates to Regulator
        token1 = TrustChainEngine.create_delegation_token(
            delegator_key_pair=root_keys,
            delegate_did=inter_keys["did"],
            allowed_credential_types=["UniversityDegreeCredential", "*"],
            max_depth=3
        )
        self.assertTrue(TrustChainEngine.verify_delegation_token(token1, root_keys["publicKeyHex"]))

        # Step 2: Regulator delegates to University
        token2 = TrustChainEngine.create_delegation_token(
            delegator_key_pair=inter_keys,
            delegate_did=leaf_keys["did"],
            allowed_credential_types=["UniversityDegreeCredential"],
            max_depth=2
        )
        self.assertTrue(TrustChainEngine.verify_delegation_token(token2, inter_keys["publicKeyHex"]))

        # Step 3: Verify 2-hop Trust Chain
        leaf_vc = {
            "id": "urn:uuid:degree-01",
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": leaf_keys["did"]
        }
        chain_res = TrustChainEngine.verify_trust_chain(
            chain=[token1, token2],
            credential=leaf_vc,
            accredited_root_dids=[root_keys["did"]]
        )
        self.assertTrue(chain_res["valid"])
        self.assertEqual(chain_res["chainDepth"], 2)

    def test_dual_hybrid_kem_engine(self):
        recipient_keys = DualHybridKEMEngine.generate_dual_key_pair()
        self.assertIn("hybridPublicKey", recipient_keys)
        self.assertIn("hybridSecretKey", recipient_keys)

        payload = {"secretClearance": "Omega-7", "authCode": 987654}
        envelope = DualHybridKEMEngine.seal_credential(payload, recipient_keys["hybridPublicKey"])
        self.assertEqual(envelope["type"], "DocuTrustQuantumSealedEnvelope2026")

        unsealed = DualHybridKEMEngine.unseal_credential(envelope, recipient_keys["hybridSecretKey"])
        self.assertEqual(unsealed["secretClearance"], "Omega-7")
        self.assertEqual(unsealed["authCode"], 987654)

    def test_accumulator_batch_witness(self):
        acc = CryptographicAccumulator("test-batch-acc")
        acc.add("doc-1")
        acc.add("doc-2")
        acc.add("doc-3")
        acc.add("doc-4")

        batch_wit = acc.create_batch_witness(["doc-1", "doc-3"])
        self.assertEqual(batch_wit["elements"], ["doc-1", "doc-3"])
        self.assertTrue(CryptographicAccumulator.verify_batch_witness(batch_wit, hex(acc.V)[2:]))

        # Tampered element should fail
        tampered_wit = dict(batch_wit)
        tampered_wit["elements"] = ["doc-1", "doc-4"]
        self.assertFalse(CryptographicAccumulator.verify_batch_witness(tampered_wit, hex(acc.V)[2:]))

    def test_confidential_linear_combination(self):
        keys = PaillierCryptosystem.generate_key_pair(bit_length=256)
        pub = keys["publicKey"]
        priv = keys["privateKey"]

        c1 = PaillierCryptosystem.encrypt(10, pub)
        c2 = PaillierCryptosystem.encrypt(5, pub)

        # Linear combination: 2*c1 + 3*c2 = 2*10 + 3*5 = 35
        terms = [
            {"ciphertextHex": c1, "weight": 2},
            {"ciphertextHex": c2, "weight": 3}
        ]
        res = ConfidentialClaimsEngine.evaluate_linear_combination(terms, pub)
        decrypted = PaillierCryptosystem.decrypt(res["resultCiphertextHex"], priv, pub)
        self.assertEqual(decrypted, 35)

        # Subtraction: c1 - c2 = 10 - 5 = 5
        c_sub = PaillierCryptosystem.subtract(c1, c2, pub)
        dec_sub = PaillierCryptosystem.decrypt(c_sub, priv, pub)
        self.assertEqual(dec_sub, 5)

    def test_did_jwk(self):
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }
        did = DIDResolver.encode_did_jwk(jwk)
        self.assertTrue(did.startswith("did:jwk:"))

        decoded = DIDResolver.decode_did_jwk(did)
        self.assertEqual(decoded["x"], jwk["x"])

        doc = DIDResolver.resolve(did)
        self.assertEqual(doc["id"], did)
        self.assertEqual(doc["verificationMethod"][0]["type"], "Ed25519VerificationKey2020")
        self.assertEqual(doc["verificationMethod"][0]["publicKeyJwk"]["x"], jwk["x"])

    def test_badge_engine(self):
        from docutrust.crypto import generate_key_pair, sign_data
        issuer_kp = generate_key_pair()
        subject_kp = generate_key_pair()

        unsigned = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:py-badge-vc-01",
            "type": ["VerifiableCredential", "MasterDegreeCredential"],
            "issuer": {"id": issuer_kp["did"], "name": "Stanford Online"},
            "validFrom": "2026-08-30T10:00:00Z",
            "credentialSubject": {
                "id": subject_kp["did"],
                "degree": "MSc in Quantum Engineering",
                "recipient": "Katherine Johnson"
            }
        }
        sig = sign_data(canonicalize_json(unsigned), issuer_kp)
        credential = {
            **unsigned,
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2026-08-30T10:00:00Z",
                "verificationMethod": f"{issuer_kp['did']}#keys-1",
                "proofPurpose": "assertionMethod",
                "proofValue": sig
            }
        }

        # 1. Render badge
        svg = BadgeEngine.render_badge_svg(credential, {
            "theme": "cyber-neon",
            "badgeTitle": "MSc in Quantum Engineering",
            "recipientName": "Katherine Johnson"
        })
        self.assertIn("<svg", svg)
        self.assertIn("Katherine Johnson", svg)
        self.assertIn("<metadata>", svg)

        # 2. Extract credential
        extracted = BadgeEngine.extract_credential_from_svg(svg)
        self.assertEqual(extracted["id"], credential["id"])
        self.assertEqual(extracted["credentialSubject"]["degree"], "MSc in Quantum Engineering")

        # 3. Verify badge
        verify_res = BadgeEngine.verify_badge_svg(svg)
        self.assertTrue(verify_res["valid"])
        self.assertEqual(verify_res["issuer"], issuer_kp["did"])

    def test_policy_engine_evaluation_and_receipt(self):
        from docutrust.policy import PolicyEngine
        from docutrust.crypto import generate_keypair

        evaluator_kp = generate_keypair()
        issuer_kp = generate_keypair()

        credential = {
            "id": "urn:uuid:py-policy-cred-01",
            "type": ["VerifiableCredential", "SecurityOfficerCredential"],
            "issuer": issuer_kp["did"],
            "validFrom": "2026-08-30T10:00:00Z",
            "credentialSubject": {
                "id": "did:key:holder777",
                "name": "Alex Vance",
                "clearanceLevel": 4,
                "role": "SecurityLead",
                "active": True
            }
        }

        policy = {
            "id": "policy-sec-clearance-v9",
            "name": "High Clearance Access Policy",
            "allowedIssuers": [issuer_kp["did"]],
            "requiredCredentialTypes": ["SecurityOfficerCredential"],
            "condition": {
                "operator": "and",
                "conditions": [
                    {"field": "credentialSubject.clearanceLevel", "operator": "gte", "value": 3},
                    {"field": "credentialSubject.role", "operator": "eq", "value": "SecurityLead"},
                    {"field": "credentialSubject.active", "operator": "eq", "value": True}
                ]
            }
        }

        result = PolicyEngine.evaluate(credential, policy, evaluator_keypair=evaluator_kp)
        self.assertTrue(result["passed"])
        self.assertEqual(len(result["errors"]), 0)
        self.assertIn("receipt", result)

        # Verify receipt
        receipt_ok = PolicyEngine.verify_receipt(result["receipt"], evaluator_kp["publicKeyHex"])
        self.assertTrue(receipt_ok)

    def test_did_peer_0_and_2(self):
        from docutrust.did import DIDResolver, create_did_peer_0, create_did_peer_2
        from docutrust.crypto import generate_keypair

        kp1 = generate_keypair()
        peer0 = create_did_peer_0(kp1["publicKeyHex"])
        self.assertTrue(peer0.startswith("did:peer:0z"))

        doc0 = DIDResolver.resolve(peer0)
        self.assertEqual(doc0["id"], peer0)
        self.assertEqual(doc0["verificationMethod"][0]["publicKeyHex"], kp1["publicKeyHex"])

        kp2 = generate_keypair()
        peer2 = create_did_peer_2(
            verification_key_hex=kp1["publicKeyHex"],
            encryption_key_hex=kp2["publicKeyHex"],
            service_endpoint="https://agent.docutrust.org"
        )
        self.assertTrue(peer2.startswith("did:peer:2.V"))
        self.assertIn(".E", peer2)
        self.assertIn(".S", peer2)

        doc2 = DIDResolver.resolve(peer2)
        self.assertEqual(doc2["id"], peer2)
        self.assertEqual(len(doc2["verificationMethod"]), 2)
        self.assertEqual(len(doc2["service"]), 1)

    def test_solidity_registry_contract_generation(self):
        from docutrust.solidity import SolidityEngine
        code = SolidityEngine.generate_registry_contract(contract_name="DocuTrustGovRegistry")
        self.assertIn("contract DocuTrustGovRegistry", code)
        self.assertIn("registerIssuer", code)
        self.assertIn("updateRevocationRoot", code)

    def test_badge_engine_v9_themes(self):
        from docutrust.badge import BadgeEngine
        from docutrust.crypto import generate_keypair, sign_data, canonicalize_json

        issuer_kp = generate_keypair()
        unsigned = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:py-badge-vc-v9",
            "type": ["VerifiableCredential", "SecurityClearanceBadge"],
            "issuer": {"id": issuer_kp["did"]},
            "validFrom": "2026-08-30T10:00:00Z",
            "credentialSubject": {
                "id": "did:key:holder888",
                "degree": "Top Secret Clearance",
                "recipient": "Agent Smith"
            }
        }
        sig = sign_data(canonicalize_json(unsigned), issuer_kp)
        credential = {
            **unsigned,
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2026-08-30T10:00:00Z",
                "verificationMethod": f"{issuer_kp['did']}#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": sig
            }
        }

        svg_noir = BadgeEngine.render_badge_svg(credential, {
            "theme": "obsidian-noir",
            "badge_title": "Top Secret Clearance",
            "recipient_name": "Agent Smith"
        })
        self.assertIn("#09090b", svg_noir)
        self.assertTrue(BadgeEngine.verify_badge_svg(svg_noir)["valid"])

        svg_amethyst = BadgeEngine.render_badge_svg(credential, {
            "theme": "royal-amethyst",
            "badge_title": "Top Secret Clearance",
            "recipient_name": "Agent Smith"
        })
        self.assertIn("#2e1065", svg_amethyst)
        self.assertTrue(BadgeEngine.verify_badge_svg(svg_amethyst)["valid"])

    def test_linkable_ring_signature_lsag(self):
        from docutrust.ringsig import RingSignatureEngine
        from docutrust.crypto import generate_keypair

        k1 = generate_keypair()
        k2 = generate_keypair()
        k3 = generate_keypair()

        ring = [k1["publicKeyHex"], k2["publicKeyHex"], k3["publicKeyHex"]]
        msg = {"action": "BALLOT_VOTE_PROPOSAL_10", "vote": "YES"}

        sig = RingSignatureEngine.sign(
            message=msg,
            ring=ring,
            signer_private_key_hex=k2["privateKeyHex"],
            signer_public_key_hex=k2["publicKeyHex"]
        )
        self.assertEqual(sig["type"], "DocuTrustLinkableRingSignature2026")
        self.assertEqual(len(sig["ring"]), 3)
        self.assertEqual(len(sig["keyImage"]), 64)

        # Verification
        audit = RingSignatureEngine.verify(message=msg, signature=sig)
        self.assertTrue(audit["valid"])
        self.assertFalse(audit["isDoubleAction"])

        # Double-voting detection
        audit_used = RingSignatureEngine.verify(message=msg, signature=sig, used_key_images=[sig["keyImage"]])
        self.assertFalse(audit_used["valid"])
        self.assertTrue(audit_used["isDoubleAction"])

    def test_sparse_merkle_tree_smt(self):
        from docutrust.smt import SparseMerkleTree

        smt = SparseMerkleTree(256)
        smt.set("did:key:alice_10", "VALID_CERTIFICATE_HASH_123")
        smt.set("did:key:bob_10", "REVOKED_STATUS_456")

        root = smt.get_root()
        self.assertEqual(len(root), 64)

        # Proof of inclusion
        proof_alice = smt.prove("did:key:alice_10")
        self.assertTrue(proof_alice["exists"])
        self.assertTrue(SparseMerkleTree.verify_proof(proof_alice, root))

        # Proof of non-membership
        proof_charlie = smt.prove("did:key:charlie_nonexistent")
        self.assertFalse(proof_charlie["exists"])
        self.assertTrue(SparseMerkleTree.verify_proof(proof_charlie, root))

    def test_policy_engine_v10_operators(self):
        from docutrust.policy import PolicyEngine

        cred = {
            "type": ["VerifiableCredential", "SecurityClearance"],
            "credentialSubject": {
                "roles": ["admin", "auditor"],
                "securityLevel": 4,
                "createdDate": "2026-08-30T12:00:00Z"
            }
        }

        # Array indexing path test
        pol_bracket = {
            "id": "pol-bracket",
            "condition": {
                "operator": "eq",
                "field": "credentialSubject.roles[0]",
                "value": "admin"
            }
        }
        res_bracket = PolicyEngine.evaluate(cred, pol_bracket)
        self.assertTrue(res_bracket["passed"])

        # all_of & valid_between
        pol_combo = {
            "id": "pol-combo",
            "condition": {
                "operator": "and",
                "conditions": [
                    {
                        "operator": "all_of",
                        "field": "credentialSubject.roles",
                        "value": ["admin", "auditor"]
                    },
                    {
                        "operator": "valid_between",
                        "field": "credentialSubject.securityLevel",
                        "min": 1,
                        "max": 5
                    }
                ]
            }
        }
        res_combo = PolicyEngine.evaluate(cred, pol_combo)
        self.assertTrue(res_combo["passed"])

    def test_solidity_smt_verifier_generation(self):
        from docutrust.solidity import SolidityEngine

        code = SolidityEngine.generate_smt_verifier_contract(contract_name="DocuTrustSMTVerifier")
        self.assertIn("contract DocuTrustSMTVerifier", code)
        self.assertIn("verifySMTProof", code)

if __name__ == '__main__':
    unittest.main()


