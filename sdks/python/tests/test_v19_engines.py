"""
DocuTrust v19.0.0 Python SDK Engine Unit Tests
"""

import unittest
from docutrust.proactive_sharing import ProactiveSecretSharingEngine
from docutrust.vector_commitments import VectorCommitmentEngine
from docutrust.pq_blind import PQBlindSignatureEngine
from docutrust.agent_contract import AgentContractEngine
from docutrust.client import DocuTrustClient


class TestV19Engines(unittest.TestCase):

    def test_proactive_secret_sharing(self):
        master_secret = "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"
        threshold = 3
        total = 5

        # 1. Setup committee
        setup = ProactiveSecretSharingEngine.setup_committee(master_secret, threshold, total)
        self.assertEqual(setup["committee"]["threshold"], threshold)
        self.assertEqual(len(setup["shares"]), total)

        # 2. Reconstruct at epoch 0
        recon0 = ProactiveSecretSharingEngine.reconstruct_secret(setup["shares"][:3], threshold)
        self.assertTrue(recon0["valid"])
        self.assertEqual(recon0["secret_hex"].lower(), setup["reconstruction_check_hex"].lower())

        # 3. Reshare to epoch 1
        all_packets = []
        all_coeffs = []
        for i in range(1, total + 1):
            renewal = ProactiveSecretSharingEngine.generate_renewal_sub_shares(i, threshold, total, 0)
            all_packets.extend(renewal["sub_share_packets"])
            all_coeffs.append([int(c, 16) for c in renewal["zero_coefficients"]])

        epoch1_shares = []
        for s in setup["shares"]:
            rec = [p for p in all_packets if p["to_participant"] == s["participant_id"]]
            up = ProactiveSecretSharingEngine.apply_renewal(s, rec, setup["committee"])
            epoch1_shares.append(up)

        res = ProactiveSecretSharingEngine.finalize_resharing_round(setup["committee"], all_coeffs, epoch1_shares)
        self.assertEqual(res["updated_committee"]["epoch"], 1)

        # 4. Reconstruct at epoch 1
        recon1 = ProactiveSecretSharingEngine.reconstruct_secret(epoch1_shares[1:4], threshold)
        self.assertTrue(recon1["valid"])
        self.assertEqual(recon1["secret_hex"].lower(), setup["reconstruction_check_hex"].lower())

    def test_vector_commitments(self):
        vec = [
            {"claim": "role", "val": "CHIEF_OFFICER"},
            {"claim": "salary", "val": 250000},
            {"claim": "accredited", "val": True}
        ]

        comm = VectorCommitmentEngine.commit(vec)
        self.assertTrue(isinstance(comm["commitment_hex"], str) and len(comm["commitment_hex"]) == 64)
        self.assertEqual(comm["dimension"], 3)

        # Single position proof
        pos_proof = VectorCommitmentEngine.prove_position(vec, 1)
        res = VectorCommitmentEngine.verify_position(comm["commitment_hex"], pos_proof)
        self.assertTrue(res["valid"])

        # Subvector proof
        sub_proof = VectorCommitmentEngine.prove_subvector(vec, [0, 2])
        res_sub = VectorCommitmentEngine.verify_subvector(comm["commitment_hex"], sub_proof)
        self.assertTrue(res_sub["valid"])

    def test_pq_blind_signatures(self):
        key_pair = PQBlindSignatureEngine.generate_key_pair()
        message = {"grant": "TOP_SECRET_CLEARANCE", "seed": "8812739"}

        # User blinds
        blind_res = PQBlindSignatureEngine.blind_message(message, key_pair)
        self.assertTrue("request" in blind_res)

        # Signer signs
        blind_sig = PQBlindSignatureEngine.sign_blinded_message(blind_res["request"], key_pair)
        self.assertTrue("blind_signature_hex" in blind_sig)

        # User unblinds
        receipt = PQBlindSignatureEngine.unblind_signature(
            blind_res["message_hash"],
            blind_sig,
            blind_res["blinding_secret_hex"],
            key_pair
        )
        self.assertTrue("unblinded_signature_hex" in receipt)

        # Public verification
        ver = PQBlindSignatureEngine.verify_signature(message, receipt, key_pair["public_key_hex"])
        self.assertTrue(ver["valid"])

    def test_agent_contracts(self):
        principal = "did:docutrust:enterprise:principal_01"
        agent = "did:docutrust:agent:auditor_01"

        contract = AgentContractEngine.create_contract(
            principal,
            agent,
            {"task": "AI_SAFETY_AUDIT"},
            2000,
            1000,
            1800
        )
        self.assertEqual(contract["status"], "ACTIVE")

        sub = AgentContractEngine.submit_execution(
            contract,
            {"result": "PASSED"},
            [{"step": "LOAD_WEIGHTS", "hash": "0x111"}]
        )
        self.assertEqual(sub["updated_contract"]["status"], "SUBMITTED")

        settle = AgentContractEngine.settle_contract(sub["updated_contract"], sub["receipt"])
        self.assertTrue(settle["settled"])
        self.assertEqual(settle["updated_contract"]["status"], "SETTLED")


if __name__ == "__main__":
    unittest.main()
