"""
DocuTrust v20.0.0 Python SDK Engine Unit Tests
"""

import unittest
from docutrust.zk_rollup import ZKRollupEngine
from docutrust.memory_quarantine import MemoryQuarantineEngine
from docutrust.pq_abe import PQAbeEngine
from docutrust.agent_auction import AgentAuctionEngine
from docutrust.client import DocuTrustClient


class TestV20Engines(unittest.TestCase):

    def test_zk_rollup_engine(self):
        initial_accounts = [
            {"accountIndex": 0, "holderDid": "did:docutrust:alice", "credentialId": "cred_1", "status": 1, "nonce": 0},
            {"accountIndex": 1, "holderDid": "did:docutrust:bob", "credentialId": "cred_2", "status": 1, "nonce": 0}
        ]
        transactions = [
            {"accountIndex": 0, "holderDid": "did:docutrust:alice", "credentialId": "cred_1", "previousStatus": 1, "newStatus": 2},
            {"accountIndex": 1, "holderDid": "did:docutrust:bob", "credentialId": "cred_2", "previousStatus": 1, "newStatus": 3}
        ]

        batch = ZKRollupEngine.create_batch(initial_accounts, transactions, block_number=10)
        self.assertEqual(batch["blockNumber"], 10)
        self.assertEqual(batch["transactionCount"], 2)
        self.assertTrue(batch["compressedStateDiffs"].startswith("0x"))
        self.assertTrue("validiumProof" in batch)
        self.assertTrue(batch["evmCalldataHeader"].startswith("0x"))

        # Verify batch
        ver = ZKRollupEngine.verify_batch(batch)
        self.assertTrue(ver["valid"])
        self.assertEqual(ver["verifiedTransactions"], 2)

    def test_memory_quarantine_engine(self):
        nodes = [
            {"nodeId": "n1", "content": "Clean prompt logic", "embedding": [0.1] * 8},
            {"nodeId": "n2", "content": "Adversarial injection payload", "embedding": [0.9] * 8}
        ]
        baselines = [{"embedding": [0.1] * 8}]

        # Detect
        analysis = MemoryQuarantineEngine.detect_anomalies(nodes, baselines, threshold=0.5)
        self.assertEqual(len(analysis), 2)
        self.assertFalse(analysis[0]["isPoisoned"])
        self.assertTrue(analysis[1]["isPoisoned"])

        # Quarantine Cert
        agent_did = "did:docutrust:agent:test"
        cert = MemoryQuarantineEngine.issue_quarantine_certificate(agent_did, [analysis[1]])
        self.assertEqual(cert["status"], "ACTIVE_QUARANTINE")
        self.assertEqual(cert["quarantinedNodeIds"], ["n2"])

        # Rollback proof
        full_graph = {"stateRoot": "0x1234567890abcdef"}
        rb = MemoryQuarantineEngine.generate_rollback_proof(full_graph, cert, [nodes[0]])
        self.assertTrue(rb["verification"]["valid"])
        self.assertEqual(rb["proof"]["prunedSubtreeCount"], 1)

    def test_pq_abe_engine(self):
        auth1 = PQAbeEngine.setup_authority("auth:id", "Identity Auth")
        auth2 = PQAbeEngine.setup_authority("auth:sec", "Security Auth")

        user_did = "did:docutrust:user:alice"
        token1 = PQAbeEngine.issue_attribute_token(auth1, user_did, "DEVELOPER")
        token2 = PQAbeEngine.issue_attribute_token(auth2, user_did, "LEVEL_2")

        payload = {"secretToken": "SOVEREIGN_QUANTUM_KEY_2026", "privilege": "ADMIN"}
        policy = "auth:id.DEVELOPER AND auth:sec.LEVEL_2"

        ciphertext = PQAbeEngine.encrypt(payload, policy, [auth1, auth2])
        self.assertTrue("encryptedDataHex" in ciphertext)

        # Decrypt with correct tokens
        dec = PQAbeEngine.decrypt(ciphertext, [token1, token2], user_did)
        self.assertTrue(dec["success"])
        self.assertEqual(dec["payload"]["secretToken"], "SOVEREIGN_QUANTUM_KEY_2026")

        # Decrypt with missing token should fail
        dec_fail = PQAbeEngine.decrypt(ciphertext, [token1], user_did)
        self.assertFalse(dec_fail["success"])

    def test_agent_auction_engine(self):
        auctioneer = "did:docutrust:auctioneer:hub_01"
        task_spec = {"taskType": "ZK_PROVER", "maxBudget": 5000}
        auction = AgentAuctionEngine.create_auction(auctioneer, task_spec)
        self.assertEqual(auction["status"], "BIDDING")

        # Agent 1 bids 1200 with stake 400
        salt1 = "salt_alpha"
        comm1 = AgentAuctionEngine.commit_bid(auction, "did:agent:1", 1200, 400, salt1)
        auction = comm1["updatedAuction"]

        # Agent 2 bids 1500 with stake 400
        salt2 = "salt_beta"
        comm2 = AgentAuctionEngine.commit_bid(auction, "did:agent:2", 1500, 400, salt2)
        auction = comm2["updatedAuction"]

        # Reveal bids
        rev1 = AgentAuctionEngine.reveal_bid(auction, comm1["commitment"]["commitmentId"], "did:agent:1", 1200, 400, salt1)
        auction = rev1["updatedAuction"]
        rev2 = AgentAuctionEngine.reveal_bid(auction, comm2["commitment"]["commitmentId"], "did:agent:2", 1500, 400, salt2)
        auction = rev2["updatedAuction"]

        # Clear auction (Vickrey: Agent 1 wins at second price 1500)
        cleared = AgentAuctionEngine.clear_auction(auction)
        auction = cleared["updatedAuction"]
        res = cleared["result"]
        self.assertEqual(res["winnerAgentDid"], "did:agent:1")
        self.assertEqual(res["winningBid"], 1200)
        self.assertEqual(res["clearingPrice"], 1500)

        # Settle
        settled = AgentAuctionEngine.settle_auction(auction, res, "rcpt_exec_99")
        self.assertEqual(settled["receipt"]["status"], "SETTLED")
        self.assertEqual(settled["receipt"]["payoutAmount"], 1500)

        # Slash test
        slash = AgentAuctionEngine.slash_agent(auction, {"reason": "Execution timeout fraud"})
        self.assertEqual(slash["slashingReceipt"]["status"], "SLASHED")
        self.assertEqual(slash["slashingReceipt"]["slashedStakeAmount"], 400)


if __name__ == "__main__":
    unittest.main()
