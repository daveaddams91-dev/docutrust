"""Decentralized AI Agent Capability Auction Protocol Engine for DocuTrust v20.0.0."""

from __future__ import annotations

from typing import Dict, Any, List, Optional
import time

from .crypto import canonicalize_json, sha256_hex


class AgentAuctionEngine:
    """Commit-Reveal Vickrey Second-Price Agent Capability Procurement Engine."""

    @classmethod
    def create_auction(
        cls,
        auctioneer_did: str,
        task_spec: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Initializes a new sealed-bid capability auction."""
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        auction_id = "auc_" + sha256_hex(f"auction:{auctioneer_did}:{created_at}")[:16]

        return {
            "type": "DocuTrustAgentCapabilityAuction2026",
            "auctionId": auction_id,
            "auctioneerDid": auctioneer_did,
            "taskSpecification": {
                "taskType": task_spec.get("taskType", "CAPABILITY_PROCUREMENT"),
                "description": task_spec.get("description", ""),
                "maxBudget": task_spec.get("maxBudget", 10000),
                "deadlineEpoch": task_spec.get("deadlineEpoch", int(time.time()) + 7200),
                "requiredCapabilities": task_spec.get("requiredCapabilities", [])
            },
            "commitments": [],
            "revealedBids": [],
            "status": "BIDDING",
            "createdAt": created_at
        }

    @classmethod
    def commit_bid(
        cls,
        auction: Dict[str, Any],
        agent_did: str,
        bid_amount: int,
        stake_amount: int,
        salt: str
    ) -> Dict[str, Any]:
        """Submits a cryptographic commitment hiding the bid amount and stake."""
        if auction.get("status") != "BIDDING":
            raise ValueError(f"Cannot commit bid: auction status is {auction.get('status')}")

        commitment_hash = sha256_hex(f"bid:{auction['auctionId']}:{agent_did}:{bid_amount}:{stake_amount}:{salt}")
        commitment_id = "bid_comm_" + sha256_hex(f"{commitment_hash}:{time.time()}")[:16]

        commitment_obj = {
            "commitmentId": commitment_id,
            "agentDid": agent_did,
            "commitmentHash": "0x" + commitment_hash,
            "committedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        updated_auction = dict(auction)
        updated_auction["commitments"] = list(auction.get("commitments", [])) + [commitment_obj]
        return {
            "updatedAuction": updated_auction,
            "commitment": commitment_obj
        }

    @classmethod
    def reveal_bid(
        cls,
        auction: Dict[str, Any],
        commitment_id: str,
        agent_did: str,
        bid_amount: int,
        stake_amount: int,
        salt: str,
        quality_metric: Optional[float] = 1.0
    ) -> Dict[str, Any]:
        """Reveals the sealed bid values and verifies against the commitment hash."""
        comm = next((c for c in auction.get("commitments", []) if c.get("commitmentId") == commitment_id), None)
        if not comm:
            raise ValueError(f"Commitment ID {commitment_id} not found in auction")

        expected_hash = "0x" + sha256_hex(f"bid:{auction['auctionId']}:{agent_did}:{bid_amount}:{stake_amount}:{salt}")
        if comm.get("commitmentHash") != expected_hash:
            raise ValueError("Revealed bid does not match commitment hash")

        revealed_obj = {
            "commitmentId": commitment_id,
            "agentDid": agent_did,
            "bidAmount": bid_amount,
            "stakeAmount": stake_amount,
            "qualityMetric": quality_metric or 1.0,
            "revealedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        updated_auction = dict(auction)
        updated_auction["revealedBids"] = list(auction.get("revealedBids", [])) + [revealed_obj]
        return {
            "updatedAuction": updated_auction,
            "bid": revealed_obj
        }

    @classmethod
    def clear_auction(cls, auction: Dict[str, Any]) -> Dict[str, Any]:
        """Clears the auction using Vickrey second-price procurement logic."""
        bids = auction.get("revealedBids", [])
        if not bids:
            raise ValueError("No bids revealed to clear auction")

        # For reverse/procurement auction: lowest bid wins, price paid is second-lowest bid
        sorted_bids = sorted(bids, key=lambda b: b["bidAmount"])
        winner = sorted_bids[0]
        clearing_price = sorted_bids[1]["bidAmount"] if len(sorted_bids) > 1 else winner["bidAmount"]

        result = {
            "type": "DocuTrustAgentAuctionClearingResult2026",
            "auctionId": auction["auctionId"],
            "winnerAgentDid": winner["agentDid"],
            "winningBid": winner["bidAmount"],
            "clearingPrice": clearing_price,
            "winnerStake": winner["stakeAmount"],
            "totalEscrowLocked": clearing_price + winner["stakeAmount"],
            "clearedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        updated_auction = dict(auction)
        updated_auction["status"] = "CLEARED"
        updated_auction["clearingResult"] = result

        return {
            "updatedAuction": updated_auction,
            "result": result
        }

    @classmethod
    def settle_auction(
        cls,
        auction: Dict[str, Any],
        clearing_result: Dict[str, Any],
        execution_receipt_id: str
    ) -> Dict[str, Any]:
        """Settles escrow payout upon verified task execution."""
        settlement_id = "stl_auc_" + sha256_hex(f"settle:{auction['auctionId']}:{execution_receipt_id}")[:16]
        receipt = {
            "type": "DocuTrustAgentAuctionSettlementReceipt2026",
            "settlementId": settlement_id,
            "auctionId": auction["auctionId"],
            "winnerAgentDid": clearing_result["winnerAgentDid"],
            "payoutAmount": clearing_result["clearingPrice"],
            "returnedStake": clearing_result["winnerStake"],
            "executionReceiptId": execution_receipt_id,
            "settledAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "SETTLED"
        }

        updated_auction = dict(auction)
        updated_auction["status"] = "SETTLED"
        updated_auction["settlementReceipt"] = receipt

        return {
            "updatedAuction": updated_auction,
            "receipt": receipt
        }

    @classmethod
    def slash_agent(
        cls,
        auction: Dict[str, Any],
        dispute_proof: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Slashes malicious or defaulted winning agent stake upon fraud proof."""
        slashing_id = "slash_auc_" + sha256_hex(f"slash:{auction['auctionId']}:{time.time()}")[:16]
        clearing = auction.get("clearingResult", {})
        staked = clearing.get("winnerStake", 0)

        receipt = {
            "type": "DocuTrustAgentAuctionSlashingReceipt2026",
            "slashingId": slashing_id,
            "auctionId": auction["auctionId"],
            "slashedAgentDid": clearing.get("winnerAgentDid"),
            "slashedStakeAmount": staked,
            "disputeProofDigest": sha256_hex(canonicalize_json(dispute_proof)),
            "slashedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "SLASHED"
        }

        updated_auction = dict(auction)
        updated_auction["status"] = "SLASHED"
        updated_auction["slashingReceipt"] = receipt

        return {
            "updatedAuction": updated_auction,
            "slashingReceipt": receipt
        }
