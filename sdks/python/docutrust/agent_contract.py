"""Autonomous Agent Smart Contracts & Slashing Engine for DocuTrust v19.0.0."""

from __future__ import annotations

from typing import Dict, Any, List, Optional
import time

from .crypto import canonicalize_json, sha256_hex


class AgentContractEngine:
    """Verifiable Autonomous Agent Smart Contracts and Slashing Engine."""

    @classmethod
    def create_contract(
        cls,
        principal_did: str,
        agent_did: str,
        task_spec: Dict[str, Any],
        bounty_amount: int = 1000,
        agent_stake_amount: int = 500,
        challenge_window_seconds: int = 3600
    ) -> Dict[str, Any]:
        """Initializes a new autonomous agent escrow smart contract."""
        schema_hash = sha256_hex(canonicalize_json(task_spec.get("expectedOutputSchema", {})))
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        contract_id = "ag_ctr_" + sha256_hex(f"contract:{principal_did}:{agent_did}:{created_at}")[:16]

        payload = {
            "contractId": contract_id,
            "principalDid": principal_did,
            "agentDid": agent_did,
            "taskSpecification": {
                "taskType": task_spec.get("taskType", "DEFAULT_TASK"),
                "description": task_spec.get("description", ""),
                "inputParameters": task_spec.get("inputParameters", {}),
                "expectedOutputSchemaHash": schema_hash
            },
            "bountyAmount": bounty_amount,
            "agentStakeAmount": agent_stake_amount,
            "challengeWindowSeconds": challenge_window_seconds,
            "createdAt": created_at,
            "status": "ACTIVE"
        }
        state_root = sha256_hex(canonicalize_json(payload))
        payload["stateRootHash"] = state_root
        return payload

    @classmethod
    def submit_execution(
        cls,
        contract: Dict[str, Any],
        output_payload: Dict[str, Any],
        execution_steps: Optional[List[Any]] = None
    ) -> Dict[str, Any]:
        """Submits agent task execution output and trace commitments."""
        if contract.get("status") != "ACTIVE":
            raise ValueError(f"Cannot submit execution: contract status is {contract.get('status')}")

        steps = execution_steps or []
        step_hashes = [
            sha256_hex(canonicalize_json({"stepIdx": idx, "stepData": step}))
            for idx, step in enumerate(steps)
        ]

        submitted_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        window_sec = contract.get("challengeWindowSeconds", 3600)
        challenge_deadline = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + window_sec))
        receipt_id = "ag_exec_" + sha256_hex(f"receipt:{contract['contractId']}:{submitted_at}")[:16]

        execution_digest = sha256_hex(canonicalize_json({
            "contractId": contract["contractId"],
            "agentDid": contract["agentDid"],
            "outputPayload": output_payload,
            "executionTraceHashes": step_hashes
        }))

        receipt = {
            "type": "DocuTrustAgentContractExecutionReceipt2026",
            "receiptId": receipt_id,
            "contractId": contract["contractId"],
            "agentDid": contract["agentDid"],
            "outputPayload": output_payload,
            "executionTraceHashes": step_hashes,
            "executionDigest": execution_digest,
            "submittedAt": submitted_at,
            "challengeDeadline": challenge_deadline
        }
        receipt_hash = sha256_hex(canonicalize_json(receipt))
        receipt["receiptHash"] = receipt_hash

        updated_contract = dict(contract)
        updated_contract["status"] = "SUBMITTED"
        updated_contract["stateRootHash"] = sha256_hex(f"{contract.get('stateRootHash')}:{receipt_hash}:SUBMITTED")

        return {
            "updatedContract": updated_contract,
            "updated_contract": updated_contract,
            "receipt": receipt
        }

    @classmethod
    def verify_and_slash(
        cls,
        contract: Dict[str, Any],
        receipt: Dict[str, Any],
        dispute: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verifies a fraud-proof dispute and slashes the agent if valid."""
        if contract.get("status") not in ("SUBMITTED", "CHALLENGED"):
            return {
                "slashed": False,
                "updatedContract": contract,
                "updated_contract": contract,
                "error": f"Cannot slash contract in status {contract.get('status')}"
            }

        c_id = contract.get("contractId") or contract.get("contract_id")
        r_id = receipt.get("receiptId") or receipt.get("receipt_id")
        disp_cid = dispute.get("contractId") or dispute.get("contract_id")
        disp_rid = dispute.get("receiptId") or dispute.get("receipt_id")

        if disp_cid != c_id or disp_rid != r_id:
            return {
                "slashed": False,
                "updatedContract": contract,
                "updated_contract": contract,
                "error": "Dispute contract or receipt mismatch"
            }

        is_fraud_valid = False
        reason = dispute.get("disputeReason") or dispute.get("dispute_reason")
        if reason == "INVALID_STEP":
            idx = dispute.get("invalidStepIndex") if dispute.get("invalidStepIndex") is not None else dispute.get("invalid_step_index")
            hashes = receipt.get("executionTraceHashes") or receipt.get("execution_trace_hashes", [])
            actual_step = dispute.get("actualStepHash") or dispute.get("actual_step_hash")
            if idx is not None and 0 <= idx < len(hashes):
                if actual_step == hashes[idx]:
                    is_fraud_valid = True
        elif reason in ("SCHEMA_VIOLATION", "INVARIANT_FAILURE", "UNAUTHORIZED_STATE"):
            is_fraud_valid = True

        if not is_fraud_valid:
            return {
                "slashed": False,
                "updatedContract": contract,
                "updated_contract": contract,
                "error": "Fraud proof invalid"
            }

        stake = contract.get("agentStakeAmount") or contract.get("agent_stake_amount", 500)
        reward = stake // 2
        refund = stake - reward

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        slashing_id = "slash_" + sha256_hex(f"slash:{c_id}:{timestamp}")[:16]

        slashing_receipt = {
            "type": "DocuTrustSlashingReceipt2026",
            "slashingId": slashing_id,
            "slashing_id": slashing_id,
            "contractId": c_id,
            "contract_id": c_id,
            "slashedAgentDid": contract.get("agentDid") or contract.get("agent_did"),
            "slashed_agent_did": contract.get("agentDid") or contract.get("agent_did"),
            "challengerDid": dispute.get("challengerDid") or dispute.get("challenger_did", "did:docutrust:challenger"),
            "challenger_did": dispute.get("challengerDid") or dispute.get("challenger_did", "did:docutrust:challenger"),
            "slashedStakeAmount": stake,
            "slashed_stake_amount": stake,
            "challengerReward": reward,
            "challenger_reward": reward,
            "principalRefund": refund,
            "principal_refund": refund,
            "fraudReason": reason,
            "fraud_reason": reason,
            "timestamp": timestamp
        }
        slashing_receipt["receiptHash"] = sha256_hex(canonicalize_json(slashing_receipt))
        slashing_receipt["receipt_hash"] = slashing_receipt["receiptHash"]

        updated_contract = dict(contract)
        updated_contract["status"] = "SLASHED"
        updated_contract["stateRootHash"] = sha256_hex(f"{contract.get('stateRootHash')}:{slashing_receipt['receiptHash']}:SLASHED")
        updated_contract["state_root_hash"] = updated_contract["stateRootHash"]

        return {
            "slashed": True,
            "updatedContract": updated_contract,
            "updated_contract": updated_contract,
            "slashingReceipt": slashing_receipt,
            "slashing_receipt": slashing_receipt
        }

    @classmethod
    def settle_contract(cls, contract: Dict[str, Any], receipt: Dict[str, Any]) -> Dict[str, Any]:
        """Settles contract upon successful challenge window expiration."""
        if contract.get("status") != "SUBMITTED":
            return {
                "settled": False,
                "updatedContract": contract,
                "updated_contract": contract,
                "error": f"Cannot settle contract in status {contract.get('status')}"
            }

        rec_hash = receipt.get("receiptHash") or receipt.get("receipt_hash")
        updated_contract = dict(contract)
        updated_contract["status"] = "SETTLED"
        updated_contract["stateRootHash"] = sha256_hex(f"{contract.get('stateRootHash')}:{rec_hash}:SETTLED")
        updated_contract["state_root_hash"] = updated_contract["stateRootHash"]

        return {
            "settled": True,
            "updatedContract": updated_contract,
            "updated_contract": updated_contract
        }
