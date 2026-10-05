"""Module for mathematical computation and analysis."""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
import hashlib
import hmac
import json
import secrets


class AgenticCapabilityEngine:
    @classmethod
    def _matches_pattern(cls, pattern: str, target: str) -> bool:
        """Matches pattern.
        
        Args:
            pattern:
            target:
        
        Returns:
            bool: Result of type bool
        
        """
        if pattern == "*" or pattern == target:
            return True
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return target.startswith(prefix)
        return False

    @classmethod
    def issue_root_capability(
        cls,
        issuer_did: str,
        audience_did: str,
        capabilities: List[Dict[str, Any]],
        caveats: List[Dict[str, Any]],
        expires_in_seconds: int,
        issuer_private_key_hex: str
    ) -> Dict[str, Any]:
        """Issue root capability.
        
        Args:
            issuer_did:
            audience_did:
            capabilities:
            caveats:
            expires_in_seconds:
            issuer_private_key_hex:
        
        Returns:
            dict: Result of type dict
        
        """
        token_id = f"ucan_{secrets.token_hex(8)}"
        now = datetime.now(timezone.utc)
        exp = now + timedelta(seconds=expires_in_seconds)

        unsigned = {
            "type": "DocuTrustUCANToken2026",
            "tokenId": token_id,
            "issuer": issuer_did,
            "audience": audience_did,
            "capabilities": capabilities,
            "caveats": caveats,
            "parentProofHashes": [],
            "issuedAt": now.isoformat(),
            "expiresAt": exp.isoformat()
        }

        canonical = json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode('utf-8')
        h = hashlib.sha256(canonical).digest()
        key_bytes = bytes.fromhex(issuer_private_key_hex.replace("0x", ""))
        sig = "0x" + hmac.new(key_bytes, h, hashlib.sha256).hexdigest()

        return {**unsigned, "signature": sig}

    @classmethod
    def attenuate_capability(
        cls,
        parent_token: Dict[str, Any],
        delegator_did: str,
        delegatee_did: str,
        restricted_capabilities: List[Dict[str, Any]],
        additional_caveats: List[Dict[str, Any]],
        expires_in_seconds: int,
        delegator_private_key_hex: str
    ) -> Dict[str, Any]:
        """Attenuate capability.
        
        Args:
            parent_token:
            delegator_did:
            delegatee_did:
            restricted_capabilities:
            additional_caveats:
            expires_in_seconds:
            delegator_private_key_hex:
        
        Returns:
            dict: Result of type dict
        
        """
        if parent_token.get("audience") != delegator_did:
            raise ValueError("Delegator DID must match parent token audience")

        parent_caps = parent_token.get("capabilities", [])
        for req_cap in restricted_capabilities:
            matched = any(
                cls._matches_pattern(p.get("resource", ""), req_cap.get("resource", "")) and
                cls._matches_pattern(p.get("action", ""), req_cap.get("action", ""))
                for p in parent_caps
            )
            if not matched:
                raise ValueError(f"Attenuation violation: requested capability exceeds parent permissions ({req_cap.get('action')} on {req_cap.get('resource')})")

        parent_canonical = json.dumps(parent_token, sort_keys=True, separators=(',', ':')).encode('utf-8')
        parent_hash = "0x" + hashlib.sha256(parent_canonical).hexdigest()

        token_id = f"ucan_{secrets.token_hex(8)}"
        now = datetime.now(timezone.utc)
        parent_exp = datetime.fromisoformat(parent_token["expiresAt"])
        requested_exp = now + timedelta(seconds=expires_in_seconds)
        effective_exp = min(requested_exp, parent_exp)

        merged_caveats = parent_token.get("caveats", []) + additional_caveats

        unsigned = {
            "type": "DocuTrustUCANToken2026",
            "tokenId": token_id,
            "issuer": delegator_did,
            "audience": delegatee_did,
            "capabilities": restricted_capabilities,
            "caveats": merged_caveats,
            "parentProofHashes": [parent_hash],
            "issuedAt": now.isoformat(),
            "expiresAt": effective_exp.isoformat()
        }

        canonical = json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode('utf-8')
        h = hashlib.sha256(canonical).digest()
        key_bytes = bytes.fromhex(delegator_private_key_hex.replace("0x", ""))
        sig = "0x" + hmac.new(key_bytes, h, hashlib.sha256).hexdigest()

        return {**unsigned, "signature": sig}

    @classmethod
    def verify_delegation_path(
        cls,
        token_chain: List[Dict[str, Any]],
        target_action: str,
        target_resource: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Check whether delegation path.
        
        Args:
            token_chain:
            target_action:
            target_resource:
            context:
        
        Returns:
            dict: Result of type dict
        
        """
        if not token_chain:
            return {"valid": False, "error": "Token chain is empty"}

        ctx = context or {}
        now = datetime.fromisoformat(ctx["current_timestamp"]) if "current_timestamp" in ctx else datetime.now(timezone.utc)

        for i, token in enumerate(token_chain):
            if token.get("type") != "DocuTrustUCANToken2026":
                return {"valid": False, "error": f"Invalid UCAN token type at depth {i}"}

            exp = datetime.fromisoformat(token["expiresAt"])
            if exp < now:
                return {"valid": False, "error": f"Token at depth {i} has expired"}

            for caveat in token.get("caveats", []):
                c_type = caveat.get("type")
                val = caveat.get("value")
                if c_type == "maxSpend" and "spend_amount" in ctx:
                    if ctx["spend_amount"] > val:
                        return {"valid": False, "error": f"Caveat violation: spend amount {ctx['spend_amount']} exceeds limit {val}"}
                if c_type == "ipWhitelist" and "client_ip" in ctx:
                    if ctx["client_ip"] not in val:
                        return {"valid": False, "error": f"Caveat violation: client IP {ctx['client_ip']} not in whitelist"}

            if i > 0:
                parent = token_chain[i - 1]
                if token.get("issuer") != parent.get("audience"):
                    return {"valid": False, "error": f"Delegation chain broken at depth {i}: issuer {token.get('issuer')} != parent audience {parent.get('audience')}"}

        leaf = token_chain[-1]
        has_cap = any(
            cls._matches_pattern(c.get("resource", ""), target_resource) and
            cls._matches_pattern(c.get("action", ""), target_action)
            for c in leaf.get("capabilities", [])
        )

        if not has_cap:
            return {"valid": False, "error": f"Leaf token does not authorize {target_action} on {target_resource}"}

        return {"valid": True}

    @classmethod
    def create_execution_receipt(
        cls,
        agent_did: str,
        invoked_capability: Dict[str, Any],
        token_chain: List[Dict[str, Any]],
        execution_payload: Any,
        agent_private_key_hex: str
    ) -> Dict[str, Any]:
        """Create execution receipt.
        
        Args:
            agent_did:
            invoked_capability:
            token_chain:
            execution_payload:
            agent_private_key_hex:
        
        Returns:
            dict: Result of type dict
        
        """
        receipt_id = f"exec_{secrets.token_hex(8)}"
        payload_canonical = json.dumps(execution_payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        execution_digest = "0x" + hashlib.sha256(payload_canonical).hexdigest()

        unsigned = {
            "type": "DocuTrustAgentExecutionReceipt2026",
            "receiptId": receipt_id,
            "agentDid": agent_did,
            "invokedCapability": invoked_capability,
            "tokenChain": token_chain,
            "executionDigest": execution_digest,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "EXECUTED_AUTHENTIC"
        }

        canonical = json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode('utf-8')
        h = hashlib.sha256(canonical).digest()
        key_bytes = bytes.fromhex(agent_private_key_hex.replace("0x", ""))
        sig = "0x" + hmac.new(key_bytes, h, hashlib.sha256).hexdigest()

        return {**unsigned, "signature": sig}

    @classmethod
    def verify_execution_receipt(
        cls,
        receipt: Dict[str, Any],
        expected_agent_private_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Check whether execution receipt.
        
        Args:
            receipt:
            expected_agent_private_key_hex:
        
        Returns:
            dict: Result of type dict
        
        """
        if receipt.get("type") != "DocuTrustAgentExecutionReceipt2026":
            return {"valid": False, "error": "Invalid execution receipt type"}

        invoked_cap = receipt.get("invokedCapability", {})
        path_check = cls.verify_delegation_path(
            receipt.get("tokenChain", []),
            invoked_cap.get("action", ""),
            invoked_cap.get("resource", "")
        )

        if not path_check.get("valid"):
            return {"valid": False, "error": f"Delegation path invalid: {path_check.get('error')}"}

        if expected_agent_private_key_hex:
            unsigned = {k: v for k, v in receipt.items() if k != "signature"}
            canonical = json.dumps(unsigned, sort_keys=True, separators=(',', ':')).encode('utf-8')
            h = hashlib.sha256(canonical).digest()
            key_bytes = bytes.fromhex(expected_agent_private_key_hex.replace("0x", ""))
            expected_sig = "0x" + hmac.new(key_bytes, h, hashlib.sha256).hexdigest()

            if receipt.get("signature") != expected_sig:
                return {"valid": False, "error": "Cryptographic signature mismatch"}

        return {"valid": True}
