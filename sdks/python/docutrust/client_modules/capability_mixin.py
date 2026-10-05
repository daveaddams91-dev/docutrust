from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class CapabilityMixin:

    def capability_issue_root(
        self,
        issuer_did: str,
        audience_did: str,
        capabilities: List[Dict[str, Any]],
        caveats: List[Dict[str, Any]],
        expires_in_seconds: int,
        issuer_private_key_hex: str
    ) -> Dict[str, Any]:
        """Issues a root UCAN capability token."""
        from .agentic_capability import AgenticCapabilityEngine
        return AgenticCapabilityEngine.issue_root_capability(
            issuer_did, audience_did, capabilities, caveats, expires_in_seconds, issuer_private_key_hex
        )

    def capability_attenuate(
        self,
        parent_token: Dict[str, Any],
        delegator_did: str,
        delegatee_did: str,
        restricted_capabilities: List[Dict[str, Any]],
        additional_caveats: List[Dict[str, Any]],
        expires_in_seconds: int,
        delegator_private_key_hex: str
    ) -> Dict[str, Any]:
        """Attenuates and delegates a UCAN capability token."""
        from .agentic_capability import AgenticCapabilityEngine
        return AgenticCapabilityEngine.attenuate_capability(
            parent_token, delegator_did, delegatee_did, restricted_capabilities,
            additional_caveats, expires_in_seconds, delegator_private_key_hex
        )

    def capability_verify_delegation_path(
        self,
        token_chain: List[Dict[str, Any]],
        target_action: str,
        target_resource: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Verifies an attenuated UCAN delegation chain."""
        from .agentic_capability import AgenticCapabilityEngine
        return AgenticCapabilityEngine.verify_delegation_path(
            token_chain, target_action, target_resource, context
        )

    def capability_create_execution_receipt(
        self,
        agent_did: str,
        invoked_capability: Dict[str, Any],
        token_chain: List[Dict[str, Any]],
        execution_payload: Any,
        agent_private_key_hex: str
    ) -> Dict[str, Any]:
        """Generates a verifiable execution receipt for an agent action."""
        from .agentic_capability import AgenticCapabilityEngine
        return AgenticCapabilityEngine.create_execution_receipt(
            agent_did, invoked_capability, token_chain, execution_payload, agent_private_key_hex
        )

    def capability_verify_execution_receipt(
        self,
        receipt: Dict[str, Any],
        expected_agent_private_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies an agent execution receipt."""
        from .agentic_capability import AgenticCapabilityEngine
        return AgenticCapabilityEngine.verify_execution_receipt(receipt, expected_agent_private_key_hex)
