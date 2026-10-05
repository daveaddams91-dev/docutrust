from __future__ import annotations
"""Module for mathematical computation and analysis."""


from typing import Dict, Any, List, Optional, Union
import secrets
import time

from .crypto import canonicalize_json, sha256_hex, sign_message, verify_signature


class AgentProvenanceEngine:
    """
    Autonomous AI Agent Action Attestation & Policy Guardrail Engine (DocuTrust v13.0.0).
    Issues and verifies DocuTrustAgentAttestation2026 for AI agents.
    """

    @staticmethod
    def compute_model_fingerprint(model_card: Dict[str, Any]) -> str:
        """Compute model fingerprint using optimized algorithms.
        
        Args:
            model_card:
        
        Returns:
            The computed result
        
        """
        canonical = canonicalize_json({
            'modelName': model_card.get('modelName', ''),
            'modelVersion': model_card.get('modelVersion', ''),
            'provider': model_card.get('provider', ''),
            'weightsFingerprintHex': model_card.get('weightsFingerprintHex', 'unspecified'),
            'quantization': model_card.get('quantization', 'float16'),
            'systemPromptHash': model_card.get('systemPromptHash', 'none')
        })
        return sha256_hex(f"MODEL_CARD:{canonical}")

    @staticmethod
    def compute_context_digest(context_payload: Union[Dict[str, Any], str]) -> str:
        """Compute context digest using optimized algorithms.
        
        Args:
            context_payload:
        
        Returns:
            The computed result
        
        """
        canonical = context_payload if isinstance(context_payload, str) else canonicalize_json(context_payload)
        return sha256_hex(f"AGENT_CONTEXT:{canonical}")

    @classmethod
    def issue_attestation(
        cls,
        payload: Dict[str, Any],
        agent_key_pair: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Issue attestation.
        
        Args:
            payload:
            agent_key_pair:
        
        Returns:
            dict: Result of type dict
        
        """
        attestation_id = f"agent-att-{secrets.token_hex(8)}"
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        model_card = payload.get('modelCard', {})
        model_fingerprint = cls.compute_model_fingerprint(model_card)

        context_digest = payload.get('contextDigest')
        if not context_digest:
            prompt_text = payload.get('promptText')
            context_digest = cls.compute_context_digest(prompt_text) if prompt_text else sha256_hex('EMPTY_CONTEXT')

        trace = []
        for idx, step in enumerate(payload.get('executionTrace', [])):
            step_record = {
                'stepIndex': idx + 1,
                'toolName': step.get('toolName', ''),
                'toolArguments': step.get('toolArguments', {}),
                'observationDigest': step.get('observationDigest', '')
            }
            step_record['stepHash'] = sha256_hex(canonicalize_json(step_record))
            trace.append(step_record)

        execution_trace_hash = sha256_hex(canonicalize_json(trace))
        output_artifact = payload.get('outputArtifact', {})
        output_canonical = output_artifact if isinstance(output_artifact, str) else canonicalize_json(output_artifact)
        output_commitment = sha256_hex(output_canonical)
        guardrail_passed = payload.get('guardrailPassed', True)

        sign_payload = {
            'attestationId': attestation_id,
            'agentDid': agent_key_pair.get('did', 'did:key:agent'),
            'modelFingerprint': model_fingerprint,
            'contextDigest': context_digest,
            'executionTraceHash': execution_trace_hash,
            'stepCount': len(trace),
            'outputCommitment': output_commitment,
            'guardrailPolicyId': payload.get('guardrailPolicyId', 'default-safety-guardrail'),
            'guardrailPassed': guardrail_passed,
            'timestamp': timestamp
        }

        signature_hex = sign_message(canonicalize_json(sign_payload), agent_key_pair.get('privateKeyHex', ''))

        return {
            'type': 'DocuTrustAgentAttestation2026',
            'attestationId': attestation_id,
            'agentDid': agent_key_pair.get('did', 'did:key:agent'),
            'modelFingerprint': model_fingerprint,
            'contextDigest': context_digest,
            'executionTraceHash': execution_trace_hash,
            'stepCount': len(trace),
            'outputCommitment': output_commitment,
            'guardrailPolicyId': payload.get('guardrailPolicyId', 'default-safety-guardrail'),
            'guardrailPassed': guardrail_passed,
            'modelCard': model_card,
            'outputArtifact': output_artifact,
            'signatureHex': signature_hex,
            'timestamp': timestamp
        }

    @classmethod
    def verify_attestation(
        cls,
        attestation: Dict[str, Any],
        agent_public_key_hex: str,
        expected_output: Optional[Union[Dict[str, Any], str]] = None
    ) -> Dict[str, Any]:
        """Check whether attestation.
        
        Args:
            attestation:
            agent_public_key_hex:
            expected_output:
        
        Returns:
            dict: Result of type dict
        
        """
        errors = []

        if not attestation or attestation.get('type') != 'DocuTrustAgentAttestation2026':
            return {
                'valid': False,
                'attestationId': attestation.get('attestationId', 'unknown') if attestation else 'unknown',
                'agentDid': attestation.get('agentDid', 'unknown') if attestation else 'unknown',
                'modelFingerprint': '',
                'guardrailPassed': False,
                'outputCommitment': '',
                'errors': ['Invalid attestation structure or type mismatch.']
            }

        # 1. Verify model fingerprint
        computed_fingerprint = cls.compute_model_fingerprint(attestation.get('modelCard', {}))
        if computed_fingerprint.lower() != str(attestation.get('modelFingerprint', '')).lower():
            errors.append('Model card fingerprint mismatch in attestation.')

        # 2. Verify output commitment
        output_art = attestation.get('outputArtifact', {})
        actual_output_canonical = output_art if isinstance(output_art, str) else canonicalize_json(output_art)
        computed_commitment = sha256_hex(actual_output_canonical)
        if computed_commitment.lower() != str(attestation.get('outputCommitment', '')).lower():
            errors.append('Output artifact commitment mismatch.')

        # 3. Expected output comparison
        if expected_output is not None:
            exp_canonical = expected_output if isinstance(expected_output, str) else canonicalize_json(expected_output)
            exp_commitment = sha256_hex(exp_canonical)
            if exp_commitment.lower() != str(attestation.get('outputCommitment', '')).lower():
                errors.append(f"Expected output commitment mismatch.")

        # 4. Signature verification
        sign_payload = {
            'attestationId': attestation.get('attestationId'),
            'agentDid': attestation.get('agentDid'),
            'modelFingerprint': attestation.get('modelFingerprint'),
            'contextDigest': attestation.get('contextDigest'),
            'executionTraceHash': attestation.get('executionTraceHash'),
            'stepCount': attestation.get('stepCount'),
            'outputCommitment': attestation.get('outputCommitment'),
            'guardrailPolicyId': attestation.get('guardrailPolicyId'),
            'guardrailPassed': attestation.get('guardrailPassed'),
            'timestamp': attestation.get('timestamp')
        }

        is_sig_valid = verify_signature(
            canonicalize_json(sign_payload),
            attestation.get('signatureHex', ''),
            agent_public_key_hex
        )
        if not is_sig_valid:
            errors.append('Agent cryptographic signature verification failed on action attestation.')

        if not attestation.get('guardrailPassed'):
            errors.append('Agent action attestation reports safety/policy guardrail violation.')

        return {
            'valid': not errors,
            'attestationId': attestation.get('attestationId'),
            'agentDid': attestation.get('agentDid'),
            'modelFingerprint': attestation.get('modelFingerprint'),
            'stepCount': attestation.get('stepCount', 0),
            'guardrailPassed': attestation.get('guardrailPassed', False),
            'outputCommitment': attestation.get('outputCommitment'),
            'errors': errors
        }
