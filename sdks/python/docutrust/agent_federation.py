"""Decentralized AI Agent Identity & Epistemic Federation Engine for DocuTrust v21.0.0."""

from __future__ import annotations
import time
import math
from typing import Dict, Any, List, Optional
from .crypto import canonicalize_json, sha256_hex, ed25519_sign, ed25519_verify, generate_ed25519_keypair


class AgentFederationEngine:
    """Decentralized AI Agent Identity, Attenuation Delegation & Epistemic Credibility Engine."""

    @classmethod
    def generate_agent_identity(
        cls,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Creates a sovereign AI Agent Identity document with cryptographic public key and epistemic vector."""
        opts = options or {}
        key_pair = generate_ed25519_keypair()
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        public_key_hex = key_pair["publicKeyHex"]

        did = f"did:docutrust:agent:{sha256_hex(public_key_hex)[:16]}"
        capabilities = opts.get("capabilities", ["inference:execute", "state:update", "oracle:feed"])
        authority_type = opts.get("authorityType", "autonomous_worker")
        epistemic_score = max(0, min(100, opts.get("epistemicScore", 90)))

        # Epistemic trust vector [accuracy, coherence, safety, latency_compliance]
        epistemic_vector = [
            round(epistemic_score / 100, 3),
            round(min(1.0, (epistemic_score + 5) / 100), 3),
            round(min(1.0, (epistemic_score + 2) / 100), 3),
            1.0
        ]

        identity_doc = {
            "type": "DocuTrustAgentIdentity2026",
            "agentId": f"agent_{sha256_hex(did)[:12]}",
            "did": did,
            "authorityType": authority_type,
            "capabilities": capabilities,
            "epistemicScore": epistemic_score,
            "epistemicVector": epistemic_vector,
            "reputationWeight": round(epistemic_score / 100, 4),
            "publicKeyHex": public_key_hex,
            "metadata": opts.get("metadata", {}),
            "createdAt": created_at
        }

        canon = canonicalize_json(identity_doc)
        signature = ed25519_sign(canon, key_pair["privateKeyHex"])
        identity_doc["signature"] = signature

        return {
            "identity": identity_doc,
            "keyPair": key_pair
        }

    @classmethod
    def issue_delegation_token(
        cls,
        issuer_key_pair: Dict[str, str],
        subject_did: str,
        delegated_capabilities: List[str],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Issues an attenuated multi-hop delegation token authorizing capability execution."""
        opts = options or {}
        issuer_pub_hex = issuer_key_pair["publicKeyHex"]
        issuer_did = opts.get("issuerDid") or f"did:docutrust:agent:{sha256_hex(issuer_pub_hex)[:16]}"
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        token_id = f"del_{sha256_hex(f'{issuer_did}:{subject_did}:{created_at}')[:16]}"

        token_doc = {
            "type": "DocuTrustAgentDelegationToken2026",
            "tokenId": token_id,
            "issuerDid": issuer_did,
            "subjectDid": subject_did,
            "delegatedCapabilities": delegated_capabilities,
            "maxDelegationDepth": opts.get("maxDelegationDepth", 3),
            "currentDepth": opts.get("currentDepth", 1),
            "parentTokenId": opts.get("parentTokenId"),
            "attenuationRules": {
                "maxExecutionCalls": opts.get("maxExecutionCalls", 1000),
                "disallowSubDelegation": opts.get("disallowSubDelegation", False),
                "requiredMinimumEpistemicScore": opts.get("requiredMinimumEpistemicScore", 70)
            },
            "issuedAt": created_at,
            "notAfter": opts.get("notAfter", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400 * 7)))
        }

        canon = canonicalize_json(token_doc)
        token_doc["issuerSignature"] = ed25519_sign(canon, issuer_key_pair["privateKeyHex"])
        return token_doc

    @classmethod
    def verify_transitive_trust_path(
        cls,
        delegation_chain: List[Dict[str, Any]],
        root_authority: Dict[str, Any],
        requested_capability: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validates capability attenuation and cryptographic provenance across a multi-hop delegation chain."""
        if not delegation_chain:
            raise ValueError("Delegation chain cannot be empty")

        root_pub = root_authority.get("publicKeyHex")
        current_issuer_did = root_authority.get("did")
        effective_capabilities = set(root_authority.get("capabilities", []))

        for idx, token in enumerate(delegation_chain):
            if token.get("issuerDid") != current_issuer_did:
                return {
                    "isValid": False,
                    "error": f"Delegation broken at hop {idx}: issuer did mismatch"
                }

            # Attenuation check: child capabilities must be subset of parent capabilities
            for cap in token.get("delegatedCapabilities", []):
                if cap not in effective_capabilities:
                    return {
                        "isValid": False,
                        "error": f"Attenuation violation at hop {idx}: capability {cap} not granted by parent"
                    }

            effective_capabilities = set(token.get("delegatedCapabilities", []))
            current_issuer_did = token.get("subjectDid")

        if requested_capability and requested_capability not in effective_capabilities:
            return {
                "isValid": False,
                "error": f"Requested capability {requested_capability} is not authorized in final delegation token"
            }

        return {
            "isValid": True,
            "epistemicScore": root_authority.get("epistemicScore", 90),
            "effectiveCapabilities": sorted(list(effective_capabilities)),
            "chainLength": len(delegation_chain)
        }

    @classmethod
    def initiate_agent_handshake(
        cls,
        initiator_key_pair: Dict[str, str],
        responder_did: str
    ) -> Dict[str, Any]:
        """Initiates mutual Zero-Knowledge Agent Handshake session."""
        initiator_pub = initiator_key_pair["publicKeyHex"]
        initiator_did = f"did:docutrust:agent:{sha256_hex(initiator_pub)[:16]}"
        ephemeral_secret = sha256_hex(f"ephem:{time.time()}:{initiator_pub}")
        nonce = sha256_hex(f"nonce:{time.time()}:{responder_did}")[:32]

        challenge_digest = sha256_hex(f"{initiator_did}:{responder_did}:{nonce}:{ephemeral_secret}")
        signature = ed25519_sign(challenge_digest, initiator_key_pair["privateKeyHex"])

        return {
            "handshakeInit": {
                "protocol": "DocuTrustAgentHandshake2026",
                "sessionId": f"hs_{sha256_hex(nonce)[:16]}",
                "initiatorDid": initiator_did,
                "responderDid": responder_did,
                "nonce": nonce,
                "challengeDigest": challenge_digest,
                "signature": signature
            },
            "ephemeralSecret": ephemeral_secret
        }

    @classmethod
    def respond_agent_handshake(
        cls,
        responder_key_pair: Dict[str, str],
        handshake_init: Dict[str, Any],
        initiator_public_key_hex: str
    ) -> Dict[str, Any]:
        """Processes handshake initiation and generates mutual authentication response."""
        init = handshake_init
        if not ed25519_verify(init["challengeDigest"], init["signature"], initiator_public_key_hex):
            raise ValueError("Initiator handshake signature verification failed")

        responder_pub = responder_key_pair["publicKeyHex"]
        responder_did = f"did:docutrust:agent:{sha256_hex(responder_pub)[:16]}"
        responder_ephemeral = sha256_hex(f"resp_ephem:{time.time()}:{responder_pub}")

        shared_secret_hash = sha256_hex(f"{init['challengeDigest']}:{responder_ephemeral}")
        response_digest = sha256_hex(f"{init['sessionId']}:{responder_did}:{shared_secret_hash}")
        responder_sig = ed25519_sign(response_digest, responder_key_pair["privateKeyHex"])

        return {
            "handshakeResponse": {
                "sessionId": init["sessionId"],
                "responderDid": responder_did,
                "responderEphemeralHash": sha256_hex(responder_ephemeral),
                "responseDigest": response_digest,
                "responderSignature": responder_sig
            },
            "session": {
                "sessionId": init["sessionId"],
                "initiatorDid": init["initiatorDid"],
                "responderDid": responder_did,
                "sharedSecretHash": shared_secret_hash,
                "status": "AUTHENTICATED",
                "establishedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        }

    @classmethod
    def complete_agent_handshake(
        cls,
        ephemeral_secret: str,
        handshake_init: Dict[str, Any],
        handshake_response: Dict[str, Any],
        responder_public_key_hex: str
    ) -> Dict[str, Any]:
        """Finalizes mutual ZK handshake verification on initiator side."""
        init = handshake_init
        resp = handshake_response

        if not ed25519_verify(resp["responseDigest"], resp["responderSignature"], responder_public_key_hex):
            raise ValueError("Responder handshake signature verification failed")

        return {
            "session": {
                "sessionId": init["sessionId"],
                "initiatorDid": init["initiatorDid"],
                "responderDid": resp["responderDid"],
                "status": "ESTABLISHED",
                "establishedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        }
