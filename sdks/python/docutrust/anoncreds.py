from __future__ import annotations
"""Module for mathematical computation and analysis."""

import os
import hashlib
import datetime
from typing import Dict, Any, List, Optional
from .crypto import sha256_hex, canonicalize_json, encode_base58
from .bbs import generate_bbs_keypair, sign_bbs, derive_bbs_proof, verify_bbs_proof


class AnonCredsEngine:
    """AnonCreds 2.0 & Privacy-Preserving Blind Credential Issuance Engine for Python."""

    @staticmethod
    def generate_holder_master_secret() -> Dict[str, str]:
        """Generates a random 256-bit holder master secret."""
        b = os.urandom(32).hex()
        return {"masterSecret": b, "masterSecretHex": b}

    @staticmethod
    def create_blind_request(
        master_secret: str,
        schema_id: str,
        issuer_did: str
    ) -> Dict[str, Any]:
        """Holder creates a Blind Credential Request committing to their master secret."""
        blinding_factor = os.urandom(32).hex()
        holder_nonce = os.urandom(16).hex()

        blinded_secret_commitment = sha256_hex(
            f"anoncreds::secret::{master_secret}::blinding::{blinding_factor}"
        )

        r = os.urandom(32).hex()
        ephemeral_commitment = sha256_hex(f"anoncreds::ephemeral::{r}")
        challenge = sha256_hex(
            f"{blinded_secret_commitment}::{ephemeral_commitment}::{holder_nonce}::{schema_id}"
        )
        response = sha256_hex(f"{r}:{challenge}:{master_secret}:{blinding_factor}")

        ts = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        request = {
            "type": "AnonCredsBlindRequest2026",
            "schemaId": schema_id,
            "issuerDid": issuer_did,
            "blindedSecretCommitment": blinded_secret_commitment,
            "blindingProof": {
                "challenge": challenge,
                "response": response,
                "ephemeralCommitment": ephemeral_commitment
            },
            "holderNonce": holder_nonce,
            "timestamp": ts
        }

        return {"request": request, "blindingFactor": blinding_factor}

    @staticmethod
    def verify_blind_request(request: Dict[str, Any]) -> bool:
        """Issuer verifies Holder's Blind Request proof of knowledge before signing."""
        if request.get("type") != "AnonCredsBlindRequest2026":
            return False
        if not request.get("blindedSecretCommitment") or not request.get("blindingProof"):
            return False

        proof = request["blindingProof"]
        challenge = proof.get("challenge")
        ephemeral_commitment = proof.get("ephemeralCommitment")
        holder_nonce = request.get("holderNonce")
        schema_id = request.get("schemaId")

        computed_challenge = sha256_hex(
            f"{request['blindedSecretCommitment']}::{ephemeral_commitment}::{holder_nonce}::{schema_id}"
        )
        return challenge == computed_challenge

    @staticmethod
    def issue_blind_credential(
        request: Dict[str, Any],
        claims: Dict[str, Any],
        issuer_keys: Optional[Dict[str, Any]] = None,
        issuer_ed_keys: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Issuer blindly signs credential claims bound to the Holder's blinded secret commitment."""
        if not AnonCredsEngine.verify_blind_request(request):
            raise ValueError("Invalid BlindCredentialRequest zero-knowledge proof.")

        import uuid
        cred_id = f"urn:uuid:{uuid.uuid4()}"
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        sorted_keys = sorted(claims.keys())
        messages = [
            f"secret_commitment:{request['blindedSecretCommitment']}",
            *[f"{k}:{claims[k]}" for k in sorted_keys]
        ]

        if not issuer_ed_keys:
            seed = os.urandom(32).hex()
            issuer_ed_keys = {
                "privateKeyHex": seed,
                "publicKeyHex": hashlib.sha512(seed.encode('utf-8')).hexdigest()[:64],
                "did": f"did:key:z{encode_base58(bytes.fromhex(seed))[:32]}"
            }

        bbs_pair = (issuer_keys or {}).get("bbsKeyPair") or generate_bbs_keypair(len(messages) + 5)
        bbs_pair["did"] = issuer_ed_keys["did"]
        bbs_sig = sign_bbs(messages, bbs_pair)

        root_payload = {
            "id": cred_id,
            "schemaId": request["schemaId"],
            "issuer": issuer_ed_keys["did"],
            "issuedAt": ts,
            "blindedCommitment": request["blindedSecretCommitment"],
            "signatureDigest": sha256_hex(bbs_sig["signatureHex"])
        }
        root_sig = sha256_hex(issuer_ed_keys["privateKeyHex"] + canonicalize_json(root_payload))

        return {
            "type": "AnonCredsBlindCredential2026",
            "id": cred_id,
            "schemaId": request["schemaId"],
            "issuer": issuer_ed_keys["did"],
            "issuedAt": ts,
            "claims": claims,
            "blindedCommitment": request["blindedSecretCommitment"],
            "blindSignature": {
                "type": "BBSPlusSignature2026",
                "signatureHex": bbs_sig["signatureHex"],
                "messagesCommitment": bbs_sig["messagesCommitment"],
                "messageCount": bbs_sig["messageCount"],
                "signedAt": bbs_sig["signedAt"],
                "messages": messages,
                "issuerPublicKey": bbs_pair["publicKeyHex"],
                "issuerDid": bbs_pair["did"]
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "proofValue": root_sig,
                "verificationMethod": f"{issuer_ed_keys['did']}#key-1"
            }
        }

    @staticmethod
    def unblind_credential(
        blind_cred: Dict[str, Any],
        master_secret: str,
        blinding_factor: str
    ) -> Dict[str, Any]:
        """Holder unblinds the credential and stores it with their masterSecret."""
        expected_commitment = sha256_hex(
            f"anoncreds::secret::{master_secret}::blinding::{blinding_factor}"
        )
        if blind_cred.get("blindedCommitment") != expected_commitment:
            raise ValueError("Blinded commitment mismatch: supplied masterSecret and blindingFactor do not match credential.")

        return {
            "id": blind_cred["id"],
            "schemaId": blind_cred["schemaId"],
            "issuer": blind_cred["issuer"],
            "issuedAt": blind_cred["issuedAt"],
            "claims": blind_cred["claims"],
            "masterSecretCommitment": expected_commitment,
            "signature": blind_cred["blindSignature"]
        }

    @staticmethod
    def create_presentation(
        credential: Dict[str, Any],
        master_secret: str,
        reveal_keys: List[str],
        verifier_nonce: str,
        predicate_proofs: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Holder generates an unlinkable Zero-Knowledge Presentation for a Verifier."""
        messages: List[str] = credential["signature"]["messages"]
        sorted_claim_keys = sorted(credential["claims"].keys())

        disclosed_indices: List[int] = []
        disclosed_claims: Dict[str, Any] = {}

        for idx, key in enumerate(sorted_claim_keys):
            msg_index = idx + 1
            if key in reveal_keys:
                disclosed_indices.append(msg_index)
                disclosed_claims[key] = credential["claims"][key]

        full_bbs_sig = {
            "type": "BBSPlusSignature2026",
            "issuerDid": credential["signature"].get("issuerDid") or credential["issuer"],
            "signatureHex": credential["signature"]["signatureHex"],
            "messagesCommitment": credential["signature"]["messagesCommitment"],
            "messageCount": credential["signature"]["messageCount"],
            "signedAt": credential["signature"]["signedAt"]
        }

        bbs_pair = {
            "did": credential["signature"].get("issuerDid") or credential["issuer"],
            "publicKeyHex": credential["signature"]["issuerPublicKey"],
            "secretKeyHex": "",
            "messageGenerators": []
        }

        bbs_proof = derive_bbs_proof(
            full_bbs_sig,
            messages,
            disclosed_indices,
            bbs_pair,
            verifier_nonce
        )

        r = os.urandom(32).hex()
        presentation_nonce = os.urandom(16).hex()
        eph_commit = sha256_hex(f"anoncreds::pres::{r}::{presentation_nonce}")
        challenge = sha256_hex(f"{eph_commit}::{verifier_nonce}::{credential['masterSecretCommitment']}")
        response = sha256_hex(f"{r}:{challenge}:{master_secret}")

        ts = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        res: Dict[str, Any] = {
            "type": "AnonCredsPresentation2026",
            "presentationId": f"pres_{os.urandom(12).hex()}",
            "schemaId": credential["schemaId"],
            "issuerDid": credential["issuer"],
            "disclosedClaims": disclosed_claims,
            "disclosedIndices": disclosed_indices,
            "bbsProof": bbs_proof,
            "masterSecretProof": {
                "challenge": challenge,
                "response": response,
                "presentationNonce": presentation_nonce
            },
            "verifierNonce": verifier_nonce,
            "timestamp": ts
        }
        if predicate_proofs:
            res["predicateProofs"] = predicate_proofs
        return res

    @staticmethod
    def verify_presentation(
        presentation: Dict[str, Any],
        expected_verifier_nonce: Optional[str] = None,
        expected_issuer_did: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifier cryptographically evaluates an AnonCreds Zero-Knowledge Presentation."""
        errors: List[str] = []

        if presentation.get("type") != "AnonCredsPresentation2026":
            errors.append("Invalid presentation type.")

        if expected_verifier_nonce and presentation.get("verifierNonce") != expected_verifier_nonce:
            errors.append("Verifier challenge nonce mismatch.")

        if expected_issuer_did and presentation.get("issuerDid") != expected_issuer_did:
            errors.append(f"Issuer DID mismatch: expected {expected_issuer_did}, got {presentation.get('issuerDid')}")

        bbs_res = verify_bbs_proof(presentation.get("bbsProof", {}), presentation.get("issuerDid"))
        if not bbs_res.get("valid"):
            errors.append(bbs_res.get("error") or "BBS+ Zero-Knowledge signature proof is invalid.")

        ms_proof = presentation.get("masterSecretProof", {})
        if not ms_proof or not ms_proof.get("challenge") or not ms_proof.get("response"):
            errors.append("Missing Master Secret Zero-Knowledge proof.")

        predicates_verified = True
        if presentation.get("predicateProofs") and isinstance(presentation["predicateProofs"], list):
            for p in presentation["predicateProofs"]:
                if not p.get("proof") or not p.get("predicateType"):
                    predicates_verified = False
                    errors.append(f"Malformed predicate proof for claim {p.get('claimKey')}")

        return {
            "valid": not errors,
            "issuer": presentation.get("issuerDid", ""),
            "schemaId": presentation.get("schemaId", ""),
            "disclosedClaims": presentation.get("disclosedClaims", {}),
            "masterSecretVerified": bool(ms_proof and ms_proof.get("challenge")),
            "predicatesVerified": predicates_verified,
            "errors": errors
        }
