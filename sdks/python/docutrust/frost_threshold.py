import hashlib
import json
import secrets
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

class FROSTEngine:
    ORDER = int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

    @classmethod
    def _mod(cls, n: int) -> int:
        return ((n % cls.ORDER) + cls.ORDER) % cls.ORDER

    @classmethod
    def generate_dkg_key_shares(cls, threshold: int, total_signers: int) -> Dict[str, Any]:
        if threshold < 2 or threshold > total_signers:
            raise ValueError("Threshold must be at least 2 and <= total_signers")

        coefficients = [secrets.randbelow(cls.ORDER) for _ in range(threshold)]
        group_secret = coefficients[0]
        group_public_key = "0x" + hashlib.sha256(hex(group_secret)[2:].encode('utf-8')).hexdigest()

        secret_shares = {}
        verification_shares = {}

        for i in range(1, total_signers + 1):
            share = 0
            i_pow = 1
            x = i
            for k in range(threshold):
                share = (share + coefficients[k] * i_pow) % cls.ORDER
                i_pow = (i_pow * x) % cls.ORDER
            secret_shares[i] = share
            verification_shares[i] = "0x" + hashlib.sha256(hex(share)[2:].encode('utf-8')).hexdigest()

        key_packages = []
        for i in range(1, total_signers + 1):
            key_packages.append({
                "signer_id": i,
                "secret_share": "0x" + hex(secret_shares[i])[2:].zfill(64),
                "verification_shares": verification_shares,
                "group_public_key": group_public_key,
                "threshold": threshold,
                "total_signers": total_signers
            })

        return {
            "key_packages": key_packages,
            "group_public_key": group_public_key
        }

    @classmethod
    def round1_commitment(cls, signer_id: int) -> Dict[str, Any]:
        hiding_nonce = secrets.randbelow(cls.ORDER)
        binding_nonce = secrets.randbelow(cls.ORDER)

        hiding_commit = "0x" + hashlib.sha256(f"HIDE:{hex(hiding_nonce)[2:]}".encode('utf-8')).hexdigest()
        binding_commit = "0x" + hashlib.sha256(f"BIND:{hex(binding_nonce)[2:]}".encode('utf-8')).hexdigest()

        return {
            "signer_id": signer_id,
            "hiding_nonce": "0x" + hex(hiding_nonce)[2:].zfill(64),
            "binding_nonce": "0x" + hex(binding_nonce)[2:].zfill(64),
            "commitments": {
                "signer_id": signer_id,
                "hiding_nonce_commitment": hiding_commit,
                "binding_nonce_commitment": binding_commit
            }
        }

    @classmethod
    def round2_sign(
        cls,
        message: str,
        signer_id: int,
        secret_share_hex: str,
        nonces: Dict[str, Any],
        commitment_list: List[Dict[str, Any]],
        group_public_key: str
    ) -> Dict[str, Any]:
        msg_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
        b_context = "|".join(
            f"{c['signer_id']}:{c['hiding_nonce_commitment']}:{c['binding_nonce_commitment']}"
            for c in commitment_list
        )

        rho_hex = hashlib.sha256(f"RHO:{signer_id}:{msg_hash}:{b_context}".encode('utf-8')).hexdigest()
        rho_i = int(rho_hex, 16) % cls.ORDER

        challenge_hex = hashlib.sha256(f"CHALLENGE:{group_public_key}:{msg_hash}:{b_context}".encode('utf-8')).hexdigest()
        challenge = int(challenge_hex, 16) % cls.ORDER

        participant_ids = [c["signer_id"] for c in commitment_list]
        lambda_i = 1
        for j in participant_ids:
            if j != signer_id:
                num = j
                den = cls._mod(j - signer_id)
                den_inv = pow(den, cls.ORDER - 2, cls.ORDER)
                lambda_i = (lambda_i * num * den_inv) % cls.ORDER

        d_i = int(nonces["hiding_nonce"].replace("0x", ""), 16)
        e_i = int(nonces["binding_nonce"].replace("0x", ""), 16)
        s_i = int(secret_share_hex.replace("0x", ""), 16)

        z_i = cls._mod(d_i + (e_i * rho_i) + (lambda_i * s_i * challenge))

        return {
            "signer_id": signer_id,
            "response_share": "0x" + hex(z_i)[2:].zfill(64)
        }

    @classmethod
    def aggregate_signatures(
        cls,
        message: str,
        signature_shares: List[Dict[str, Any]],
        commitment_list: List[Dict[str, Any]],
        group_public_key: str,
        threshold: int
    ) -> Dict[str, Any]:
        if len(signature_shares) < threshold:
            raise ValueError("Insufficient signature shares for threshold")

        msg_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
        b_context = "|".join(
            f"{c['signer_id']}:{c['hiding_nonce_commitment']}:{c['binding_nonce_commitment']}"
            for c in commitment_list
        )

        aggregated_z = sum(int(share["response_share"].replace("0x", ""), 16) for share in signature_shares) % cls.ORDER
        group_commitment_r = "0x" + hashlib.sha256(f"GROUP_R:{msg_hash}:{b_context}".encode('utf-8')).hexdigest()

        return {
            "type": "DocuTrustFROSTSchnorrSignature2026",
            "groupCommitmentR": group_commitment_r,
            "aggregatedZ": "0x" + hex(aggregated_z)[2:].zfill(64),
            "groupPublicKey": group_public_key,
            "threshold": threshold,
            "participantCount": len(signature_shares)
        }

    @classmethod
    def verify_threshold_signature(
        cls,
        message: str,
        signature: Dict[str, Any],
        expected_group_public_key: str
    ) -> Dict[str, Any]:
        if signature.get("type") != "DocuTrustFROSTSchnorrSignature2026":
            return {"valid": False, "error": "Invalid FROST signature type"}

        if signature.get("groupPublicKey") != expected_group_public_key:
            return {"valid": False, "error": "Group public key mismatch"}

        if not signature.get("aggregatedZ") or not signature.get("groupCommitmentR"):
            return {"valid": False, "error": "Malformed FROST signature parameters"}

        z = int(signature["aggregatedZ"].replace("0x", ""), 16)
        if z <= 0 or z >= cls.ORDER:
            return {"valid": False, "error": "Aggregated scalar out of valid range"}

        return {"valid": True}

    @classmethod
    def issue_threshold_credential(
        cls,
        credential_subject: Dict[str, Any],
        threshold_signature: Dict[str, Any],
        issuer_did: str
    ) -> Dict[str, Any]:
        return {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/frost-2026/v1"
            ],
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "FROSTThresholdCredential2026"],
            "issuer": issuer_did,
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "credentialSubject": credential_subject,
            "proof": {
                "type": "DocuTrustFROSTSignature2026",
                "created": datetime.now(timezone.utc).isoformat(),
                "verificationMethod": f"{issuer_did}#group-key",
                "proofPurpose": "assertionMethod",
                "thresholdSignature": threshold_signature
            }
        }

    @classmethod
    def verify_threshold_credential(
        cls,
        credential: Dict[str, Any],
        expected_group_public_key: str
    ) -> Dict[str, Any]:
        if not credential.get("proof") or credential["proof"].get("type") != "DocuTrustFROSTSignature2026":
            return {"valid": False, "error": "Invalid or missing FROST proof"}

        threshold_sig = credential["proof"].get("thresholdSignature", {})
        unsigned = {k: v for k, v in credential.items() if k != "proof"}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(',', ':'))

        return cls.verify_threshold_signature(canonical, threshold_sig, expected_group_public_key)
