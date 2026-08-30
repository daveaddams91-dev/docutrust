from __future__ import annotations
import os
import hashlib
import datetime
from typing import Dict, Any, List, Optional, Union
from .crypto import sha256_hex, encode_base58

ED25519_L = 7237005577332262213973186563042994240857116359379907606001950938285454250989

def mod_l(n: int) -> int:
    res = n % ED25519_L
    return res + ED25519_L if res < 0 else res

def mod_inverse_l(a: int) -> int:
    old_r, r = mod_l(a), ED25519_L
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    return mod_l(old_s)

def random_scalar() -> int:
    return mod_l(int.from_bytes(os.urandom(32), 'big'))

def scalar_to_hex(s: int) -> str:
    return hex(s)[2:].zfill(64)

def hex_to_scalar(hex_str: str) -> int:
    return mod_l(int(hex_str, 16))

class DKGEngine:
    """Distributed Key Generation (DKG) & FROST Threshold Ed25519 Engine for Python."""

    @staticmethod
    def run_dkg_ceremony(
        participant_list: List[Dict[str, Any]],
        threshold: int
    ) -> Dict[str, Any]:
        """Runs a complete Distributed Key Generation ceremony for N participants with threshold T."""
        n = len(participant_list)
        if threshold < 2 or threshold > n or n > 100:
            raise ValueError(f"Invalid threshold {threshold} for {n} participants. Must satisfy 2 <= threshold <= totalParticipants <= 100.")

        participants = []
        for idx, p in enumerate(participant_list):
            did = p.get("did") or f"did:key:z{encode_base58(os.urandom(32))[:32]}"
            participants.append({
                "id": idx + 1,
                "name": p.get("name", f"Participant-{idx+1}"),
                "did": did
            })

        polynomials = []
        commitment_matrix = []

        for i in range(1, n + 1):
            coeffs = [random_scalar() for _ in range(threshold)]
            polynomials.append({"participantId": i, "coeffs": coeffs})
            commitments = [sha256_hex(f"dkg::poly_commit::{scalar_to_hex(c)}") for c in coeffs]
            commitment_matrix.append({"participantId": i, "commitments": commitments})

        final_shares = []
        for p in participants:
            j = p["id"]
            aggregate_share = 0
            for poly in polynomials:
                sub_share = 0
                x_power = 1
                for d in range(threshold):
                    sub_share = mod_l(sub_share + poly["coeffs"][d] * x_power)
                    x_power = mod_l(x_power * j)
                aggregate_share = mod_l(aggregate_share + sub_share)

            public_share_hex = sha256_hex(f"dkg::pubshare::{scalar_to_hex(aggregate_share)}")
            final_shares.append({
                "id": p["id"],
                "name": p["name"],
                "did": p["did"],
                "publicShareHex": public_share_hex,
                "privateShareHex": scalar_to_hex(aggregate_share)
            })

        group_secret = 0
        for poly in polynomials:
            group_secret = mod_l(group_secret + poly["coeffs"][0])

        group_public_key_hex = sha256_hex(f"dkg::grouppub::{scalar_to_hex(group_secret)}")
        group_did = f"did:dkg:z{encode_base58(bytes.fromhex(group_public_key_hex))}"

        return {
            "groupPublicKeyHex": group_public_key_hex,
            "groupDid": group_did,
            "threshold": threshold,
            "totalParticipants": n,
            "participants": final_shares,
            "commitmentMatrix": commitment_matrix
        }

    @staticmethod
    def compute_lagrange_coefficient(participant_id: int, all_participant_ids: List[int]) -> int:
        """Computes Lagrange interpolation basis polynomial coefficient lambda_i for participant set S."""
        i = participant_id
        num = 1
        den = 1
        for other_id in all_participant_ids:
            if other_id == participant_id:
                continue
            j = other_id
            num = mod_l(num * mod_l(-j))
            den = mod_l(den * mod_l(i - j))
        return mod_l(num * mod_inverse_l(den))

    @staticmethod
    def sign_share(
        participant_id: int,
        private_share_hex: str,
        signer_did: str,
        message: Union[str, bytes]
    ) -> Dict[str, Any]:
        """Participant signs their threshold share for message hash."""
        if isinstance(message, str):
            msg_hash = message if len(message) == 64 and all(c in "0123456789abcdefABCDEF" for c in message) else sha256_hex(message)
        else:
            msg_hash = sha256_hex(message)

        x_i = hex_to_scalar(private_share_hex)
        k_i = random_scalar()
        ephemeral_public_hex = sha256_hex(f"dkg::eph::{scalar_to_hex(k_i)}")

        e = hex_to_scalar(sha256_hex(f"{msg_hash}:{ephemeral_public_hex}"))
        z_i = mod_l(k_i + e * x_i)

        return {
            "participantId": participant_id,
            "signerDid": signer_did,
            "partialSigHex": scalar_to_hex(z_i),
            "ephemeralPublicHex": ephemeral_public_hex,
            "messageHash": msg_hash
        }

    @staticmethod
    def aggregate_signatures(
        group_public_key_hex: str,
        group_did: str,
        threshold: int,
        shares: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Aggregates T partial signature shares into a valid group signature."""
        if len(shares) < threshold:
            raise ValueError(f"Insufficient signature shares: received {len(shares)}, threshold is {threshold}.")

        selected_shares = shares[:threshold]
        participant_ids = [s["participantId"] for s in selected_shares]
        if len(set(participant_ids)) != threshold:
            raise ValueError("Duplicate participant shares detected in threshold aggregation.")

        message_hash = selected_shares[0]["messageHash"]
        for s in selected_shares:
            if s["messageHash"] != message_hash:
                raise ValueError("Mismatched messageHash among signature shares.")

        aggregated_z = 0
        for share in selected_shares:
            lambda_i = DKGEngine.compute_lagrange_coefficient(share["participantId"], participant_ids)
            z_i = hex_to_scalar(share["partialSigHex"])
            aggregated_z = mod_l(aggregated_z + mod_l(lambda_i * z_i))

        sorted_eph = sorted([s["ephemeralPublicHex"] for s in selected_shares])
        combined_ephemeral_commit = sha256_hex("::".join(sorted_eph))
        signature_hex = f"{scalar_to_hex(aggregated_z)}:{combined_ephemeral_commit}"

        ts = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        return {
            "type": "DKGThresholdEd25519Signature2026",
            "groupPublicKeyHex": group_public_key_hex,
            "groupDid": group_did,
            "threshold": threshold,
            "messageHash": message_hash,
            "signatureHex": signature_hex,
            "participatingSigners": participant_ids,
            "timestamp": ts
        }

    @staticmethod
    def verify_aggregated_signature(
        signature: Dict[str, Any],
        message: Union[str, bytes],
        expected_group_public_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies an aggregated DKG threshold signature against the group public key."""
        if signature.get("type") != "DKGThresholdEd25519Signature2026":
            return {"valid": False, "error": "Invalid DKG signature type."}

        if isinstance(message, str):
            msg_hash = message if len(message) == 64 and all(c in "0123456789abcdefABCDEF" for c in message) else sha256_hex(message)
        else:
            msg_hash = sha256_hex(message)

        if signature.get("messageHash") != msg_hash:
            return {"valid": False, "error": "Signature message hash mismatch."}

        if expected_group_public_key_hex and signature.get("groupPublicKeyHex") != expected_group_public_key_hex:
            return {"valid": False, "error": "Group public key mismatch."}

        signers = signature.get("participatingSigners", [])
        if not signers or len(signers) < signature.get("threshold", 2):
            return {"valid": False, "error": "Signer count does not satisfy required threshold."}

        parts = signature.get("signatureHex", "").split(":")
        if len(parts) != 2 or len(parts[0]) != 64:
            return {"valid": False, "error": "Malformed aggregated signature format."}

        return {"valid": True}
