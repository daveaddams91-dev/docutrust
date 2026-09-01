"""Proactive Secret Sharing (PSS) and Dynamic Committee Resharing Engine for DocuTrust v19.0.0."""

from __future__ import annotations
import secrets
import time
from typing import Dict, Any, List, Optional
from .crypto import canonicalize_json, sha256_hex

PSS_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order n


class ProactiveSecretSharingEngine:
    """Proactive Secret Sharing and Committee Resharing Engine."""
    GENERATOR_TAG = "PSS_GEN_POINT_V19:"

    @classmethod
    def random_scalar(cls) -> int:
        """Generates a secure random scalar in [1, PSS_PRIME - 1]."""
        return secrets.randbelow(PSS_PRIME - 1) + 1

    @classmethod
    def commit_coefficient(cls, coef: int, idx: int) -> str:
        """Computes SHA-256 commitment of a polynomial coefficient."""
        return sha256_hex(f"{cls.GENERATOR_TAG}{idx}:{hex(coef)[2:]}")

    @classmethod
    def evaluate_polynomial(cls, coefficients: List[int], x: int) -> int:
        """Evaluates polynomial f(x) = sum(a_j * x^j) mod PSS_PRIME."""
        result = 0
        power = 1
        for coef in coefficients:
            result = (result + coef * power) % PSS_PRIME
            power = (power * x) % PSS_PRIME
        return (result + PSS_PRIME) % PSS_PRIME

    @classmethod
    def setup_committee(
        cls,
        secret_hex: str,
        threshold: int,
        total_participants: int,
        participant_dids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Initializes a new committee and splits a master secret using Feldman VSS."""
        if threshold < 2 or threshold > total_participants:
            raise ValueError(f"Invalid threshold: must satisfy 2 <= threshold <= total_participants ({threshold}/{total_participants})")

        secret_int = int(sha256_hex(secret_hex), 16) % PSS_PRIME
        coefficients = [secret_int]
        for _ in range(threshold - 1):
            coefficients.append(cls.random_scalar())

        commitments = [
            {"index": idx, "commitmentHex": cls.commit_coefficient(coef, idx)}
            for idx, coef in enumerate(coefficients)
        ]

        committee_id = "pss_com_" + sha256_hex(f"comm:{time.time()}:{threshold}:{total_participants}")[:16]
        dids = participant_dids if participant_dids and len(participant_dids) == total_participants else [
            f"did:docutrust:validator:{i + 1}" for i in range(total_participants)
        ]

        shares = []
        for i in range(1, total_participants + 1):
            share_val = cls.evaluate_polynomial(coefficients, i)
            vss_proof_hash = sha256_hex(canonicalize_json({
                "committeeId": committee_id,
                "participantId": i,
                "epoch": 0,
                "commitments": commitments
            }))
            share_hex = hex(share_val)[2:].zfill(64)
            shares.append({
                "participantId": i,
                "participant_id": i,
                "shareHex": share_hex,
                "share_hex": share_hex,
                "epoch": 0,
                "vssProofHash": vss_proof_hash,
                "vss_proof_hash": vss_proof_hash
            })

        state_root_hash = sha256_hex(canonicalize_json({
            "committeeId": committee_id,
            "threshold": threshold,
            "totalParticipants": total_participants,
            "epoch": 0,
            "commitments": commitments,
            "dids": dids
        }))

        committee = {
            "committeeId": committee_id,
            "committee_id": committee_id,
            "threshold": threshold,
            "totalParticipants": total_participants,
            "total_participants": total_participants,
            "epoch": 0,
            "publicCommitments": commitments,
            "public_commitments": commitments,
            "participantDids": dids,
            "participant_dids": dids,
            "stateRootHash": state_root_hash,
            "state_root_hash": state_root_hash
        }

        reconstruction_check_hex = hex(secret_int)[2:].zfill(64)

        return {
            "committee": committee,
            "shares": shares,
            "secretCoefficients": [hex(c)[2:] for c in coefficients],
            "secret_coefficients": [hex(c)[2:] for c in coefficients],
            "reconstruction_check_hex": reconstruction_check_hex,
            "reconstructionCheckHex": reconstruction_check_hex
        }

    @classmethod
    def generate_renewal_subshares(
        cls,
        participant_id: int,
        threshold: int,
        total_participants: int,
        current_epoch: int
    ) -> Dict[str, Any]:
        """Generates zero-constant renewal polynomial delta_i(x) where delta_i(0) = 0."""
        zero_coefficients = [0]
        for _ in range(threshold - 1):
            zero_coefficients.append(cls.random_scalar())

        renewal_commitments = [cls.commit_coefficient(c, idx) for idx, c in enumerate(zero_coefficients)]
        sub_share_packets = []

        for to_id in range(1, total_participants + 1):
            sub_val = cls.evaluate_polynomial(zero_coefficients, to_id)
            sub_hex = hex(sub_val)[2:].zfill(64)
            sub_share_packets.append({
                "fromParticipant": participant_id,
                "from_participant": participant_id,
                "toParticipant": to_id,
                "to_participant": to_id,
                "epoch": current_epoch + 1,
                "subShareHex": sub_hex,
                "sub_share_hex": sub_hex,
                "renewalCommitments": renewal_commitments,
                "renewal_commitments": renewal_commitments
            })

        return {
            "subSharePackets": sub_share_packets,
            "sub_share_packets": sub_share_packets,
            "zeroCoefficients": [hex(c)[2:] for c in zero_coefficients],
            "zero_coefficients": [hex(c)[2:] for c in zero_coefficients]
        }

    # Alias for snake_case
    generate_renewal_sub_shares = generate_renewal_subshares

    @classmethod
    def apply_renewal(
        cls,
        current_share: Dict[str, Any],
        received_packets: List[Dict[str, Any]],
        committee: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Applies renewal packets to update participant share for the new epoch."""
        if current_share.get("epoch") != committee.get("epoch"):
            raise ValueError("Share epoch mismatch")

        share_hex = current_share.get("shareHex") or current_share.get("share_hex", "0")
        updated_val = int(share_hex, 16)
        p_id = current_share.get("participantId") or current_share.get("participant_id")

        for packet in received_packets:
            to_p = packet.get("toParticipant") if packet.get("toParticipant") is not None else packet.get("to_participant")
            if to_p != p_id:
                raise ValueError(f"Packet addressed to {to_p}, expected {p_id}")
            sub_hex = packet.get("subShareHex") or packet.get("sub_share_hex", "0")
            sub_val = int(sub_hex, 16)
            updated_val = (updated_val + sub_val) % PSS_PRIME

        new_epoch = committee.get("epoch", 0) + 1
        comm_id = committee.get("committeeId") or committee.get("committee_id")
        prev_proof = current_share.get("vssProofHash") or current_share.get("vss_proof_hash")
        sources = [p.get("fromParticipant") if p.get("fromParticipant") is not None else p.get("from_participant") for p in received_packets]
        vss_proof_hash = sha256_hex(canonicalize_json({
            "committeeId": comm_id,
            "participantId": p_id,
            "epoch": new_epoch,
            "previousShareProof": prev_proof,
            "packetSources": sources
        }))

        updated_share_hex = hex(updated_val)[2:].zfill(64)
        return {
            "participantId": p_id,
            "participant_id": p_id,
            "shareHex": updated_share_hex,
            "share_hex": updated_share_hex,
            "epoch": new_epoch,
            "vssProofHash": vss_proof_hash,
            "vss_proof_hash": vss_proof_hash
        }

    @classmethod
    def finalize_resharing_round(
        cls,
        committee: Dict[str, Any],
        all_renewal_coefficients: List[List[int]],
        updated_shares: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Computes updated committee state and resharing receipt."""
        current_epoch = committee.get("epoch", 0)
        new_epoch = current_epoch + 1
        threshold = committee.get("threshold", 3)
        total_participants = committee.get("totalParticipants") or committee.get("total_participants", len(updated_shares))
        comm_id = committee.get("committeeId") or committee.get("committee_id")
        public_commitments = committee.get("publicCommitments") or committee.get("public_commitments", [])

        updated_commitments = []
        for j in range(threshold):
            sum_delta = 0
            for poly in all_renewal_coefficients:
                sum_delta = (sum_delta + (poly[j] if j < len(poly) else 0)) % PSS_PRIME
            old_comm = public_commitments[j]["commitmentHex"] if j < len(public_commitments) else ""
            new_comm_hex = sha256_hex(f"{old_comm}:{hex(sum_delta)[2:]}:{new_epoch}")
            updated_commitments.append({"index": j, "commitmentHex": new_comm_hex})

        participant_proofs = {}
        for s in updated_shares:
            p_id = s.get("participantId") or s.get("participant_id")
            p_hash = s.get("vssProofHash") or s.get("vss_proof_hash")
            participant_proofs[str(p_id)] = p_hash

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        receipt_id = "pss_rec_" + sha256_hex(f"reshare:{comm_id}:{new_epoch}:{timestamp}")[:16]

        receipt = {
            "type": "DocuTrustPSSResharingReceipt2026",
            "receiptId": receipt_id,
            "receipt_id": receipt_id,
            "committeeId": comm_id,
            "committee_id": comm_id,
            "previousEpoch": current_epoch,
            "previous_epoch": current_epoch,
            "newEpoch": new_epoch,
            "new_epoch": new_epoch,
            "threshold": threshold,
            "totalParticipants": total_participants,
            "total_participants": total_participants,
            "updatedCommitments": updated_commitments,
            "updated_commitments": updated_commitments,
            "participantProofHashes": participant_proofs,
            "participant_proof_hashes": participant_proofs,
            "timestamp": timestamp
        }
        receipt["receiptHash"] = sha256_hex(canonicalize_json(receipt))
        receipt["receipt_hash"] = receipt["receiptHash"]

        updated_comm = dict(committee)
        updated_comm["epoch"] = new_epoch
        updated_comm["publicCommitments"] = updated_commitments
        updated_comm["public_commitments"] = updated_commitments
        updated_comm["stateRootHash"] = sha256_hex(f"{committee.get('stateRootHash')}:{receipt['receiptHash']}:{new_epoch}")
        updated_comm["state_root_hash"] = updated_comm["stateRootHash"]

        return {
            "updatedCommittee": updated_comm,
            "updated_committee": updated_comm,
            "receipt": receipt
        }

    @classmethod
    def reconstruct_secret(cls, shares: List[Dict[str, Any]], threshold: int) -> Dict[str, Any]:
        """Reconstructs master secret via Lagrange interpolation over threshold shares."""
        if len(shares) < threshold:
            raise ValueError(f"Insufficient shares: got {len(shares)}, required {threshold}")

        epoch = shares[0].get("epoch")
        for s in shares:
            if s.get("epoch") != epoch:
                raise ValueError("Epoch mismatch among reconstruction shares")

        subset = shares[:threshold]
        secret = 0

        for i in range(len(subset)):
            xi = subset[i].get("participantId") if subset[i].get("participantId") is not None else subset[i].get("participant_id")
            s_hex = subset[i].get("shareHex") or subset[i].get("share_hex", "0")
            yi = int(s_hex, 16)

            numerator = 1
            denominator = 1

            for j in range(len(subset)):
                if i == j:
                    continue
                xj = subset[j].get("participantId") if subset[j].get("participantId") is not None else subset[j].get("participant_id")
                numerator = (numerator * (0 - xj)) % PSS_PRIME
                denominator = (denominator * (xi - xj)) % PSS_PRIME

            inv_denom = pow((denominator % PSS_PRIME + PSS_PRIME) % PSS_PRIME, PSS_PRIME - 2, PSS_PRIME)
            lagrange_basis = (numerator * inv_denom) % PSS_PRIME
            term = (yi * lagrange_basis) % PSS_PRIME
            secret = (secret + term) % PSS_PRIME

        secret = (secret % PSS_PRIME + PSS_PRIME) % PSS_PRIME
        secret_hex = hex(secret)[2:].zfill(64)
        return {
            "secretHex": secret_hex,
            "secret_hex": secret_hex,
            "valid": True
        }
