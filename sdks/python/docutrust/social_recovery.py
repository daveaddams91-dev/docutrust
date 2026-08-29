"""
Decentralized Social Key Recovery and Timelocked Escrow Engine for Python SDK.
"""

import os
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from .shamir import split_secret, combine_shares
from .crypto import sha256_hex


class SocialRecoveryEngine:
    @staticmethod
    def setup_recovery(
        owner_did: str,
        secret: str,
        guardians: List[Dict[str, str]],
        threshold: int = 3,
        challenge_period_hours: int = 48
    ) -> Dict[str, Any]:
        if len(guardians) < 2:
            raise ValueError("At least 2 guardians required for social recovery")
        if threshold < 2 or threshold > len(guardians):
            raise ValueError(f"Threshold must be between 2 and {len(guardians)}")

        shares = split_secret(secret, len(guardians), threshold)
        checksum = "0x" + sha256_hex(secret)[:16]

        config = {
            "ownerDid": owner_did,
            "threshold": threshold,
            "totalGuardians": len(guardians),
            "challengePeriodHours": challenge_period_hours,
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "checksum": checksum
        }

        guardian_escrows = []
        for idx, g in enumerate(guardians):
            share = shares[idx]
            guardian_escrows.append({
                "guardianDid": g.get("did", ""),
                "guardianName": g.get("name", ""),
                "shareIndex": share["index"],
                "encryptedShareHex": share["shareHex"],
                "shareHash": sha256_hex(share["shareHex"])
            })

        return {
            "config": config,
            "guardians": guardian_escrows,
            "rawShares": shares
        }

    @staticmethod
    def initiate_recovery(
        owner_did: str,
        requester_did: str,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        session_id = f"rec_{os.urandom(12).hex()}"
        now = datetime.now(timezone.utc)
        exp = now + timedelta(hours=config.get("challengePeriodHours", 48))

        return {
            "sessionId": session_id,
            "ownerDid": owner_did,
            "requesterDid": requester_did,
            "initiatedAt": now.isoformat(),
            "challengeExpiration": exp.isoformat(),
            "threshold": config.get("threshold", 3),
            "totalGuardians": config.get("totalGuardians", 5),
            "status": "PENDING_TIMELOCK",
            "votes": []
        }

    @staticmethod
    def cast_vote(
        session: Dict[str, Any],
        guardian_did: str,
        share_index: int,
        raw_share_hex: str
    ) -> Dict[str, Any]:
        if session.get("status") == "VETOED_BY_OWNER":
            raise ValueError("Recovery session has been vetoed by owner")
        if session.get("status") == "RECOVERED":
            raise ValueError("Recovery session is already completed")

        votes = list(session.get("votes", []))
        if any(v["guardianDid"] == guardian_did for v in votes):
            raise ValueError(f"Guardian {guardian_did} has already cast a vote")

        sig = sha256_hex(f"{session['sessionId']}:{guardian_did}:{share_index}:{raw_share_hex}")
        vote = {
            "guardianDid": guardian_did,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "shareIndex": share_index,
            "rawShareHex": raw_share_hex,
            "signature": "0x" + sig
        }
        votes.append(vote)

        updated = dict(session)
        updated["votes"] = votes
        return updated

    @staticmethod
    def veto_recovery(
        session: Dict[str, Any],
        reason: str = "Unauthorized recovery attempt detected by legitimate key holder"
    ) -> Dict[str, Any]:
        if session.get("status") == "RECOVERED":
            raise ValueError("Cannot veto an already recovered session")

        updated = dict(session)
        updated["status"] = "VETOED_BY_OWNER"
        updated["vetoReason"] = reason
        updated["vetoTimestamp"] = datetime.now(timezone.utc).isoformat()
        return updated

    @staticmethod
    def finalize_recovery(
        session: Dict[str, Any],
        force_timelock_override: bool = False
    ) -> Dict[str, Any]:
        if session.get("status") == "VETOED_BY_OWNER":
            return {"status": "VETOED", "error": "Recovery attempt was vetoed by genuine owner"}

        votes = session.get("votes", [])
        threshold = session.get("threshold", 3)
        if len(votes) < threshold:
            return {
                "status": "INSUFFICIENT_VOTES",
                "error": f"Quorum not reached: {len(votes)}/{threshold} votes cast"
            }

        exp_str = session.get("challengeExpiration", "")
        if not force_timelock_override and exp_str:
            exp_time = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) < exp_time:
                return {
                    "status": "TIMELOCK_ACTIVE",
                    "error": f"Challenge window is still active until {exp_str}"
                }

        shares_to_combine = [
            {
                "index": v["shareIndex"],
                "shareHex": v["rawShareHex"],
                "threshold": threshold,
                "totalShares": session.get("totalGuardians", 5),
                "checksum": ""
            }
            for v in votes[:threshold]
        ]

        try:
            recovered_bytes = combine_shares(shares_to_combine)
            return {
                "status": "SUCCESS",
                "reconstructedSecret": recovered_bytes.decode("utf-8")
            }
        except Exception as e:
            return {
                "status": "RECONSTRUCTION_FAILED",
                "error": str(e)
            }
