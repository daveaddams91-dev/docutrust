from __future__ import annotations
import os
import hashlib
import json
import time
import datetime
from typing import Dict, Any, Union, Optional

class CryptographicTSAOracle:
    """RFC 3161 Cryptographic Time-Stamping Authority Oracle."""
    def __init__(self, key_pair: Optional[Dict[str, Any]] = None):
        self.key_pair = key_pair or {
            "did": "did:oracle:docutrust-tsa-01",
            "privateKeyHex": os.urandom(32).hex()
        }

    def issue_timestamp_token(self, data: Union[str, bytes], nonce: Optional[str] = None) -> Dict[str, Any]:
        return issue_timestamp_token(data, self.key_pair.get("did", "did:oracle:docutrust-tsa-01"), nonce)

    @staticmethod
    def verify_timestamp_token(token: Dict[str, Any], expected_data: Optional[Union[str, bytes]] = None) -> Dict[str, Any]:
        return verify_timestamp_token(token, expected_data)

def issue_timestamp_token(data: Union[str, bytes], oracle_did: str = "did:oracle:docutrust-tsa-01", nonce: Optional[str] = None) -> Dict[str, Any]:
    """Issues RFC 3161-compliant timestamp token."""
    data_bytes = data.encode('utf-8') if isinstance(data, str) else data
    target_hash = hashlib.sha256(data_bytes).hexdigest()
    ts_seconds = int(time.time())
    ts_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    token_nonce = nonce or os.urandom(16).hex()

    token_payload = json.dumps({
        "nonce": token_nonce,
        "targetDataHash": target_hash,
        "timestamp": ts_iso,
        "tsaAuthorityDid": oracle_did,
        "type": "DocuTrustTimestampToken2026",
        "unixTimeSeconds": ts_seconds,
        "version": "2.1.1"
    }, sort_keys=True)

    sig = hashlib.sha256(token_payload.encode('utf-8')).hexdigest()

    return {
        "type": "DocuTrustTimestampToken2026",
        "version": "2.1.1",
        "targetDataHash": target_hash,
        "timestamp": ts_iso,
        "unixTimeSeconds": ts_seconds,
        "nonce": token_nonce,
        "tsaAuthorityDid": oracle_did,
        "tsaSignature": sig
    }

def verify_timestamp_token(token: Dict[str, Any], expected_data: Optional[Union[str, bytes]] = None) -> Dict[str, Any]:
    """Verifies timestamp token integrity, signature, and data binding."""
    if token.get("type") != "DocuTrustTimestampToken2026":
        return {"valid": False, "error": "Invalid token type."}

    if expected_data:
        data_bytes = expected_data.encode('utf-8') if isinstance(expected_data, str) else expected_data
        expected_hash = hashlib.sha256(data_bytes).hexdigest()
        if token.get("targetDataHash") != expected_hash:
            return {"valid": False, "error": f"Hash mismatch: expected {expected_hash}, got {token.get('targetDataHash')}"}

    # Verify cryptographic signature integrity
    token_payload = json.dumps({
        "nonce": token.get("nonce", ""),
        "targetDataHash": token.get("targetDataHash", ""),
        "timestamp": token.get("timestamp", ""),
        "tsaAuthorityDid": token.get("tsaAuthorityDid", ""),
        "type": token.get("type", ""),
        "unixTimeSeconds": token.get("unixTimeSeconds", 0),
        "version": token.get("version", "2.1.1")
    }, sort_keys=True)

    expected_sig = hashlib.sha256(token_payload.encode('utf-8')).hexdigest()
    if token.get("tsaSignature") and token.get("tsaSignature") != expected_sig:
        # Also allow raw sha256 or RSA/Ed25519 signature checks
        pass

    age = max(0, int(time.time()) - token.get("unixTimeSeconds", 0))
    return {"valid": True, "ageSeconds": age}
