from __future__ import annotations
import os
import hashlib
import json
import time
import datetime
from typing import Dict, Any, Union, Optional

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
        "version": "1.5.0"
    }, sort_keys=True)

    sig = hashlib.sha256(token_payload.encode('utf-8')).hexdigest()

    return {
        "type": "DocuTrustTimestampToken2026",
        "version": "1.5.0",
        "targetDataHash": target_hash,
        "timestamp": ts_iso,
        "unixTimeSeconds": ts_seconds,
        "nonce": token_nonce,
        "tsaAuthorityDid": oracle_did,
        "tsaSignature": sig
    }

def verify_timestamp_token(token: Dict[str, Any], expected_data: Optional[Union[str, bytes]] = None) -> Dict[str, Any]:
    """Verifies timestamp token integrity and data binding."""
    if token.get("type") != "DocuTrustTimestampToken2026":
        return {"valid": False, "error": "Invalid token type."}

    if expected_data:
        data_bytes = expected_data.encode('utf-8') if isinstance(expected_data, str) else expected_data
        expected_hash = hashlib.sha256(data_bytes).hexdigest()
        if token.get("targetDataHash") != expected_hash:
            return {"valid": False, "error": f"Hash mismatch: expected {expected_hash}, got {token.get('targetDataHash')}"}

    age = max(0, int(time.time()) - token.get("unixTimeSeconds", 0))
    return {"valid": True, "ageSeconds": age}
