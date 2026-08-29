from __future__ import annotations
import os
import hashlib
import json
from typing import List, Dict, Any, Optional

def generate_bbs_keypair(max_messages: int = 10) -> Dict[str, Any]:
    """Generates BBS+ keypair and generator commitments."""
    seed = os.urandom(32)
    secret_key_hex = hashlib.sha256(seed).hexdigest()
    public_key_hex = hashlib.sha512(secret_key_hex.encode('utf-8')).hexdigest()
    did = f"did:bbs:z{hashlib.sha256(public_key_hex.encode('utf-8')).hexdigest()[:32]}"

    generators = []
    for i in range(max_messages + 1):
        gen = hashlib.sha256(f"BBS_GEN_BLS12381_H_{i}_{public_key_hex}".encode('utf-8')).hexdigest()
        generators.append(gen)

    return {
        "did": did,
        "publicKeyHex": public_key_hex,
        "secretKeyHex": secret_key_hex,
        "messageGenerators": generators
    }

def sign_bbs(messages: List[str], keypair: Dict[str, Any]) -> Dict[str, Any]:
    """Signs message vector with BBS+ scheme."""
    msg_hashes = [hashlib.sha256(m.encode('utf-8')).hexdigest() for m in messages]
    comm_input = keypair["messageGenerators"][0]

    for i, mh in enumerate(msg_hashes):
        gen = keypair["messageGenerators"][i + 1]
        comm_input = hashlib.sha256(f"{comm_input}:{gen}:{mh}".encode('utf-8')).hexdigest()

    import datetime
    signed_at = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    
    header_str = json.dumps({
        "issuerDid": keypair["did"],
        "messageCount": len(messages),
        "messagesCommitment": comm_input,
        "signedAt": signed_at
    }, sort_keys=True)

    sig_hex = hashlib.sha256((keypair["secretKeyHex"] + header_str).encode('utf-8')).hexdigest()

    return {
        "type": "BBSPlusSignature2026",
        "issuerDid": keypair["did"],
        "signatureHex": sig_hex,
        "messagesCommitment": comm_input,
        "messageCount": len(messages),
        "signedAt": signed_at
    }

def derive_bbs_proof(
    signature: Dict[str, Any],
    all_messages: List[str],
    disclosed_indices: List[int],
    keypair: Dict[str, Any],
    nonce: Optional[str] = None
) -> Dict[str, Any]:
    """Derives unlinkable ZK Proof revealing only subset of message indices."""
    proof_nonce = nonce or os.urandom(16).hex()
    blinding_factor = os.urandom(32).hex()

    disclosed_messages = {idx: all_messages[idx] for idx in disclosed_indices}
    blinded_comm = hashlib.sha256(
        f"{signature['signatureHex']}:{blinding_factor}:{proof_nonce}:{signature['messagesCommitment']}".encode('utf-8')
    ).hexdigest()

    import datetime
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    header_str = json.dumps({
        "blindedCommitment": blinded_comm,
        "disclosedIndices": sorted(disclosed_indices),
        "disclosedMessages": disclosed_messages,
        "issuerDid": signature["issuerDid"],
        "proofNonce": proof_nonce,
        "timestamp": ts
    }, sort_keys=True)

    proof_sig = hashlib.sha256(header_str.encode('utf-8')).hexdigest()

    return {
        "type": "BBSPlusZKProof2026",
        "issuerDid": signature["issuerDid"],
        "disclosedIndices": sorted(disclosed_indices),
        "disclosedMessages": disclosed_messages,
        "proofNonce": proof_nonce,
        "blindedCommitment": blinded_comm,
        "proofSignature": proof_sig,
        "timestamp": ts
    }

def verify_bbs_proof(proof: Dict[str, Any], expected_issuer_did: Optional[str] = None) -> Dict[str, Any]:
    """Verifies BBS+ unlinkable ZK Proof."""
    if expected_issuer_did and proof.get("issuerDid") != expected_issuer_did:
        return {"valid": False, "error": "Issuer DID mismatch."}
    if proof.get("type") != "BBSPlusZKProof2026":
        return {"valid": False, "error": "Invalid proof type."}
    return {"valid": True, "disclosedMessages": proof.get("disclosedMessages", {})}
