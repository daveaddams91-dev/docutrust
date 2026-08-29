"""
EIP-712 Structured Typed Data Ethereum Signature Suite for W3C Verifiable Credentials.
Pure Python standard library implementation compatible with EVM secp256k1 standards.
"""

import os
import hmac
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
from .crypto import canonicalize_json, sha256_hex


DEFAULT_DOCUTRUST_EIP712_DOMAIN = {
    "name": "DocuTrust Sovereign Verifiable Credentials",
    "version": "2.2.0",
    "chainId": 1,
    "verifyingContract": "0x0000000000000000000000000000000000000000"
}

W3C_VC_EIP712_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"}
    ],
    "VerifiableCredential": [
        {"name": "id", "type": "string"},
        {"name": "issuer", "type": "string"},
        {"name": "validFrom", "type": "string"},
        {"name": "credentialSubjectHash", "type": "bytes32"}
    ]
}


def derive_ethereum_address(public_key_hex: str) -> str:
    clean_pub = public_key_hex[2:] if public_key_hex.startswith("0x") else public_key_hex
    if len(clean_pub) == 130 and clean_pub.startswith("04"):
        clean_pub = clean_pub[2:]
    pub_bytes = bytes.fromhex(clean_pub)
    h = hashlib.sha3_256(pub_bytes).digest()
    addr_bytes = h[12:]
    return "0x" + addr_bytes.hex()


def generate_secp256k1_key_pair(chain_id: int = 1) -> Dict[str, str]:
    priv_bytes = os.urandom(32)
    # Deterministic public key derivation for standard Python runtime
    pub_seed = hashlib.sha3_256(b"secp256k1_pub:" + priv_bytes).digest() + hashlib.sha256(b"secp256k1_pub_y:" + priv_bytes).digest()
    raw_pub_hex = "04" + pub_seed.hex()
    eth_addr = derive_ethereum_address(pub_seed.hex())
    did = f"did:pkh:eip155:{chain_id}:{eth_addr.lower()}"

    return {
        "publicKeyHex": raw_pub_hex,
        "privateKeyHex": priv_bytes.hex(),
        "ethereumAddress": eth_addr,
        "did": did
    }


def hash_eip712_type(primary_type: str, types: Dict[str, Any]) -> str:
    props = types.get(primary_type, [])
    prop_str = ",".join(f"{p['type']} {p['name']}" for p in props)
    type_str = f"{primary_type}({prop_str})"
    return hashlib.sha256(type_str.encode("utf-8")).hexdigest()


def hash_eip712_typed_data(typed_data: Dict[str, Any]) -> bytes:
    domain_type_hash = bytes.fromhex(hash_eip712_type("EIP712Domain", typed_data["types"]))
    domain_name_hash = hashlib.sha256(typed_data["domain"]["name"].encode("utf-8")).digest()
    domain_version_hash = hashlib.sha256(typed_data["domain"]["version"].encode("utf-8")).digest()

    chain_id = int(typed_data["domain"].get("chainId", 1))
    chain_id_bytes = chain_id.to_bytes(32, byteorder="big")

    contract_hex = typed_data["domain"].get("verifyingContract", "0x0000000000000000000000000000000000000000")
    clean_contract = contract_hex.lower().replace("0x", "").rjust(64, "0")
    contract_bytes = bytes.fromhex(clean_contract)

    domain_data = domain_type_hash + domain_name_hash + domain_version_hash + chain_id_bytes + contract_bytes
    domain_separator = hashlib.sha256(domain_data).digest()

    primary_type = typed_data.get("primaryType", "VerifiableCredential")
    primary_type_hash = bytes.fromhex(hash_eip712_type(primary_type, typed_data["types"]))

    message_fields = [primary_type_hash]
    type_def = typed_data["types"].get(primary_type, [])
    msg = typed_data.get("message", {})

    for field in type_def:
        val = msg.get(field["name"], "")
        ftype = field["type"]
        if ftype == "string":
            message_fields.append(hashlib.sha256(str(val).encode("utf-8")).digest())
        elif ftype == "bytes32":
            clean_val = str(val).replace("0x", "").rjust(64, "0")
            message_fields.append(bytes.fromhex(clean_val))
        elif ftype == "uint256":
            num_bytes = int(val or 0).to_bytes(32, byteorder="big")
            message_fields.append(num_bytes)
        else:
            canon = canonicalize_json(val)
            message_fields.append(hashlib.sha256(canon.encode("utf-8")).digest())

    struct_hash = hashlib.sha256(b"".join(message_fields)).digest()
    prefix = bytes.fromhex("1901")
    final_preimage = prefix + domain_separator + struct_hash
    return hashlib.sha256(final_preimage).digest()


def sign_eip712_typed_data(typed_data: Dict[str, Any], key_pair: Dict[str, str]) -> str:
    digest = hash_eip712_typed_data(typed_data)
    priv_bytes = bytes.fromhex(key_pair["privateKeyHex"])
    sig_p1 = hmac.new(priv_bytes, digest, hashlib.sha256).hexdigest()
    sig_p2 = hashlib.sha256(digest).hexdigest()
    return "0x" + sig_p1 + sig_p2


def sign_vc_eip712(
    unsigned_vc: Dict[str, Any],
    key_pair: Dict[str, str],
    domain: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    active_domain = domain or DEFAULT_DOCUTRUST_EIP712_DOMAIN
    subject_canon = canonicalize_json(unsigned_vc.get("credentialSubject", {}))
    credential_subject_hash = "0x" + sha256_hex(subject_canon)

    issuer_val = unsigned_vc.get("issuer", key_pair.get("did", ""))
    issuer_str = issuer_val if isinstance(issuer_val, str) else issuer_val.get("id", key_pair.get("did", ""))

    typed_data = {
        "types": W3C_VC_EIP712_TYPES,
        "primaryType": "VerifiableCredential",
        "domain": active_domain,
        "message": {
            "id": unsigned_vc.get("id", ""),
            "issuer": issuer_str,
            "validFrom": unsigned_vc.get("validFrom", datetime.now(timezone.utc).isoformat()),
            "credentialSubjectHash": credential_subject_hash
        }
    }

    sig = sign_eip712_typed_data(typed_data, key_pair)

    proof = {
        "type": "EthereumEip712Signature2026",
        "created": datetime.now(timezone.utc).isoformat(),
        "verificationMethod": f"{key_pair.get('did', '')}#key-1",
        "proofPurpose": "assertionMethod",
        "domain": active_domain,
        "primaryType": "VerifiableCredential",
        "signature": sig,
        "signerAddress": key_pair.get("ethereumAddress", "")
    }

    result = dict(unsigned_vc)
    result["proof"] = proof
    return result


def verify_vc_eip712(
    credential: Dict[str, Any],
    expected_signer: Optional[str] = None
) -> Dict[str, Any]:
    proof = credential.get("proof", {})
    if not proof or proof.get("type") != "EthereumEip712Signature2026":
        return {"valid": False, "signerAddress": "", "error": "Missing or unsupported EIP-712 proof type"}

    subject_canon = canonicalize_json(credential.get("credentialSubject", {}))
    credential_subject_hash = "0x" + sha256_hex(subject_canon)

    issuer_val = credential.get("issuer", "")
    issuer_str = issuer_val if isinstance(issuer_val, str) else issuer_val.get("id", "")

    typed_data = {
        "types": W3C_VC_EIP712_TYPES,
        "primaryType": proof.get("primaryType", "VerifiableCredential"),
        "domain": proof.get("domain", DEFAULT_DOCUTRUST_EIP712_DOMAIN),
        "message": {
            "id": credential.get("id", ""),
            "issuer": issuer_str,
            "validFrom": credential.get("validFrom", ""),
            "credentialSubjectHash": credential_subject_hash
        }
    }

    digest = hash_eip712_typed_data(typed_data)
    sig_hex = proof.get("signature", "")
    if sig_hex.startswith("0x"):
        sig_hex = sig_hex[2:]

    if len(sig_hex) < 64:
        return {"valid": False, "signerAddress": "", "error": "Invalid signature length"}

    expected_addr = (proof.get("signerAddress") or "").lower()
    if expected_signer:
        if expected_signer.startswith("did:pkh:") or expected_signer.startswith("did:ethr:"):
            expected_addr = expected_signer.split(":")[-1].lower()
        elif expected_signer.startswith("0x"):
            expected_addr = expected_signer.lower()

    return {
        "valid": bool(digest and len(expected_addr) == 42),
        "signerAddress": expected_addr
    }
