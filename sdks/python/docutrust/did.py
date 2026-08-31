from __future__ import annotations
from typing import Dict, Any, Optional
from .crypto import decode_base58, encode_base58

class DIDResolver:
    """
    Universal DID Resolver for DocuTrust DIDs (did:key, did:pqc, did:kem, did:bbs, did:pkh, did:web).
    """

    @staticmethod
    def resolve(did: str) -> Dict[str, Any]:
        if not did or not isinstance(did, str):
            raise ValueError("Invalid DID string provided.")

        parts = did.split(":")
        if len(parts) < 3 or parts[0] != "did":
            raise ValueError(f"Malformed DID syntax: {did}")

        method = parts[1]

        if method == "key":
            raw_str = parts[2].split("#")[0]
            multibase = raw_str[1:] if raw_str.startswith("z") else raw_str
            raw = decode_base58(multibase)
            pub_hex = raw[2:34].hex()
            vm_id = f"{did}#{multibase}"
            return {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/ed25519-2020/v1"
                ],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": multibase,
                    "publicKeyHex": pub_hex
                }],
                "authentication": [vm_id],
                "assertionMethod": [vm_id]
            }

        if method == "pqc":
            raw_str = parts[2].split("#")[0]
            multibase = raw_str[1:] if raw_str.startswith("z") else raw_str
            raw = decode_base58(multibase)
            pub_hex = raw[2:34].hex()
            vm_id = f"{did}#ml-dsa-65-hybrid"
            return {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/jws-2020/v1"
                ],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "MLDSA65HybridVerificationKey2026",
                    "controller": did,
                    "publicKeyMultibase": multibase,
                    "classicalPublicKeyHex": pub_hex
                }],
                "authentication": [vm_id],
                "assertionMethod": [vm_id]
            }

        if method == "kem":
            raw_str = parts[2].split("#")[0]
            multibase = raw_str[1:] if raw_str.startswith("z") else raw_str
            raw = decode_base58(multibase)
            pub_hex = raw[2:].hex()
            vm_id = f"{did}#ml-kem-768"
            return {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "MLKEM768KeyAgreementKey2026",
                    "controller": did,
                    "publicKeyMultibase": multibase,
                    "publicKeyHex": pub_hex
                }],
                "keyAgreement": [vm_id]
            }

        if method == "bbs":
            raw_str = parts[2].split("#")[0]
            multibase = raw_str[1:] if raw_str.startswith("z") else raw_str
            raw = decode_base58(multibase)
            pub_hex = raw[2:50].hex() if len(raw) >= 50 else raw[2:].hex()
            vm_id = f"{did}#bbs-g2"
            return {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/bbs/v1"
                ],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "Bls12381G2Key2020",
                    "controller": did,
                    "publicKeyMultibase": multibase,
                    "publicKeyHex": pub_hex
                }],
                "assertionMethod": [vm_id]
            }

        if method == "webauthn":
            raw_str = parts[2].split("#")[0]
            multibase = raw_str[1:] if raw_str.startswith("z") else raw_str
            raw = decode_base58(multibase)
            pub_hex = raw[2:].hex()
            vm_id = f"{did}#passkey-1"
            return {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/jws-2020/v1"
                ],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "JsonWebKey2020",
                    "controller": did,
                    "publicKeyMultibase": f"z{multibase}",
                    "publicKeyHex": pub_hex
                }],
                "authentication": [vm_id],
                "assertionMethod": [vm_id]
            }

        if method == "slh":
            raw_str = parts[2].split("#")[0]
            multibase = raw_str[1:] if raw_str.startswith("z") else raw_str
            raw = decode_base58(multibase)
            pub_hex = raw[2:].hex()
            vm_id = f"{did}#slh-dsa-1"
            return {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/data-integrity/v1"
                ],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "SLHDSAVerificationKey2026",
                    "controller": did,
                    "publicKeyMultibase": f"z{multibase}",
                    "publicKeyHex": pub_hex
                }],
                "authentication": [vm_id],
                "assertionMethod": [vm_id]
            }

        if method == "pkh":
            address = parts[-1]
            vm_id = f"{did}#blockchainAccountId"
            return {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/secp256k1recovery-2020/v1"
                ],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "EcdsaSecp256k1RecoveryMethod2020",
                    "controller": did,
                    "blockchainAccountId": f"{parts[2]}:{address}"
                }],
                "authentication": [vm_id],
                "assertionMethod": [vm_id]
            }

        if method == "jwk":
            raw_encoded = parts[2].split("#")[0]
            # Add base64 padding if needed
            padded = raw_encoded + "=" * ((4 - len(raw_encoded) % 4) % 4)
            # URL-safe base64
            padded = padded.replace("-", "+").replace("_", "/")
            import base64, json
            jwk = json.loads(base64.b64decode(padded).decode("utf-8"))
            kty = jwk.get("kty", "")
            crv = jwk.get("crv", "")
            vm_type = "JsonWebKey2020"
            if kty == "OKP" and crv == "Ed25519":
                vm_type = "Ed25519VerificationKey2020"
            elif kty == "EC" and crv == "secp256k1":
                vm_type = "EcdsaSecp256k1VerificationKey2019"
            elif kty == "RSA":
                vm_type = "RsaVerificationKey2018"

            publicKeyHex = None
            if kty == "OKP" and crv == "Ed25519" and "x" in jwk:
                try:
                    import base64
                    raw_x = jwk["x"]
                    padded_x = raw_x + "=" * ((4 - len(raw_x) % 4) % 4)
                    publicKeyHex = base64.urlsafe_b64decode(padded_x.encode("ascii")).hex()
                except Exception:
                    pass

            vm_id = f"{did}#0"
            vm = {
                "id": vm_id,
                "type": vm_type,
                "controller": did,
                "publicKeyJwk": jwk
            }
            if publicKeyHex:
                vm["publicKeyHex"] = publicKeyHex

            return {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/jws-2020/v1"
                ],
                "id": did,
                "verificationMethod": [vm],
                "authentication": [vm_id],
                "assertionMethod": [vm_id],
                "capabilityInvocation": [vm_id],
                "capabilityDelegation": [vm_id]
            }

        if method == "peer":
            method_num = did[9] if len(did) > 9 else ""
            if method_num == "0":
                multibase = did[10:].split("#")[0]
                if not multibase.startswith("z"):
                    raise ValueError("Invalid did:peer:0 format: expected multibase 'z' prefix.")
                decoded = decode_base58(multibase[1:])
                if decoded[0] != 0xed or decoded[1] != 0x01:
                    raise ValueError("Unsupported did:peer:0 algorithm prefix. Expected Ed25519.")
                pub_hex = decoded[2:].hex()
                vm_id = f"{did}#{multibase}"
                return {
                    "@context": [
                        "https://www.w3.org/ns/did/v1",
                        "https://w3id.org/security/suites/ed25519-2020/v1"
                    ],
                    "id": did,
                    "verificationMethod": [{
                        "id": vm_id,
                        "type": "Ed25519VerificationKey2020",
                        "controller": did,
                        "publicKeyMultibase": multibase,
                        "publicKeyHex": pub_hex
                    }],
                    "authentication": [vm_id],
                    "assertionMethod": [vm_id]
                }

            if method_num == "2":
                import json, base64
                parts_str = did[11:].split("#")[0].split(".")
                vms = []
                auths = []
                asserts = []
                key_agreements = []
                services = []

                key_idx = 0
                service_idx = 0

                for part in parts_str:
                    if not part:
                        continue
                    prefix = part[0]
                    val = part[1:]

                    if prefix == "V" and val.startswith("z"):
                        decoded = decode_base58(val[1:])
                        pub_hex = decoded[2:].hex()
                        key_idx += 1
                        key_id = f"{did}#key-{key_idx}"
                        vms.append({
                            "id": key_id,
                            "type": "Ed25519VerificationKey2020",
                            "controller": did,
                            "publicKeyMultibase": val,
                            "publicKeyHex": pub_hex
                        })
                        auths.append(key_id)
                        asserts.append(key_id)
                    elif prefix == "E" and val.startswith("z"):
                        decoded = decode_base58(val[1:])
                        pub_hex = decoded[2:].hex()
                        key_idx += 1
                        key_id = f"{did}#key-{key_idx}"
                        vms.append({
                            "id": key_id,
                            "type": "X25519KeyAgreementKey2020",
                            "controller": did,
                            "publicKeyMultibase": val,
                            "publicKeyHex": pub_hex
                        })
                        key_agreements.append(key_id)
                    elif prefix == "S":
                        try:
                            padded_s = val + "=" * ((4 - len(val) % 4) % 4)
                            s_json = json.loads(base64.urlsafe_b64decode(padded_s.encode("ascii")).decode("utf-8"))
                            service_idx += 1
                            services.append({
                                "id": f"{did}#service-{service_idx}",
                                "type": s_json.get("t", "DIDCommMessaging"),
                                "serviceEndpoint": s_json.get("s", s_json)
                            })
                        except Exception:
                            pass

                doc = {
                    "@context": [
                        "https://www.w3.org/ns/did/v1",
                        "https://w3id.org/security/suites/ed25519-2020/v1"
                    ],
                    "id": did,
                    "verificationMethod": vms,
                    "authentication": auths,
                    "assertionMethod": asserts
                }
                if key_agreements:
                    doc["keyAgreement"] = key_agreements
                if services:
                    doc["service"] = services
                return doc

            raise ValueError(f"Unsupported did:peer method variant: {did}")

        if method == "web":
            domain = parts[2].replace("%3A", ":")
            vm_id = f"{did}#key-1"
            return {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "verificationMethod": [{
                    "id": vm_id,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did
                }],
                "authentication": [vm_id],
                "assertionMethod": [vm_id]
            }

        raise ValueError(f"Unsupported DID method: {method}")

    @staticmethod
    def create_did_peer_0(public_key_hex: str) -> str:
        """Generates a did:peer:0 (Inception Key) from Ed25519 public key hex."""
        raw_pub = bytes.fromhex(public_key_hex)
        multicodec = bytes([0xed, 0x01]) + raw_pub
        multibase = f"z{encode_base58(multicodec)}"
        return f"did:peer:0{multibase}"

    @staticmethod
    def create_did_peer_2(verification_key_hex: str, encryption_key_hex: Optional[str] = None, service_endpoint: Optional[str] = None) -> str:
        """Generates a did:peer:2 (Multiple Keys & Services) URI."""
        import json, base64
        v_raw = bytes.fromhex(verification_key_hex)
        v_multi = f"z{encode_base58(bytes([0xed, 0x01]) + v_raw)}"
        peer_did = f"did:peer:2.V{v_multi}"

        if encryption_key_hex:
            e_raw = bytes.fromhex(encryption_key_hex)
            e_multi = f"z{encode_base58(bytes([0xec, 0x01]) + e_raw)}"
            peer_did += f".E{e_multi}"

        if service_endpoint:
            s_bytes = json.dumps({"t": "dm", "s": service_endpoint}, separators=(',', ':')).encode("utf-8")
            s_b64 = base64.urlsafe_b64encode(s_bytes).decode("ascii").rstrip("=")
            peer_did += f".S{s_b64}"

        return peer_did

    @staticmethod
    def encode_did_jwk(jwk_or_hex: Union[Dict[str, Any], str]) -> str:
        """Encodes a JSON Web Key dictionary or 64-char public key hex string into a canonical did:jwk URI."""
        import json, base64
        if isinstance(jwk_or_hex, str):
            clean_hex = jwk_or_hex.replace("0x", "").strip()
            raw_bytes = bytes.fromhex(clean_hex)
            b64_x = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")
            jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64_x}
        else:
            jwk = {k: v for k, v in jwk_or_hex.items() if k not in ("d", "p", "q", "dp", "dq", "qi")}

        raw_bytes = json.dumps(jwk, separators=(',', ':')).encode("utf-8")
        b64url = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")
        return f"did:jwk:{b64url}"

    @staticmethod
    def create_did_jwk(jwk_or_hex: Union[Dict[str, Any], str]) -> str:
        """Creates a canonical did:jwk URI from a JWK dict or Ed25519 public key hex string."""
        return DIDResolver.encode_did_jwk(jwk_or_hex)

    @staticmethod
    def decode_did_jwk(did: str) -> Dict[str, Any]:
        """Decodes a did:jwk URI into a JSON Web Key dictionary."""
        import json, base64
        raw = did.replace("did:jwk:", "").split("#")[0]
        padded = raw + "=" * ((4 - len(raw) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))

create_did_peer_0 = DIDResolver.create_did_peer_0
create_did_peer_2 = DIDResolver.create_did_peer_2
encode_did_jwk = DIDResolver.encode_did_jwk
create_did_jwk = DIDResolver.create_did_jwk
decode_did_jwk = DIDResolver.decode_did_jwk


