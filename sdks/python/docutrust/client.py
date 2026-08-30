from __future__ import annotations
import requests
import base64
import json
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex, MerkleTree

class DocuTrustClient:
    """Client for DocuTrust Sovereign Trust API v5.0.0."""
    def __init__(self, api_url: str = "https://api.docutrust.org/api/v1", api_key: Optional[str] = None):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"Authorization": f"Bearer {api_key}"})

    def _request(self, endpoint: str, method: str = "GET", json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Internal helper for executing REST requests."""
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        method = method.upper()
        if method == "GET":
            res = self.session.get(url)
        elif method == "POST":
            res = self.session.post(url, json=json_data or {})
        elif method == "PUT":
            res = self.session.put(url, json=json_data or {})
        elif method == "DELETE":
            res = self.session.delete(url)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        res.raise_for_status()
        return res.json()

    def issue_credential(
        self,
        credential_subject: Dict[str, Any],
        credential_type: str = "AchievementCredential",
        valid_until: Optional[str] = None,
        enable_selective_disclosure: bool = False,
        enable_pqc: bool = False
    ) -> Dict[str, Any]:
        url = f"{self.api_url}/credentials/issue"
        payload = {
            "credentialSubject": credential_subject,
            "type": ["VerifiableCredential", credential_type],
            "validUntil": valid_until,
            "enableSelectiveDisclosure": enable_selective_disclosure,
            "enablePQC": enable_pqc
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def batch_issue(
        self,
        records: List[Dict[str, Any]],
        credential_type: str = "UniversityDegreeCredential",
        anchor_to_ledger: bool = True
    ) -> Dict[str, Any]:
        url = f"{self.api_url}/credentials/issue-batch"
        payload = {
            "records": [{"credentialSubject": r} for r in records],
            "type": ["VerifiableCredential", credential_type],
            "anchorToLedger": anchor_to_ledger
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def verify_credential(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.api_url}/credentials/verify"
        res = self.session.post(url, json={"credential": credential})
        res.raise_for_status()
        return res.json()

    def verify_pdf(self, pdf_bytes_or_base64: Union[bytes, str]) -> Dict[str, Any]:
        """Extracts and verifies embedded W3C Verifiable Credential from a PDF."""
        url = f"{self.api_url}/credentials/verify-pdf"
        if isinstance(pdf_bytes_or_base64, bytes):
            b64 = base64.b64encode(pdf_bytes_or_base64).decode('utf-8')
        else:
            b64 = pdf_bytes_or_base64
        res = self.session.post(url, json={"pdfBase64": b64})
        res.raise_for_status()
        return res.json()

    def generate_selective_disclosure(
        self,
        credential: Dict[str, Any],
        disclosed_keys: List[str]
    ) -> Dict[str, Any]:
        url = f"{self.api_url}/credentials/selective-disclosure"
        payload = {
            "credential": credential,
            "revealKeys": disclosed_keys
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def encrypt_data(self, data: Any, passphrase: str) -> Dict[str, Any]:
        """Encrypts data with AES-256-GCM via API vault."""
        url = f"{self.api_url}/vault/encrypt"
        res = self.session.post(url, json={"data": data, "passphrase": passphrase})
        res.raise_for_status()
        return res.json()

    def decrypt_data(self, encrypted_payload: Dict[str, Any], passphrase: str) -> Dict[str, Any]:
        """Decrypts AES-256-GCM payload via API vault."""
        url = f"{self.api_url}/vault/decrypt"
        res = self.session.post(url, json={"encrypted": encrypted_payload, "passphrase": passphrase})
        res.raise_for_status()
        return res.json()

    def prove_zk_range(
        self,
        claim_key: str,
        actual_value: float,
        min_val: float,
        max_val: float,
        salt: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates a Zero-Knowledge Range Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/prove"
        payload = {
            "predicateType": "range",
            "claimKey": claim_key,
            "actualValue": actual_value,
            "salt": salt,
            "min": min_val,
            "max": max_val
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def verify_zk_predicate(self, proof: Dict[str, Any], expected_commitment: Optional[str] = None) -> Dict[str, Any]:
        """Verifies a Zero-Knowledge Predicate Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/verify"
        res = self.session.post(url, json={"proof": proof, "expectedCommitment": expected_commitment})
        res.raise_for_status()
        return res.json()

    def prove_zk_membership(
        self,
        claim_key: str,
        secret_value: str,
        allowed_set: List[str],
        salt: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates a Zero-Knowledge Set Membership Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/prove"
        payload = {
            "predicateType": "membership",
            "claimKey": claim_key,
            "actualValue": secret_value,
            "allowedSet": allowed_set,
            "salt": salt
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def verify_zk_membership(
        self,
        proof: Dict[str, Any],
        allowed_set: List[str],
        expected_commitment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a Zero-Knowledge Set Membership Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/verify"
        res = self.session.post(url, json={
            "proof": proof,
            "allowedSet": allowed_set,
            "expectedCommitment": expected_commitment
        })
        res.raise_for_status()
        return res.json()

    def prove_zk_age(
        self,
        birth_date: str,
        minimum_age_years: int = 18,
        claim_key: str = "birthDate",
        salt: Optional[str] = None,
        reference_date: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates a Zero-Knowledge Age Predicate Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/prove-age"
        payload = {
            "claimKey": claim_key,
            "birthDate": birth_date,
            "minimumAgeYears": minimum_age_years,
            "salt": salt,
            "referenceDate": reference_date
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def verify_zk_age(self, proof: Dict[str, Any], expected_commitment: Optional[str] = None) -> Dict[str, Any]:
        """Verifies a Zero-Knowledge Age Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/verify-age"
        res = self.session.post(url, json={"proof": proof, "expectedCommitment": expected_commitment})
        res.raise_for_status()
        return res.json()

    def prove_zk_date(
        self,
        actual_date: str,
        min_date: str,
        max_date: str,
        claim_key: str = "date",
        salt: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates a Zero-Knowledge Date Range Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/prove-date"
        payload = {
            "claimKey": claim_key,
            "actualDate": actual_date,
            "minDate": min_date,
            "maxDate": max_date,
            "salt": salt
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def verify_zk_date(self, proof: Dict[str, Any], expected_commitment: Optional[str] = None) -> Dict[str, Any]:
        """Verifies a Zero-Knowledge Date Range Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/verify-date"
        res = self.session.post(url, json={"proof": proof, "expectedCommitment": expected_commitment})
        res.raise_for_status()
        return res.json()

    def kem_generate_keys(self) -> Dict[str, Any]:
        """Generates Post-Quantum ML-KEM-768 hybrid keys."""
        url = f"{self.api_url}/kem/generate-keys"
        res = self.session.post(url, json={})
        res.raise_for_status()
        return res.json()

    def create_pop_challenge(self, audience: str = "did:web:docutrust.org") -> Dict[str, Any]:
        """Creates an ephemeral Proof-of-Possession challenge."""
        url = f"{self.api_url}/credentials/pop/challenge"
        res = self.session.post(url, json={"audience": audience})
        res.raise_for_status()
        return res.json()

    def verify_pop_presentation(self, presentation: Dict[str, Any], expected_audience: Optional[str] = None) -> Dict[str, Any]:
        """Verifies a Proof-of-Possession presentation."""
        url = f"{self.api_url}/credentials/pop/verify"
        payload = {"presentation": presentation}
        if expected_audience:
            payload["expectedAudience"] = expected_audience
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def shamir_split(self, secret: str, total_shares: int = 5, threshold: int = 3) -> Dict[str, Any]:
        """Splits a secret into K-of-N Shamir shares."""
        url = f"{self.api_url}/keys/shamir/split"
        res = self.session.post(url, json={"secret": secret, "totalShares": total_shares, "threshold": threshold})
        res.raise_for_status()
        return res.json()

    def shamir_combine(self, shares: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Reconstructs a secret from Shamir shares."""
        url = f"{self.api_url}/keys/shamir/combine"
        res = self.session.post(url, json={"shares": shares})
        res.raise_for_status()
        return res.json()

    def issue_sd_jwt(self, claims: Dict[str, Any], subject_did: Optional[str] = None) -> Dict[str, Any]:
        """Issues an IETF SD-JWT package with salted disclosures."""
        url = f"{self.api_url}/credentials/sd-jwt/issue"
        payload = {"claims": claims}
        if subject_did:
            payload["subjectDid"] = subject_did
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def verify_sd_jwt(self, presentation: str) -> Dict[str, Any]:
        """Verifies an IETF SD-JWT presentation."""
        url = f"{self.api_url}/credentials/sd-jwt/verify"
        res = self.session.post(url, json={"presentation": presentation})
        res.raise_for_status()
        return res.json()

    def verify_trust_issuer(self, issuer_did: str, schema_type: str) -> Dict[str, Any]:
        """Verifies issuer authorization against Decentralized Trust Registry."""
        url = f"{self.api_url}/trust/verify-issuer"
        res = self.session.post(url, json={"issuerDid": issuer_did, "schemaType": schema_type})
        res.raise_for_status()
        return res.json()

    def create_bloom_filter(self, revoked_ids: List[str], size_bits: int = 8192, hash_count: int = 5) -> Dict[str, Any]:
        """Creates and signs a revocation Bloom filter."""
        url = f"{self.api_url}/revocation/bloom/create"
        res = self.session.post(url, json={"revokedIds": revoked_ids, "sizeBits": size_bits, "hashCount": hash_count})
        res.raise_for_status()
        return res.json()

    def check_bloom_filter(self, signed_filter: Dict[str, Any], credential_id: str) -> Dict[str, Any]:
        """Checks revocation status against a signed Bloom filter."""
        url = f"{self.api_url}/revocation/bloom/check"
        res = self.session.post(url, json={"signedFilter": signed_filter, "credentialId": credential_id})
        res.raise_for_status()
        return res.json()

    def bbs_generate_keys(self, max_messages: int = 10) -> Dict[str, Any]:
        """Generates BBS+ keypair with generator commitments."""
        url = f"{self.api_url}/credentials/bbs/generate-keys"
        res = self.session.post(url, json={"maxMessages": max_messages})
        res.raise_for_status()
        return res.json()

    def bbs_issue(self, messages: List[str], keypair: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Issues BBS+ multi-message signature."""
        url = f"{self.api_url}/credentials/bbs/issue"
        payload = {"messages": messages}
        if keypair:
            payload["keyPair"] = keypair
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def bbs_derive_proof(
        self,
        signature: Dict[str, Any],
        all_messages: List[str],
        disclosed_indices: List[int],
        keypair: Optional[Dict[str, Any]] = None,
        nonce: Optional[str] = None
    ) -> Dict[str, Any]:
        """Derives unlinkable BBS+ zero-knowledge proof."""
        url = f"{self.api_url}/credentials/bbs/derive-proof"
        payload = {
            "signature": signature,
            "allMessages": all_messages,
            "disclosedIndices": disclosed_indices,
            "keyPair": keypair,
            "nonce": nonce
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def bbs_verify_proof(self, proof: Dict[str, Any], expected_issuer_did: Optional[str] = None) -> Dict[str, Any]:
        """Verifies BBS+ zero-knowledge proof."""
        url = f"{self.api_url}/credentials/bbs/verify-proof"
        payload = {"proof": proof}
        if expected_issuer_did:
            payload["expectedIssuerDid"] = expected_issuer_did
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def issue_timestamp_token(self, data: str, nonce: Optional[str] = None) -> Dict[str, Any]:
        """Issues RFC 3161 cryptographic timestamp token from TSA Oracle."""
        url = f"{self.api_url}/oracle/timestamp"
        res = self.session.post(url, json={"data": data, "nonce": nonce})
        res.raise_for_status()
        return res.json()

    def verify_timestamp_token(self, token: Dict[str, Any], expected_data: Optional[str] = None) -> Dict[str, Any]:
        """Verifies RFC 3161 timestamp token integrity."""
        url = f"{self.api_url}/oracle/verify-timestamp"
        res = self.session.post(url, json={"token": token, "expectedData": expected_data})
        res.raise_for_status()
        return res.json()

    def didcomm_pack(
        self,
        message: Dict[str, Any],
        recipient_public_key_hex: str,
        recipient_did: str,
        sender_keypair: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Packs a DIDComm v2 authenticated encrypted envelope."""
        url = f"{self.api_url}/didcomm/pack"
        payload = {
            "message": message,
            "recipientPublicKeyHex": recipient_public_key_hex,
            "recipientDid": recipient_did,
            "senderKeyPair": sender_keypair
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def didcomm_unpack(
        self,
        envelope: Dict[str, Any],
        recipient_keypair: Dict[str, Any],
        expected_sender_did: Optional[str] = None
    ) -> Dict[str, Any]:
        """Unpacks and decrypts a DIDComm v2 message envelope."""
        url = f"{self.api_url}/didcomm/unpack"
        payload = {
            "envelope": envelope,
            "recipientKeyPair": recipient_keypair,
            "expectedSenderDid": expected_sender_did
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def mmr_append(self, leaf: str) -> Dict[str, Any]:
        """Appends a leaf to the streaming Merkle Mountain Range ledger."""
        url = f"{self.api_url}/ledger/mmr/append"
        res = self.session.post(url, json={"leaf": leaf})
        res.raise_for_status()
        return res.json()

    def mmr_get_peaks(self) -> Dict[str, Any]:
        """Retrieves peaks and bagged root of Merkle Mountain Range."""
        url = f"{self.api_url}/ledger/mmr"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def mmr_get_proof(self, element_index: int) -> Dict[str, Any]:
        """Gets Merkle Mountain Range peak inclusion proof."""
        url = f"{self.api_url}/ledger/mmr/proof"
        res = self.session.post(url, json={"elementIndex": element_index})
        res.raise_for_status()
        return res.json()

    def mmr_verify_proof(self, proof: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies Merkle Mountain Range peak inclusion proof."""
        url = f"{self.api_url}/ledger/mmr/verify"
        res = self.session.post(url, json={"proof": proof})
        res.raise_for_status()
        return res.json()

    def get_hashchain(self) -> Dict[str, Any]:
        """Retrieves tamper-evident hashchain and verifies audit integrity."""
        url = f"{self.api_url}/ledger/hashchain"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def get_vault_metrics(self) -> Dict[str, Any]:
        """Gets credential vault metrics and telemetry."""
        url = f"{self.api_url}/vault/metrics"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def auto_anchor_vault(self) -> Dict[str, Any]:
        """Triggers batch auto-anchoring worker on unanchored credentials."""
        url = f"{self.api_url}/vault/auto-anchor"
        res = self.session.post(url, json={})
        res.raise_for_status()
        return res.json()

    def generate_secp256k1_keys(self, chain_id: int = 1) -> Dict[str, str]:
        """Generates Ethereum secp256k1 keypair and did:pkh DID."""
        from .eip712 import generate_secp256k1_key_pair
        return generate_secp256k1_key_pair(chain_id)

    def sign_vc_eip712(
        self,
        unsigned_vc: Dict[str, Any],
        key_pair: Dict[str, str],
        domain: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Signs W3C Verifiable Credential using EIP-712 structured typing."""
        from .eip712 import sign_vc_eip712
        return sign_vc_eip712(unsigned_vc, key_pair, domain)

    def verify_vc_eip712(
        self,
        credential: Dict[str, Any],
        expected_signer: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies EIP-712 structured signature on W3C Verifiable Credential."""
        from .eip712 import verify_vc_eip712
        return verify_vc_eip712(credential, expected_signer)

    def setup_social_recovery(
        self,
        owner_did: str,
        secret: str,
        guardians: List[Dict[str, str]],
        threshold: int = 3,
        challenge_period_hours: int = 48
    ) -> Dict[str, Any]:
        """Sets up decentralized social recovery with guardian DIDs."""
        from .social_recovery import SocialRecoveryEngine
        return SocialRecoveryEngine.setup_recovery(owner_did, secret, guardians, threshold, challenge_period_hours)

    def initiate_social_recovery(
        self,
        owner_did: str,
        requester_did: str,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Initiates a timelocked social recovery session."""
        from .social_recovery import SocialRecoveryEngine
        return SocialRecoveryEngine.initiate_recovery(owner_did, requester_did, config)

    def cast_social_recovery_vote(
        self,
        session: Dict[str, Any],
        guardian_did: str,
        share_index: int,
        raw_share_hex: str
    ) -> Dict[str, Any]:
        """Guardian casts vote with decrypted secret share."""
        from .social_recovery import SocialRecoveryEngine
        return SocialRecoveryEngine.cast_vote(session, guardian_did, share_index, raw_share_hex)

    def veto_social_recovery(
        self,
        session: Dict[str, Any],
        reason: str = "Unauthorized recovery attempt"
    ) -> Dict[str, Any]:
        """Genuine owner vetoes fraudulent recovery session."""
        from .social_recovery import SocialRecoveryEngine
        return SocialRecoveryEngine.veto_recovery(session, reason)

    def finalize_social_recovery(
        self,
        session: Dict[str, Any],
        force_timelock_override: bool = False
    ) -> Dict[str, Any]:
        """Finalizes social recovery session and reconstructs root secret."""
        from .social_recovery import SocialRecoveryEngine
        return SocialRecoveryEngine.finalize_recovery(session, force_timelock_override)

    def prove_set_non_membership(
        self,
        claim_key: str,
        secret_value: str,
        salt: str,
        restricted_set: List[str]
    ) -> Dict[str, Any]:
        """Generates ZK proof that secret_value is NOT in restricted set."""
        from .zk_predicates import prove_set_non_membership
        return prove_set_non_membership(claim_key, secret_value, salt, restricted_set)

    def verify_set_non_membership(
        self,
        proof: Dict[str, Any],
        restricted_set: List[str],
        expected_commitment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies ZK Set Non-Membership proof."""
        from .zk_predicates import verify_set_non_membership_proof
        return verify_set_non_membership_proof(proof, restricted_set, expected_commitment)

    def prove_composite_predicate(self, proofs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Combines multiple ZK predicate proofs into a single composite proof."""
        from .zk_predicates import prove_composite_predicate
        return prove_composite_predicate(proofs)

    def verify_composite_predicate(
        self,
        composite_proof: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Verifies multi-predicate composite ZK proof."""
        from .zk_predicates import verify_composite_predicate
        return verify_composite_predicate(composite_proof, context)

    def format_multichain_anchor(
        self,
        chain: str,
        merkle_root: str,
        batch_count: int,
        memo: str = "DocuTrust Merkle Batch Anchor"
    ) -> Dict[str, Any]:
        """Generates standardized calldata or payload for multi-chain anchoring."""
        from .multichain import MultiChainLedgerAnchor
        return MultiChainLedgerAnchor.format_anchor(chain, merkle_root, batch_count, memo)

    def validate_schema(
        self,
        data: Any,
        schema: Dict[str, Any],
        path: str = "$"
    ) -> Dict[str, Any]:
        """Validates arbitrary data against a JSON schema."""
        from .schema import SchemaValidator
        return SchemaValidator.validate(data, schema, path)

    def validate_credential_subject_schema(
        self,
        credential: Dict[str, Any],
        schema: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validates W3C VC credentialSubject against a JSON Schema."""
        from .schema import SchemaValidator
        return SchemaValidator.validate_credential_subject(credential, schema)

    def compute_schema_hash(self, schema: Dict[str, Any]) -> str:
        """Computes deterministic RFC 8785 canonical hash of a schema."""
        from .schema import SchemaValidator
        return SchemaValidator.compute_schema_hash(schema)

    def create_accumulator(
        self,
        accumulator_id: str,
        modulus_hex: Optional[str] = None,
        generator_hex: Optional[str] = None
    ):
        """Creates a dynamic cryptographic accumulator instance."""
        from .accumulator import CryptographicAccumulator
        kwargs = {}
        if modulus_hex:
            kwargs["modulus_hex"] = modulus_hex
        if generator_hex:
            kwargs["generator_hex"] = generator_hex
        return CryptographicAccumulator(accumulator_id, **kwargs)

    def encrypt_jwe(
        self,
        payload: Union[str, bytes, Dict[str, Any]],
        recipients: List[Dict[str, Any]],
        custom_protected_header: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Encrypts payload for multiple recipient DIDs in General JWE format."""
        from .jwe import MultiRecipientJWE
        return MultiRecipientJWE.encrypt(payload, recipients, custom_protected_header)

    def decrypt_jwe(
        self,
        jwe: Dict[str, Any],
        recipient_did: str,
        recipient_private_key: Union[str, bytes]
    ) -> Dict[str, Any]:
        """Decrypts General JWE payload for recipient DID."""
        from .jwe import MultiRecipientJWE
        return MultiRecipientJWE.decrypt(jwe, recipient_did, recipient_private_key)

    def prove_set_intersection(
        self,
        claim_key: str,
        secret_value: str,
        salt: str,
        target_set: List[str]
    ) -> Dict[str, Any]:
        """Generates ZK Set Intersection Proof."""
        from .zk_predicates import prove_set_intersection
        return prove_set_intersection(claim_key, secret_value, salt, target_set)

    def verify_set_intersection(
        self,
        proof: Dict[str, Any],
        target_set: List[str],
        expected_commitment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies ZK Set Intersection Proof."""
        from .zk_predicates import verify_set_intersection_proof
        return verify_set_intersection_proof(proof, target_set, expected_commitment)

    def create_status_list_2024(
        self,
        length: int = 100000,
        status_size: int = 1,
        status_purpose: str = "revocation"
    ):
        """Creates a W3C BitstringStatusList2024 instance."""
        from .status_list import BitstringStatusList2024
        return BitstringStatusList2024(length, status_size, status_purpose)

    def check_status_list_2024(
        self,
        encoded_list: str,
        index: int,
        status_size: int = 1,
        length: Optional[int] = None
    ) -> Dict[str, Any]:
        """Decodes and checks status at index in a BitstringStatusList2024."""
        from .status_list import BitstringStatusList2024
        opts = {"status_size": status_size}
        if length:
            opts["length"] = length
        list_inst = BitstringStatusList2024.decode(encoded_list, opts)
        status_val = list_inst.get_status(index)
        return {
            "index": index,
            "status": status_val,
            "statusSize": status_size,
            "isValid": list_inst.is_valid(index),
            "isRevoked": list_inst.is_revoked(index),
            "isSuspended": list_inst.is_suspended(index)
        }

    def update_status_list_2024(
        self,
        encoded_list: str,
        index: int,
        status: int,
        status_size: int = 1,
        length: Optional[int] = None
    ) -> Dict[str, Any]:
        """Updates status at index in a BitstringStatusList2024."""
        from .status_list import BitstringStatusList2024
        opts = {"status_size": status_size}
        if length:
            opts["length"] = length
        list_inst = BitstringStatusList2024.decode(encoded_list, opts)
        list_inst.set_status(index, status)
        new_encoded = list_inst.encode(True)
        return {
            "index": index,
            "status": status,
            "encodedList": new_encoded
        }

    def create_presentation_definition(
        self,
        definition_id: str,
        input_descriptors: List[Dict[str, Any]],
        name: Optional[str] = None,
        purpose: Optional[str] = None
    ) -> Dict[str, Any]:
        """Creates a DIF Presentation Exchange 2.0 Presentation Definition."""
        from .presentation_exchange import PresentationExchangeEngine
        opts = {}
        if name:
            opts["name"] = name
        if purpose:
            opts["purpose"] = purpose
        return PresentationExchangeEngine.create_definition(definition_id, input_descriptors, opts)

    def create_presentation_submission(
        self,
        submission_id: str,
        definition_id: str,
        descriptor_map: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Creates a DIF Presentation Exchange 2.0 Presentation Submission."""
        from .presentation_exchange import PresentationExchangeEngine
        return PresentationExchangeEngine.create_submission(submission_id, definition_id, descriptor_map)

    def evaluate_presentation_exchange(
        self,
        presentation: Dict[str, Any],
        definition: Dict[str, Any],
        submission: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Evaluates a Verifiable Presentation against a DIF Presentation Definition."""
        from .presentation_exchange import PresentationExchangeEngine
        return PresentationExchangeEngine.evaluate_presentation(presentation, definition, submission)

    def prove_zk_predicate_graph(
        self,
        graph_id: str,
        root_node: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generates a recursive Zero-Knowledge Predicate Graph Proof."""
        from .zk_predicates import prove_predicate_graph
        return prove_predicate_graph(graph_id, root_node)

    def verify_zk_predicate_graph(
        self,
        graph_proof: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Verifies a recursive Zero-Knowledge Predicate Graph Proof."""
        from .zk_predicates import verify_predicate_graph
        return verify_predicate_graph(graph_proof, context)

    def create_multisig_draft(
        self,
        credential: Dict[str, Any],
        policy: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Creates an unsigned Multi-Signature (M-of-N) Credential draft and canonical hash."""
        from .multisig import MultiSigEngine
        return MultiSigEngine.create_multisig_draft(credential, policy)

    def sign_multisig_as_authority(
        self,
        canonical_hash: str,
        signer_did: str,
        signer_role: str,
        private_key_hex: str
    ) -> Dict[str, Any]:
        """Signs a canonical hash as an authorized institutional authority."""
        from .multisig import MultiSigEngine
        return MultiSigEngine.sign_as_authority(canonical_hash, signer_did, signer_role, private_key_hex)

    def assemble_multisig_credential(
        self,
        credential: Dict[str, Any],
        policy: Dict[str, Any],
        signatures: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Assembles a finalized M-of-N MultiSig Verifiable Credential from collected signatures."""
        from .multisig import MultiSigEngine
        return MultiSigEngine.assemble_multisig_credential(credential, policy, signatures)

    def verify_multisig_credential(
        self,
        credential: Dict[str, Any],
        policy: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Cryptographically verifies an M-of-N MultiSig Verifiable Credential against policy."""
        from .multisig import MultiSigEngine
        return MultiSigEngine.verify_multisig_credential(credential, policy)

    def resolve_did(self, did: str) -> Dict[str, Any]:
        """Resolves a DID string to its complete W3C DID Document."""
        from .did import DIDResolver
        return DIDResolver.resolve(did)

    def get_trust_registry_issuers(self) -> Dict[str, Any]:
        """Retrieves all accredited issuers from the trust registry via API."""
        return self._request("/trust/registry", "GET")

    def get_vault_credentials(
        self,
        search: Optional[str] = None,
        type_filter: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None
    ) -> Dict[str, Any]:
        """Queries stored credentials from the institutional vault."""
        params = []
        if search:
            params.append(f"search={search}")
        if type_filter:
            params.append(f"type={type_filter}")
        if limit is not None:
            params.append(f"limit={limit}")
        if offset is not None:
            params.append(f"offset={offset}")
        qs = f"?{'&'.join(params)}" if params else ""
        return self._request(f"/vault/credentials{qs}", "GET")

    # ==========================================
    # AnonCreds 2.0 & Privacy-Preserving Blind Issuance
    # ==========================================

    def create_anoncreds_blind_request(
        self,
        schema_id: str,
        issuer_did: str,
        master_secret: Optional[str] = None
    ) -> Dict[str, Any]:
        """Holder creates a blind credential request binding a holder master secret."""
        from .anoncreds import AnonCredsEngine
        secret = master_secret or AnonCredsEngine.generate_holder_master_secret()["masterSecret"]
        return AnonCredsEngine.create_blind_request(secret, schema_id, issuer_did)

    def issue_anoncreds_blind_credential(
        self,
        request: Dict[str, Any],
        claims: Dict[str, Any],
        issuer_ed_keys: Optional[Dict[str, Any]] = None,
        issuer_keys: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Issuer issues a blinded BBS+ credential bound to holder master secret."""
        from .anoncreds import AnonCredsEngine
        return AnonCredsEngine.issue_blind_credential(request, claims, issuer_keys, issuer_ed_keys)

    def unblind_anoncreds_credential(
        self,
        blind_credential: Dict[str, Any],
        master_secret: str,
        blinding_factor: str
    ) -> Dict[str, Any]:
        """Holder unblinds the blind credential and stores it with their master secret."""
        from .anoncreds import AnonCredsEngine
        return AnonCredsEngine.unblind_credential(blind_credential, master_secret, blinding_factor)

    def create_anoncreds_presentation(
        self,
        credential: Dict[str, Any],
        master_secret: str,
        reveal_keys: List[str],
        verifier_nonce: str,
        predicate_proofs: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Holder generates an unlinkable Zero-Knowledge Presentation for a Verifier."""
        from .anoncreds import AnonCredsEngine
        return AnonCredsEngine.create_presentation(credential, master_secret, reveal_keys, verifier_nonce, predicate_proofs)

    def verify_anoncreds_presentation(
        self,
        presentation: Dict[str, Any],
        verifier_nonce: Optional[str] = None,
        issuer_did: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifier validates an AnonCreds Zero-Knowledge Presentation."""
        from .anoncreds import AnonCredsEngine
        return AnonCredsEngine.verify_presentation(presentation, verifier_nonce, issuer_did)

    # ==========================================
    # FROST Distributed Key Generation (DKG)
    # ==========================================

    def run_dkg_ceremony(
        self,
        participants: List[Dict[str, Any]],
        threshold: int
    ) -> Dict[str, Any]:
        """Runs a complete Distributed Key Generation (DKG) setup ceremony."""
        from .dkg import DKGEngine
        return DKGEngine.run_dkg_ceremony(participants, threshold)

    def sign_dkg_share(
        self,
        participant_index: int,
        private_share_hex: str,
        signer_did: str,
        message: Union[str, bytes]
    ) -> Dict[str, Any]:
        """Generates a partial signature share for a message using participant private share."""
        from .dkg import DKGEngine
        return DKGEngine.sign_share(participant_index, private_share_hex, signer_did, message)

    def aggregate_dkg_signatures(
        self,
        group_public_key_hex: str,
        group_did: str,
        threshold: int,
        shares: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Aggregates partial signature shares into a valid group Ed25519 signature."""
        from .dkg import DKGEngine
        return DKGEngine.aggregate_signatures(group_public_key_hex, group_did, threshold, shares)

    def verify_dkg_signature(
        self,
        signature: Dict[str, Any],
        message: Union[str, bytes],
        group_public_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies an aggregated FROST threshold signature."""
        from .dkg import DKGEngine
        return DKGEngine.verify_aggregated_signature(signature, message, group_public_key_hex)

    # ==========================================
    # EVM Solidity Smart Contract Verifier
    # ==========================================

    def generate_solidity_verifier(
        self,
        contract_name: str = "DocuTrustVerifier",
        solidity_version: str = "^0.8.20",
        owner_address: Optional[str] = None
    ) -> str:
        """Generates production-ready DocuTrustVerifier.sol Solidity source code."""
        from .solidity import SolidityEngine
        return SolidityEngine.generate_verifier_contract(contract_name, solidity_version, owner_address)

    def encode_solidity_calldata(
        self,
        credential_hash: str,
        merkle_proof: List[Union[str, Dict[str, Any]]],
        root_hash: str
    ) -> Dict[str, Any]:
        """Encodes ABI calldata for calling on-chain verifyCredentialOnChain."""
        from .solidity import SolidityEngine
        return SolidityEngine.encode_verification_calldata(credential_hash, merkle_proof, root_hash)

    # ==========================================
    # Cryptographic Audit Bundles (.dtbundle)
    # ==========================================

    def create_audit_bundle(
        self,
        organization: str = "DocuTrust Enterprise Sovereign Trust",
        signer_keypair: Optional[Dict[str, Any]] = None,
        compliance_standards: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Creates a signed cryptographic audit bundle (.dtbundle)."""
        from .bundle import AuditBundleEngine
        return AuditBundleEngine.create_audit_bundle(
            organization=organization,
            signer_keypair=signer_keypair,
            compliance_standards=compliance_standards
        )

    def verify_audit_bundle(
        self,
        bundle: Dict[str, Any],
        expected_signer_public_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a cryptographic audit bundle (.dtbundle)."""
        from .bundle import AuditBundleEngine
        return AuditBundleEngine.verify_audit_bundle(bundle, expected_signer_public_key_hex)

    def get_audit_bundle_compliance_report(
        self,
        bundle: Dict[str, Any],
        expected_signer_public_key_hex: Optional[str] = None
    ) -> str:
        """Verifies an audit bundle and generates a formal Markdown compliance report."""
        from .bundle import AuditBundleEngine
        result = AuditBundleEngine.verify_audit_bundle(bundle, expected_signer_public_key_hex)
        return AuditBundleEngine.generate_compliance_report(bundle, result)

    # ==========================================
    # W3C DataIntegrityProof Cryptosuites
    # ==========================================

    def issue_data_integrity_credential(
        self,
        credential_subject: Dict[str, Any],
        issuer: Union[str, Dict[str, Any]],
        key_pair: Dict[str, Any],
        cryptosuite: str = "eddsa-jcs-2022",
        type_list: Optional[List[str]] = None,
        valid_until: Optional[str] = None,
        cred_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Issues a W3C Verifiable Credential secured with DataIntegrityProof."""
        from .dataintegrity import DataIntegrityEngine
        return DataIntegrityEngine.issue(
            credential_subject=credential_subject,
            issuer=issuer,
            key_pair=key_pair,
            cryptosuite=cryptosuite,
            type_list=type_list,
            valid_until=valid_until,
            cred_id=cred_id
        )

    def verify_data_integrity_credential(
        self,
        credential: Dict[str, Any],
        expected_public_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a W3C DataIntegrityProof credential."""
        from .dataintegrity import DataIntegrityEngine
        return DataIntegrityEngine.verify(credential, expected_public_key_hex)

    # ==========================================
    # v6.0.0 Confidential Homomorphic Computing
    # ==========================================

    def generate_paillier_key_pair(self, bit_length: int = 512) -> Dict[str, Any]:
        """Generates a Paillier KeyPair for confidential arithmetic."""
        from .confidential import PaillierCryptosystem
        return PaillierCryptosystem.generate_key_pair(bit_length)

    def encrypt_confidential_claim(self, claim_key: str, value: int, public_key: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypts a numeric claim with Paillier Homomorphic encryption."""
        from .confidential import ConfidentialClaimsEngine
        return ConfidentialClaimsEngine.encrypt_claim(claim_key, value, public_key)

    def homomorphic_sum(self, ciphertexts: List[str], public_key: Dict[str, Any]) -> Dict[str, Any]:
        """Sums multiple encrypted claim ciphertexts homomorphically."""
        from .confidential import ConfidentialClaimsEngine
        return ConfidentialClaimsEngine.homomorphic_sum(ciphertexts, public_key)

    def prove_confidential_threshold(
        self,
        claim_key: str,
        actual_value: int,
        threshold: int,
        operator: str,
        public_key: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generates a confidential zero-knowledge threshold proof."""
        from .confidential import ConfidentialClaimsEngine
        return ConfidentialClaimsEngine.prove_threshold(claim_key, actual_value, threshold, operator, public_key)

    def verify_confidential_threshold(self, proof: Dict[str, Any]) -> bool:
        """Verifies a confidential threshold proof."""
        from .confidential import ConfidentialClaimsEngine
        return ConfidentialClaimsEngine.verify_threshold_proof(proof)

    # ==========================================
    # v6.0.0 W3C URDNA2015 JSON-LD Engine
    # ==========================================

    def canonicalize_jsonld(self, doc: Dict[str, Any]) -> str:
        """Canonicalizes a JSON-LD document into deterministic URDNA2015 N-Quads."""
        from .jsonld import JsonLdCanonicalizationEngine
        return JsonLdCanonicalizationEngine.canonicalize(doc)

    def sign_jsonld(
        self,
        doc: Dict[str, Any],
        key_pair: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Signs a JSON-LD document with Linked Data Signatures."""
        from .jsonld import JsonLdCanonicalizationEngine
        return JsonLdCanonicalizationEngine.sign_jsonld(doc, key_pair, options)

    def verify_jsonld(
        self,
        signed_doc: Dict[str, Any],
        expected_public_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a Linked Data Signed JSON-LD document."""
        from .jsonld import JsonLdCanonicalizationEngine
        return JsonLdCanonicalizationEngine.verify_jsonld(signed_doc, expected_public_key_hex)

    # ==========================================
    # v6.0.0 Hierarchical Verifiable Trust Chains
    # ==========================================

    def create_delegation_token(
        self,
        delegator_key_pair: Dict[str, Any],
        delegate_did: str,
        allowed_credential_types: Optional[List[str]] = None,
        max_depth: int = 2,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None
    ) -> Dict[str, Any]:
        """Issues a signed delegation token to a subordinate authority."""
        from .trustchain import TrustChainEngine
        return TrustChainEngine.create_delegation_token(
            delegator_key_pair=delegator_key_pair,
            delegate_did=delegate_did,
            allowed_credential_types=allowed_credential_types,
            max_depth=max_depth,
            valid_from=valid_from,
            valid_until=valid_until
        )

    def verify_trust_chain(
        self,
        chain: List[Dict[str, Any]],
        credential: Dict[str, Any],
        accredited_root_dids: List[str]
    ) -> Dict[str, Any]:
        """Recursively verifies an end-to-end delegation trust chain."""
        from .trustchain import TrustChainEngine
        return TrustChainEngine.verify_trust_chain(
            chain=chain,
            credential=credential,
            accredited_root_dids=accredited_root_dids
        )

    # ==========================================
    # v6.0.0 Post-Quantum Dual Hybrid KEM Armor
    # ==========================================

    def generate_dual_kem_keys(self) -> Dict[str, Any]:
        """Generates a Dual-KEM Hybrid KeyPair (X25519 + NIST ML-KEM-768)."""
        from .quantum_armor import DualHybridKEMEngine
        return DualHybridKEMEngine.generate_dual_key_pair()

    def seal_credential_with_quantum_armor(
        self,
        payload: Dict[str, Any],
        recipient_hybrid_pub: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Seals a credential payload in a quantum-armored envelope."""
        from .quantum_armor import DualHybridKEMEngine
        return DualHybridKEMEngine.seal_credential(payload, recipient_hybrid_pub)

    def unseal_credential_with_quantum_armor(
        self,
        envelope: Dict[str, Any],
        recipient_hybrid_priv: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Unseals a quantum-armored envelope."""
        from .quantum_armor import DualHybridKEMEngine
        return DualHybridKEMEngine.unseal_credential(envelope, recipient_hybrid_priv)
