from __future__ import annotations
import requests
import base64
import json
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex, MerkleTree

class DocuTrustClient:
    """Client for DocuTrust Sovereign Trust API v8.0.0."""
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

    def create_accumulator_batch_witness(
        self,
        accumulator: Any,
        elements: List[str]
    ) -> Dict[str, Any]:
        """Generates a constant-size batch membership witness for a subset of elements."""
        return accumulator.create_batch_witness(elements)

    def verify_accumulator_batch_witness(
        self,
        witness: Dict[str, Any],
        current_accumulator_hex: str,
        modulus_hex: Optional[str] = None
    ) -> bool:
        """Verifies a constant-size batch membership witness."""
        from .accumulator import CryptographicAccumulator
        if modulus_hex:
            return CryptographicAccumulator.verify_batch_witness(witness, current_accumulator_hex, modulus_hex)
        return CryptographicAccumulator.verify_batch_witness(witness, current_accumulator_hex)

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

    def evaluate_confidential_linear_combination(
        self,
        terms: List[Dict[str, Any]],
        public_key: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluates a homomorphic linear combination (weighted sum) over Paillier ciphertexts."""
        from .confidential import ConfidentialClaimsEngine
        return ConfidentialClaimsEngine.evaluate_linear_combination(terms, public_key)

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

    # ==========================================
    # Verifiable SVG Digital Badge Methods
    # ==========================================

    def render_badge_svg(
        self,
        credential: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Renders a tamper-evident SVG digital badge containing embedded credential metadata."""
        from .badge import BadgeEngine
        return BadgeEngine.render_badge_svg(credential, options)

    def verify_badge_svg(self, svg_content: str) -> Dict[str, Any]:
        """Verifies the integrity and authenticity of an SVG badge."""
        from .badge import BadgeEngine
        return BadgeEngine.verify_badge_svg(svg_content)

    # ==========================================
    # v9.0.0 Sovereign Policy-as-Proof & did:peer
    # ==========================================

    def evaluate_policy(
        self,
        payload: Dict[str, Any],
        policy: Dict[str, Any],
        evaluator_keypair: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Evaluates a verifiable credential or presentation against an AST policy."""
        from .policy import PolicyEngine
        return PolicyEngine.evaluate(payload, policy, evaluator_keypair=evaluator_keypair)

    def verify_policy_receipt(
        self,
        receipt: Dict[str, Any],
        expected_evaluator_public_key_hex: Optional[str] = None
    ) -> bool:
        """Cryptographically verifies a DocuTrustPolicyReceipt2026."""
        from .policy import PolicyEngine
        return PolicyEngine.verify_receipt(receipt, expected_evaluator_public_key_hex=expected_evaluator_public_key_hex)

    def create_did_peer_0(self, public_key_hex: str) -> str:
        """Creates a W3C did:peer:0 inception key URI."""
        from .did import create_did_peer_0
        return create_did_peer_0(public_key_hex)

    def create_did_peer_2(
        self,
        verification_key_hex: str,
        encryption_key_hex: Optional[str] = None,
        service_endpoint: Optional[str] = None
    ) -> str:
        """Creates a W3C did:peer:2 multi-key and service endpoint URI."""
        from .did import create_did_peer_2
        return create_did_peer_2(
            verification_key_hex=verification_key_hex,
            encryption_key_hex=encryption_key_hex,
            service_endpoint=service_endpoint
        )

    def generate_solidity_registry(
        self,
        contract_name: str = "DocuTrustRegistry",
        solidity_version: str = "^0.8.20"
    ) -> str:
        """Generates a multi-issuer Sovereign Trust Registry smart contract for on-chain accreditation."""
        from .solidity import SolidityEngine
        return SolidityEngine.generate_registry_contract(
            contract_name=contract_name,
            solidity_version=solidity_version
        )

    # ========================================================
    # v10.0.0 Linkable Ring Signatures (LSAG)
    # ========================================================

    def sign_ring_signature(
        self,
        message: Union[str, bytes, Dict[str, Any]],
        ring: List[str],
        signer_private_key_hex: str,
        signer_public_key_hex: str
    ) -> Dict[str, Any]:
        """Signs a message anonymously using a 1-of-N Linkable Ring Signature."""
        from .ringsig import RingSignatureEngine
        return RingSignatureEngine.sign(
            message=message,
            ring=ring,
            signer_private_key_hex=signer_private_key_hex,
            signer_public_key_hex=signer_public_key_hex
        )

    def verify_ring_signature(
        self,
        message: Union[str, bytes, Dict[str, Any]],
        signature: Dict[str, Any],
        used_key_images: Optional[Union[Set[str], List[str]]] = None
    ) -> Dict[str, Any]:
        """Verifies a 1-of-N Linkable Ring Signature and checks for double-voting/double-action."""
        from .ringsig import RingSignatureEngine
        return RingSignatureEngine.verify(
            message=message,
            signature=signature,
            used_key_images=used_key_images
        )

    # ========================================================
    # v10.0.0 256-bit Sparse Merkle Trees (SMT)
    # ========================================================

    def set_smt_leaf(self, key: str, value: str) -> Dict[str, Any]:
        """Sets or updates a leaf in a 256-bit Sparse Merkle Tree via REST API."""
        return self._request("/smt/set", method="POST", json_data={"key": key, "value": value})

    def generate_smt_proof(self, key: str, entries: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Generates an SMT inclusion/non-membership proof via REST API."""
        return self._request("/smt/prove", method="POST", json_data={"key": key, "entries": entries or {}})

    def verify_smt_proof(self, proof: Dict[str, Any], root: Optional[str] = None) -> Dict[str, Any]:
        """Verifies an SMT proof via REST API or local logic."""
        return self._request("/smt/verify", method="POST", json_data={"proof": proof, "root": root})

    def generate_solidity_smt_verifier(
        self,
        contract_name: str = "DocuTrustSMTVerifier",
        solidity_version: str = "^0.8.20"
    ) -> str:
        """Generates production-ready Solidity contract code for verifying 256-bit SMT proofs."""
        from .solidity import SolidityEngine
        return SolidityEngine.generate_smt_verifier_contract(
            contract_name=contract_name,
            solidity_version=solidity_version
        )

    # ========================================================
    # v11.0.0 NIST FIPS 205 SLH-DSA Methods
    # ========================================================

    def generate_slhdsa_key_pair(self) -> Dict[str, Any]:
        """Generates a NIST FIPS 205 SLH-DSA keypair."""
        from .slhdsa import SLHDSAEngine
        return SLHDSAEngine.generate_key_pair()

    def sign_slhdsa(self, message: Any, key_pair: Dict[str, Any]) -> Dict[str, Any]:
        """Signs a message with SLH-DSA."""
        from .slhdsa import SLHDSAEngine
        return SLHDSAEngine.sign(message, key_pair)

    def verify_slhdsa(self, message: Any, signature: Any, public_key: Any) -> bool:
        """Verifies an SLH-DSA post-quantum signature."""
        from .slhdsa import SLHDSAEngine
        return SLHDSAEngine.verify(message, signature, public_key)

    # ========================================================
    # v11.0.0 WebAuthn / FIDO2 Passkey Methods
    # ========================================================

    def generate_webauthn_key_pair(self, rp_id: str = "localhost") -> Dict[str, Any]:
        """Generates a WebAuthn P-256 passkey keypair."""
        from .webauthn import WebAuthnAttestationEngine
        return WebAuthnAttestationEngine.generate_key_pair(rp_id)

    def create_webauthn_assertion(self, challenge: str, key_pair: Dict[str, Any], options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Creates a signed hardware passkey assertion."""
        from .webauthn import WebAuthnAttestationEngine
        return WebAuthnAttestationEngine.create_assertion(challenge, key_pair, options)

    def verify_webauthn_assertion(self, assertion: Dict[str, Any], challenge: str, public_key: Any, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Verifies a WebAuthn passkey assertion."""
        from .webauthn import WebAuthnAttestationEngine
        return WebAuthnAttestationEngine.verify_assertion(assertion, challenge, public_key, options)

    # ========================================================
    # v11.0.0 Multi-Chain Verifiable Attestation Bridge Methods
    # ========================================================

    def create_crosschain_message(
        self,
        source_chain_id: int,
        destination_chain_id: int,
        sequence_nonce: int,
        state_root: str,
        payload_hash: str,
        sender_address: str = "0x0000000000000000000000000000000000000001",
        recipient_address: str = "0x0000000000000000000000000000000000000002"
    ) -> Dict[str, Any]:
        """Constructs a standard cross-chain attestation bridge message."""
        from .crosschain import CrossChainBridgeEngine
        return CrossChainBridgeEngine.create_message(
            source_chain_id, destination_chain_id, sequence_nonce, state_root, payload_hash, sender_address, recipient_address
        )

    def sign_crosschain_message(self, message: Dict[str, Any], relayer_key_pair: Dict[str, Any]) -> Dict[str, Any]:
        """Signs a cross-chain packet as an authorized relayer."""
        from .crosschain import CrossChainBridgeEngine
        return CrossChainBridgeEngine.sign_message(message, relayer_key_pair)

    def assemble_crosschain_attestation(self, message: Dict[str, Any], signatures: List[Dict[str, Any]], quorum_threshold: int = 1) -> Dict[str, Any]:
        """Assembles relayer signatures into a cross-chain attestation."""
        from .crosschain import CrossChainBridgeEngine
        return CrossChainBridgeEngine.assemble_attestation(message, signatures, quorum_threshold)

    def verify_crosschain_attestation(self, attestation: Dict[str, Any], authorized_relayers: Optional[List[str]] = None) -> Dict[str, Any]:
        """Verifies a multi-relayer cross-chain attestation against quorum threshold."""
        from .crosschain import CrossChainBridgeEngine
        return CrossChainBridgeEngine.verify_attestation(attestation, authorized_relayers)

    # ========================================================
    # v11.0.0 BN254 Groth16 Zero-Knowledge SNARK Methods
    # ========================================================

    def setup_groth16_circuit(self, circuit_name: str, public_input_count: int = 2) -> Dict[str, Any]:
        """Generates a Groth16 circuit verification key."""
        from .groth16 import Groth16Engine
        return Groth16Engine.generate_verification_key(circuit_name, public_input_count)

    def prove_groth16(self, circuit_name: str, public_inputs: List[Any], witness_secret: Optional[Any] = None) -> Dict[str, Any]:
        """Generates a BN254 Groth16 Zero-Knowledge proof."""
        from .groth16 import Groth16Engine
        return Groth16Engine.create_proof(circuit_name, public_inputs, witness_secret)

    def verify_groth16_proof(self, proof: Dict[str, Any], vk: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies a BN254 Groth16 ZK-SNARK proof against a verification key."""
        from .groth16 import Groth16Engine
        return Groth16Engine.verify_proof(proof, vk)

    def aggregate_groth16_proofs(self, proofs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregates multiple Groth16 proofs into a batched verification payload."""
        from .groth16 import Groth16Engine
        return Groth16Engine.aggregate_proofs(proofs)

    # ========================================================
    # v11.0.0 Solidity Exporters
    # ========================================================

    def generate_solidity_bridge_relayer(self, contract_name: str = "DocuTrustBridgeRelayer", solidity_version: str = "^0.8.20") -> str:
        """Generates production-ready Solidity contract for Cross-Chain Bridge Relayer."""
        from .solidity import SolidityEngine
        return SolidityEngine.generate_bridge_relayer_contract(contract_name, solidity_version)

    def generate_solidity_groth16_verifier(self, contract_name: str = "DocuTrustGroth16Verifier", solidity_version: str = "^0.8.20") -> str:
        """Generates production-ready Solidity contract for Groth16 SNARK verification."""
        from .solidity import SolidityEngine
        return SolidityEngine.generate_groth16_verifier_contract(contract_name, solidity_version)

    # ========================================================
    # v12.0.0 Sovereign Trust Mesh & Verifiable Compute Methods
    # ========================================================

    def evaluate_trust_score(
        self,
        credential: Dict[str, Any],
        evaluator_key_pair: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Evaluates multi-vector trust score and optionally issues a signed risk receipt."""
        from .trust_score import TrustScoreEngine
        if evaluator_key_pair:
            return TrustScoreEngine.issue_risk_receipt(credential, evaluator_key_pair, options)
        return TrustScoreEngine.calculate_trust_score(credential, options)

    def verify_trust_score_receipt(self, receipt: Dict[str, Any], evaluator_public_key: str) -> Dict[str, Any]:
        """Cryptographically verifies a signed DocuTrustRiskReceipt2026."""
        from .trust_score import TrustScoreEngine
        return TrustScoreEngine.verify_risk_receipt(receipt, evaluator_public_key)

    def execute_verifiable_compute(
        self,
        program: Dict[str, Any],
        inputs: Dict[str, Any],
        prover_key_pair: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Executes a deterministic AST program and generates execution trace & receipt."""
        from .verifiable_compute import VerifiableComputeEngine
        return VerifiableComputeEngine.execute_program(program, inputs, prover_key_pair)

    def verify_compute_receipt(
        self,
        receipt: Dict[str, Any],
        prover_public_key: str,
        inputs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Verifies an off-chain compute execution receipt."""
        from .verifiable_compute import VerifiableComputeEngine
        return VerifiableComputeEngine.verify_compute_receipt(receipt, prover_public_key, inputs)

    def issue_vanish_token(
        self,
        claims: Dict[str, Any],
        issuer_key_pair: Dict[str, Any],
        subject_did: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Issues an ephemeral forward-secret token with time-decay commitment."""
        from .vanish_cred import VanishCredEngine
        return VanishCredEngine.issue_token(claims, issuer_key_pair, subject_did, options)

    def verify_vanish_token(
        self,
        token: Dict[str, Any],
        ephemeral_key: str,
        issuer_public_key: str,
        current_epoch: Optional[int] = None
    ) -> Dict[str, Any]:
        """Verifies and decrypts an active ephemeral vanish token."""
        from .vanish_cred import VanishCredEngine
        return VanishCredEngine.verify_and_decrypt(token, ephemeral_key, issuer_public_key, current_epoch)

    def generate_state_delta(
        self,
        base_state: Dict[str, Any],
        target_state: Dict[str, Any],
        relayer_key_pair: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generates a compact O(Δ) cross-ledger delta proof between state replicas."""
        from .state_sync import StateSyncEngine
        return StateSyncEngine.generate_delta_proof(base_state, target_state, relayer_key_pair, options)

    def verify_state_delta(
        self,
        base_state: Dict[str, Any],
        delta_proof: Dict[str, Any],
        relayer_public_key: str
    ) -> Dict[str, Any]:
        """Reconciles and verifies a cross-ledger delta proof against an initial base state."""
        from .state_sync import StateSyncEngine
        return StateSyncEngine.verify_and_reconcile(base_state, delta_proof, relayer_public_key)

    def generate_universal_solidity_verifier(
        self,
        contract_name: str = "DocuTrustUniversalVerifier",
        solidity_version: str = "^0.8.20"
    ) -> str:
        """Generates master Solidity contract verifying Merkle, SMT-256, Cross-Chain Bridge, and Groth16."""
        from .solidity import SolidityEngine
        return SolidityEngine.generate_universal_verifier_contract(contract_name, solidity_version)

    # ==========================================
    # v13.0.0 Sovereign Trust Mesh Evolution Methods
    # ==========================================

    def aggregate_recursive_zk_proofs(
        self,
        sub_proofs: List[Dict[str, Any]],
        aggregator_key_pair: Dict[str, Any],
        depth: int = 1,
        generate_evm_calldata: bool = False
    ) -> Dict[str, Any]:
        """Aggregates multiple heterogeneous ZK sub-proofs via Fiat-Shamir recursive folding."""
        from .zk_recursive import ZKRecursiveEngine
        return ZKRecursiveEngine.aggregate_proofs(sub_proofs, aggregator_key_pair, depth, generate_evm_calldata)

    def verify_recursive_zk_proof(
        self,
        proof: Dict[str, Any],
        aggregator_public_key_hex: str
    ) -> Dict[str, Any]:
        """Verifies a recursive ZK aggregated proof."""
        from .zk_recursive import ZKRecursiveEngine
        return ZKRecursiveEngine.verify_recursive_proof(proof, aggregator_public_key_hex)

    def initialize_revocation_lattice(
        self,
        lattice_id: str,
        issuer_did: str,
        shards_count: int = 4
    ) -> Dict[str, Any]:
        """Initializes a 2D multi-epoch temporal-spatial revocation lattice."""
        from .revocation_lattice import RevocationLatticeEngine
        return RevocationLatticeEngine.initialize_lattice(lattice_id, issuer_did, shards_count)

    def accumulate_revocation_lattice(
        self,
        state: Dict[str, Any],
        revoked_credential_ids: List[str],
        advance_epoch: bool = False
    ) -> Dict[str, Any]:
        """Accumulates credential revocations into lattice slices and advances epochs."""
        from .revocation_lattice import RevocationLatticeEngine
        return RevocationLatticeEngine.accumulate_revocations(state, revoked_credential_ids, advance_epoch)

    def generate_revocation_lattice_proof(
        self,
        state: Dict[str, Any],
        credential_id: str,
        issuer_key_pair: Dict[str, Any],
        target_epoch: Optional[int] = None
    ) -> Dict[str, Any]:
        """Generates an O(1) non-revocation / revocation witness proof across lattice slices."""
        from .revocation_lattice import RevocationLatticeEngine
        return RevocationLatticeEngine.generate_lattice_proof(state, credential_id, issuer_key_pair, target_epoch)

    def verify_revocation_lattice_proof(
        self,
        proof: Dict[str, Any],
        issuer_public_key_hex: str,
        expected_lattice_root: Optional[str] = None
    ) -> Dict[str, Any]:
        """Cryptographically verifies a lattice revocation proof."""
        from .revocation_lattice import RevocationLatticeEngine
        return RevocationLatticeEngine.verify_lattice_proof(proof, issuer_public_key_hex, expected_lattice_root)

    def issue_agent_attestation(
        self,
        payload: Dict[str, Any],
        agent_key_pair: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Issues an autonomous AI agent action attestation with model card fingerprinting and trace commitment."""
        from .agent_provenance import AgentProvenanceEngine
        return AgentProvenanceEngine.issue_attestation(payload, agent_key_pair)

    def verify_agent_attestation(
        self,
        attestation: Dict[str, Any],
        agent_public_key_hex: str,
        expected_output: Optional[Union[Dict[str, Any], str]] = None
    ) -> Dict[str, Any]:
        """Verifies an AI agent action attestation and guardrail compliance."""
        from .agent_provenance import AgentProvenanceEngine
        return AgentProvenanceEngine.verify_attestation(attestation, agent_public_key_hex, expected_output)

    # ========================================================
    # v14.0.0 VRF & Multi-Oracle Consensus Mesh Methods
    # ========================================================

    def evaluate_vrf(
        self,
        input_seed: Union[str, bytes, Dict[str, Any]],
        key_pair: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluates a deterministic Verifiable Random Function (VRF) with proof."""
        from .vrf_oracle import VRFOracleEngine
        return VRFOracleEngine.evaluate(input_seed, key_pair)

    def verify_vrf(
        self,
        evaluation: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Cryptographically verifies a VRF evaluation and deterministic output."""
        from .vrf_oracle import VRFOracleEngine
        return VRFOracleEngine.verify(evaluation)

    def create_vrf_beacon(
        self,
        epoch: int,
        round_num: int,
        previous_beacon_hash: str,
        oracle_key_pairs: List[Dict[str, Any]],
        threshold_required: Optional[int] = None
    ) -> Dict[str, Any]:
        """Creates a multi-oracle threshold randomness beacon round."""
        from .vrf_oracle import VRFOracleEngine
        return VRFOracleEngine.create_beacon(epoch, round_num, previous_beacon_hash, oracle_key_pairs, threshold_required)

    def verify_vrf_beacon(
        self,
        beacon: Dict[str, Any],
        expected_beacon_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a multi-oracle threshold randomness beacon."""
        from .vrf_oracle import VRFOracleEngine
        return VRFOracleEngine.verify_beacon(beacon, expected_beacon_hash)

    def create_oracle_feed(
        self,
        feed_id: str,
        round_num: int,
        data_payload: Any,
        oracle_key_pairs: List[Dict[str, Any]],
        threshold_required: Optional[int] = None
    ) -> Dict[str, Any]:
        """Issues a signed multi-oracle threshold data feed."""
        from .vrf_oracle import VRFOracleEngine
        return VRFOracleEngine.issue_oracle_feed(feed_id, round_num, data_payload, oracle_key_pairs, threshold_required)

    def verify_oracle_feed(
        self,
        feed: Dict[str, Any],
        trusted_oracle_public_keys: Optional[Union[List[str], Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """Verifies a multi-oracle threshold consensus data feed."""
        from .vrf_oracle import VRFOracleEngine
        return VRFOracleEngine.verify_oracle_feed(feed, trusted_oracle_public_keys)

    # ========================================================
    # v14.0.0 ZK Multi-Attribute Predicate DSL Methods
    # ========================================================

    def compile_zk_dsl(
        self,
        expression: str
    ) -> Dict[str, Any]:
        """Compiles a declarative predicate expression into an AST & constraint system."""
        from .zk_dsl import ZKDSLEngine
        return ZKDSLEngine.compile_dsl(expression)

    def prove_zk_dsl(
        self,
        expression: str,
        attributes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Synthesizes a non-interactive zero-knowledge proof for a predicate DSL."""
        from .zk_dsl import ZKDSLEngine
        return ZKDSLEngine.generate_proof(expression, attributes)

    def verify_zk_dsl(
        self,
        proof: Dict[str, Any],
        expression: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a Zero-Knowledge predicate DSL proof."""
        from .zk_dsl import ZKDSLEngine
        return ZKDSLEngine.verify_proof(proof, expression)

    # ========================================================
    # v14.0.0 AI-BOM Registry & Weights Merkle Methods
    # ========================================================

    def create_aibom_receipt(
        self,
        manifest: Dict[str, Any],
        certifier_key_pair: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Computes a weights Merkle root and creates an AI-BOM cryptographic receipt."""
        from .ai_bom import AIBOMRegistryEngine
        return AIBOMRegistryEngine.create_aibom_receipt(manifest, certifier_key_pair)

    def verify_aibom_receipt(
        self,
        receipt: Dict[str, Any],
        certifier_public_key: str,
        expected_weights_root: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies an AI Bill of Materials (AI-BOM) receipt and weights root."""
        from .ai_bom import AIBOMRegistryEngine
        return AIBOMRegistryEngine.verify_aibom_receipt(receipt, certifier_public_key, expected_weights_root)

    def generate_aibom_layer_proof(
        self,
        manifest: Dict[str, Any],
        layer_index: int
    ) -> Dict[str, Any]:
        """Generates a Merkle inclusion proof for a single neural network layer."""
        from .ai_bom import AIBOMRegistryEngine
        return AIBOMRegistryEngine.generate_layer_proof(manifest, layer_index)

    def verify_aibom_layer_proof(
        self,
        proof: Dict[str, Any],
        expected_root: str
    ) -> Dict[str, Any]:
        """Verifies a single layer Merkle inclusion proof against a weights root."""
        from .ai_bom import AIBOMRegistryEngine
        return AIBOMRegistryEngine.verify_layer_proof(proof, expected_root)

    # ========================================================
    # v14.0.0 Post-Quantum Falcon & ML-DSA Signature Methods
    # ========================================================

    def generate_falcon_keypair(
        self,
        mode: str = 'Falcon-512'
    ) -> Dict[str, Any]:
        """Generates a Falcon-512 / Falcon-1024 dual-lattice key pair."""
        from .pqc_falcon import PQCFalconEngine
        return PQCFalconEngine.generate_key_pair(mode)

    def sign_falcon(
        self,
        message: Any,
        private_key_hex: str,
        mode: str = 'Falcon-512'
    ) -> Dict[str, Any]:
        """Signs a payload using post-quantum Falcon lattice signature."""
        from .pqc_falcon import PQCFalconEngine
        return PQCFalconEngine.sign(message, private_key_hex, mode)

    def verify_falcon(
        self,
        message: Any,
        signature_hex: str,
        public_key_hex: str
    ) -> Dict[str, Any]:
        """Verifies a post-quantum Falcon lattice signature."""
        from .pqc_falcon import PQCFalconEngine
        return PQCFalconEngine.verify(message, signature_hex, public_key_hex)

    # ========================================================
    # v15.0.0 Post-Quantum Double Ratchet Protocol Methods
    # ========================================================

    def pq_ratchet_generate_keys(self) -> Dict[str, Any]:
        """Generates a hybrid classical + post-quantum ratchet key pair."""
        from .pq_ratchet import PQRatchetEngine
        return PQRatchetEngine.generate_ratchet_key_pair()

    def pq_ratchet_init_initiator(
        self,
        bob_combined_public_key: str,
        initial_shared_secret_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Initializes a Double Ratchet session for the Initiator."""
        from .pq_ratchet import PQRatchetEngine
        return PQRatchetEngine.init_initiator_session(bob_combined_public_key, initial_shared_secret_hex)

    def pq_ratchet_init_responder(
        self,
        bob_key_pair: Dict[str, Any],
        initial_shared_secret_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Initializes a Double Ratchet session for the Responder."""
        from .pq_ratchet import PQRatchetEngine
        return PQRatchetEngine.init_responder_session(bob_key_pair, initial_shared_secret_hex)

    def pq_ratchet_encrypt(
        self,
        session: Dict[str, Any],
        payload: Union[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Encrypts payload with current sending chain message key."""
        from .pq_ratchet import PQRatchetEngine
        return PQRatchetEngine.encrypt(session, payload)

    def pq_ratchet_decrypt(
        self,
        session: Dict[str, Any],
        message: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Decrypts message, advancing ratchet if new ratchet key received."""
        from .pq_ratchet import PQRatchetEngine
        return PQRatchetEngine.decrypt(session, message)

    # ========================================================
    # v15.0.0 Polynomial Commitments & Multi-Proof Batching Methods
    # ========================================================

    def poly_generate_srs(self, max_degree: int = 64, secret_seed: str = 'DOCUTRUST_POLYNOMIAL_SRS_SEED_V15') -> Dict[str, Any]:
        """Generates a Structured Reference String (SRS) for polynomial commitments."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.generate_srs(max_degree, secret_seed)

    def poly_commit(self, coefficients: List[Union[int, str]], srs: Dict[str, Any]) -> Dict[str, Any]:
        """Commits to a polynomial represented by coefficients."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.commit(coefficients, srs)

    def poly_evaluate(self, coefficients: List[Union[int, str]], point_z: Union[int, str]) -> int:
        """Evaluates polynomial P(z) at point z modulo BN254 prime."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.evaluate_polynomial(coefficients, point_z)

    def poly_create_proof(self, coefficients: List[Union[int, str]], point_z: Union[int, str], srs: Dict[str, Any]) -> Dict[str, Any]:
        """Creates an opening proof for polynomial P(x) at point z."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.create_evaluation_proof(coefficients, point_z, srs)

    def poly_verify_proof(self, commitment: Dict[str, Any], proof: Dict[str, Any], srs: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies an opening proof against a polynomial commitment."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.verify_evaluation_proof(commitment, proof, srs)

    def poly_multi_proof(self, coefficients: List[Union[int, str]], points: List[Union[int, str]], srs: Dict[str, Any]) -> Dict[str, Any]:
        """Creates a multi-point evaluation proof."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.create_multi_point_proof(coefficients, points, srs)

    def poly_aggregate_proofs(self, commitments: List[Dict[str, Any]], proofs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregates multiple evaluation proofs into a batch proof with EVM calldata."""
        from .polynomial_commitments import PolynomialCommitmentEngine
        return PolynomialCommitmentEngine.aggregate_proofs(commitments, proofs)

    # ========================================================
    # v15.0.0 Hardware-Enforced TEE Remote Attestation Methods
    # ========================================================

    def tee_generate_quote(
        self,
        tee_platform: str,
        measurements: Dict[str, Any],
        report_data_payload: Union[str, Dict[str, Any]],
        hardware_key_pair: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generates a hardware-modeled TEE remote attestation quote."""
        from .tee_attestation import TEEAttestationEngine
        return TEEAttestationEngine.generate_attestation_quote(tee_platform, measurements, report_data_payload, hardware_key_pair)

    def tee_verify_quote(
        self,
        quote: Dict[str, Any],
        expected_report_data: Optional[Union[str, Dict[str, Any]]] = None,
        allowed_mr_enclaves: Optional[List[str]] = None,
        allowed_mr_signers: Optional[List[str]] = None,
        min_isv_svn: Optional[int] = None
    ) -> Dict[str, Any]:
        """Validates a TEE remote attestation quote."""
        from .tee_attestation import TEEAttestationEngine
        return TEEAttestationEngine.verify_attestation_quote(
            quote,
            expected_report_data_payload=expected_report_data,
            allowed_mr_enclaves=allowed_mr_enclaves,
            allowed_mr_signers=allowed_mr_signers,
            min_isv_svn=min_isv_svn
        )

    def tee_issue_credential(
        self,
        claims: Dict[str, Any],
        enclave_key_pair: Dict[str, Any],
        quote: Dict[str, Any],
        issuer_key_pair: Dict[str, Any],
        credential_id: Optional[str] = None,
        credential_type: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Issues a W3C Verifiable Credential cryptographically bound to a TEE quote."""
        from .tee_attestation import TEEAttestationEngine
        return TEEAttestationEngine.issue_tee_bound_credential(
            claims, enclave_key_pair, quote, issuer_key_pair, credential_id, credential_type
        )

    def tee_verify_credential(
        self,
        credential: Dict[str, Any],
        issuer_public_key_hex: Optional[str] = None,
        allowed_mr_enclaves: Optional[List[str]] = None,
        allowed_mr_signers: Optional[List[str]] = None,
        min_isv_svn: Optional[int] = None
    ) -> Dict[str, Any]:
        """Verifies a TEE-bound Verifiable Credential."""
        from .tee_attestation import TEEAttestationEngine
        return TEEAttestationEngine.verify_tee_bound_credential(
            credential, issuer_public_key_hex, allowed_mr_enclaves, allowed_mr_signers, min_isv_svn
        )

    # ========================================================
    # v15.0.0 Inter-Blockchain Communication (IBC) Relayer Methods
    # ========================================================

    def ibc_compute_packet_commitment(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Computes deterministic ICS-04 packet commitment hash."""
        from .ibc_relayer import IBCRelayerEngine
        return IBCRelayerEngine.compute_packet_commitment(packet)

    def ibc_generate_merkle_proof(self, key: str, value_hex: str, depth: int = 4) -> Dict[str, Any]:
        """Creates a synthetic Merkle proof for an IBC state key-value pair."""
        from .ibc_relayer import IBCRelayerEngine
        return IBCRelayerEngine.generate_merkle_proof(key, value_hex, depth)

    def ibc_verify_merkle_proof(self, proof: Dict[str, Any], expected_root_app_hash: str) -> bool:
        """Verifies an IBC Merkle state proof against light-client AppHash."""
        from .ibc_relayer import IBCRelayerEngine
        return IBCRelayerEngine.verify_merkle_proof(proof, expected_root_app_hash)

    def ibc_create_light_client(
        self,
        chain_id: str,
        client_type: str,
        initial_height: Dict[str, int],
        initial_app_hash: str
    ) -> Dict[str, Any]:
        """Creates and initializes a light-client tracking state."""
        from .ibc_relayer import IBCRelayerEngine
        return IBCRelayerEngine.create_light_client(chain_id, client_type, initial_height, initial_app_hash)

    def ibc_update_light_client(
        self,
        client: Dict[str, Any],
        new_height: Dict[str, int],
        new_app_hash: str,
        validator_signatures: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Updates light-client state with a new header."""
        from .ibc_relayer import IBCRelayerEngine
        return IBCRelayerEngine.update_light_client(client, new_height, new_app_hash, validator_signatures)

    def ibc_relay_packet(
        self,
        packet: Dict[str, Any],
        proof: Dict[str, Any],
        source_client_on_dest: Dict[str, Any],
        proof_height: Dict[str, int],
        relayer_key_pair: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Relays an IBC packet across heterogeneous chains."""
        from .ibc_relayer import IBCRelayerEngine
        return IBCRelayerEngine.relay_packet(packet, proof, source_client_on_dest, proof_height, relayer_key_pair)







