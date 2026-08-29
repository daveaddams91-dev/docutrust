from __future__ import annotations
import requests
import base64
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex, MerkleTree

class DocuTrustClient:
    """Client for DocuTrust Sovereign Trust API v1.1."""
    def __init__(self, api_url: str = "https://api.docutrust.org/api/v1", api_key: Optional[str] = None):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"Authorization": f"Bearer {api_key}"})

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



