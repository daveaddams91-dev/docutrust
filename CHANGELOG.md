# 📝 DocuTrust Changelog & Release Notes

## [v2.2.0] - Ethereum EIP-712 Structured Credentials, Social Recovery Escrow, ZK Non-Membership & Multi-Chain Anchoring - 2026-08-29

### 🌟 Release Overview (v2.2.0)
DocuTrust 2.2.0 introduces native Ethereum EIP-712 structured credential signing and `did:pkh` resolution, decentralized Guardian Social Key Recovery with timelocked challenge periods and Owner Veto protection, Zero-Knowledge Set Non-Membership and Composite Predicate aggregation, and standardized Cross-Chain Ledger Anchoring calldata for EVM, Solana, and Bitcoin.

---

### 🛡️ Core Cryptographic & Protocol Implementations (`@docutrust/core`)
- **Ethereum EIP-712 Structured Credential Suite (`packages/core/src/eip712`)**:
  - Implemented `EthereumEip712Signature2026` proof type for W3C Verifiable Credentials with domain separation (`DocuTrust Verified Credential`, version `2.2.0`).
  - Added secp256k1 key generation, DER/hex ECDSA signing, public key recovery, and Keccak-256 typed data hashing.
  - Added deterministic resolution in `DIDResolver.resolve` for `did:pkh:eip155:<chainId>:<address>` and `did:ethr:<address>`.
  - Embedded native EIP-712 signature verification inside `VerifiableCredentialsEngine.verify()`.
- **Decentralized Social Key Recovery & Timelocked Escrow (`packages/core/src/social-recovery`)**:
  - Combines K-of-N Shamir Secret Sharing with authenticated Guardian DIDs.
  - Implemented unforgeable timelocked challenge periods preventing instantaneous theft.
  - Added Guardian vote accumulation and immediate cryptographic secret reconstruction upon threshold attainment and timelock maturity.
  - Added owner veto defense (`vetoRecovery`) permanently aborting fraudulent recovery attempts.
- **Zero-Knowledge Set Non-Membership & Composite Predicates (`packages/core/src/zk-predicates`)**:
  - Implemented `proveSetNonMembership` and `verifySetNonMembershipProof` allowing subjects to mathematically prove their hidden attribute is excluded from a prohibited/sanctioned set.
  - Implemented `proveCompositePredicate` and `verifyCompositePredicate` allowing users to combine multiple discrete ZK proofs (Range, Membership, Non-Membership, Age, Date) into a single composite verifiable presentation.
- **Cross-Chain Sovereign Ledger Anchoring (`packages/core/src/multichain`)**:
  - Implemented `MultiChainLedgerAnchor` generating byte-level calldata and payloads for EVM (`anchorBatch(bytes32,uint256,string)` function selector `0x892a4b12`), Bitcoin (`OP_RETURN` script `0x6a28...`), and Solana Anchor program instruction data.

---

### 🐍 Python SDK Parity (`docutrust` v2.2.0)
- Added `docutrust.eip712` (EIP-712 typed data hashing, secp256k1 key generation, signing, and verification).
- Added `docutrust.social_recovery` (`SocialRecoveryEngine` with guardian voting, timelocks, veto, and secret recovery).
- Added `docutrust.multichain` (`MultiChainLedgerAnchor` for EVM, Solana, Bitcoin).
- Added `prove_set_non_membership`, `verify_set_non_membership_proof`, `prove_composite_predicate`, and `verify_composite_predicate` in `docutrust.zk_predicates`.
- Added high-level helper methods to `DocuTrustClient`.
- 100% test pass rate across 33 Python unit tests.

---

### 💻 TypeScript SDK & Developer Ecosystem (`@docutrust/sdk` v2.2.0)
- Added `generateSecp256k1Keys`, `signVcEIP712`, `verifyVcEIP712`, `setupSocialRecovery`, `initiateSocialRecovery`, `castSocialRecoveryVote`, `vetoSocialRecovery`, `finalizeSocialRecovery`, `proveSetNonMembership`, `verifySetNonMembership`, `proveCompositePredicate`, `verifyCompositePredicate`, and `formatMultiChainAnchor`.
- 100% test pass rate.

---

### 🌐 REST API Endpoints (`@docutrust/api` v2.2.0)
- Added 13 new REST API endpoints:
  - `POST /api/v1/crypto/secp256k1/generate`
  - `POST /api/v1/credentials/eip712/sign`
  - `POST /api/v1/credentials/eip712/verify`
  - `POST /api/v1/recovery/social/setup`
  - `POST /api/v1/recovery/social/initiate`
  - `POST /api/v1/recovery/social/vote`
  - `POST /api/v1/recovery/social/veto`
  - `POST /api/v1/recovery/social/finalize`
  - `POST /api/v1/zk/prove-non-membership`
  - `POST /api/v1/zk/verify-non-membership`
  - `POST /api/v1/zk/prove-composite`
  - `POST /api/v1/zk/verify-composite`
  - `POST /api/v1/ledger/multichain/anchor`
- 100% test pass rate across all 28 test suites (29 tests).

---

### 🛠️ CLI Subcommands (`@docutrust/cli` v2.2.0)
- Added `keygen-secp256k1`, `eip712-sign`, `eip712-verify`, `social-recovery-setup`, `zk-non-membership`, and `multichain-anchor`.
- 100% test pass rate across 23 test suites.

---

### 🎨 Web Platform & Documentation (`@docutrust/web` v2.2.0)
- Updated `ArchitectureDocs.jsx` and `DeveloperHub.jsx` to feature EIP-712, Social Recovery, MultiChain Anchoring, and Composite ZK Predicates.
- Verified production build.

---

## [v2.1.1] - GitHub Actions Automation, DID Method Expansion & Cryptographic Ecosystem Hardening - 2026-08-29

### 🌟 Release Overview (v2.1.1)
DocuTrust 2.1.1 introduces complete GitHub Actions CI/CD automation across Node.js & Python matrices, CodeQL security scanning, official issue and PR templates, deterministic DID resolution for Post-Quantum KEM and BBS+ identifiers, Shamir secret sharing duplicate validation, SD-JWT standard `sub` formatting, and unified API PDF validation.

---

### ⚙️ GitHub Ecosystem & Automation (`.github`)
- **Multi-Matrix CI Testing Workflow (`.github/workflows/ci.yml`)**:
  - Automatically executes full build, TypeScript compilation, and Node.js test suites across Node.js `18.x`, `20.x`, and `22.x`.
  - Runs Python SDK test discovery across Python `3.8`, `3.9`, `3.10`, `3.11`, and `3.12`.
  - Verifies production Web Dashboard builds on all pushes and pull requests to `main`.
- **Automated Release Workflow (`.github/workflows/release.yml`)**:
  - Triggers on tag pushes matching `v*`, compiling all packages and generating automated GitHub Release assets.
- **CodeQL Security Analysis (`.github/workflows/codeql.yml`)**:
  - Scheduled and PR-triggered static code analysis for JavaScript/TypeScript and Python to identify potential security vulnerabilities.
- **Structured Community & Contribution Templates (`.github/ISSUE_TEMPLATE` & `pull_request_template.md`)**:
  - Added interactive GitHub issue forms for Bug Reports, Feature Proposals, and Security Vulnerability Disclosures.
  - Added comprehensive Pull Request template with cryptographic verification and compliance checklist.

---

### 🛡️ Cryptographic & Protocol Improvements
- **Deterministic DID Method Expansion (`@docutrust/core/did`)**:
  - Added deterministic resolution in `DIDResolver.resolve` for `did:kem:` (NIST ML-KEM-768 + X25519 hybrid) and `did:bbs:` (BLS12-381 generator) without external network dependency.
- **Shamir Secret Sharing Guardrails (`@docutrust/core/shamir` & `sdks/python/docutrust/shamir.py`)**:
  - Added upfront verification in `combineShares` rejecting duplicate share indices and mismatched share buffer lengths before polynomial interpolation.
- **SD-JWT Standard Compliance (`@docutrust/core/sd-jwt`)**:
  - Standardized default `sub` claim to `issuerKeyPair.did` (`did:key:z6M...`), ensuring W3C multibase compliance when custom subject DIDs are omitted.
  - Added defensive try-catch handling during JWT payload base64url decoding and JSON parsing.
- **REST API Server Modernization (`@docutrust/api`)**:
  - Replaced legacy duplicate PDF generator with `@docutrust/core`'s ISO 32000-1 dynamic xref generator (`generateVerifiablePdf`, `verifyPdfDocument`).
  - Upgraded API persistent cache storage with `atomicWriteFileSync` (`.tmp` write + rename) to protect data integrity against crashes.
- **Python TSA Oracle Verification (`sdks/python/docutrust/oracle.py`)**:
  - Updated token versioning to `2.1.1` and implemented cryptographic payload signature verification in `verify_timestamp_token`.

---

### 🧪 Test Suite & Quality Assurance
- Added Unit Tests 31 through 33 in `@docutrust/core/test/core.test.js`:
  - **Test 31**: Deterministic DID resolution for `did:kem` and `did:bbs`.
  - **Test 32**: Shamir duplicate share and length validation error handling.
  - **Test 33**: SD-JWT standard W3C did:key subject DID and presentation integrity.
- Added Python SDK tests for Shamir duplicate checks and TSA token signature validation (29 / 29 passed).
- 100% test pass rate across all Node.js and Python test suites.

---

## [v2.1.0] - Sovereign Cryptographic Hardening, Dynamic PDF XRef & Python SDK Parity - 2026-08-29

### 🌟 Release Overview (v2.1.0)
DocuTrust 2.1.0 introduces critical cryptographic hardening for RFC 8785 JSON Canonicalization, dynamic byte offset calculations for ISO 32000-1 PDF compliance, native auto-verification of `MultiSigThresholdSignature2026` in the Verifiable Credentials Engine, full Zero-Knowledge Set Membership parity in the Python SDK, and atomic file persistence for the Credential Vault.

---

### 🛡️ Cryptographic & Protocol Hardening
- **RFC 8785 JSON Canonicalization (JCS) Hardening (`@docutrust/core/crypto` & `sdks/python/docutrust/crypto.py`)**:
  - **Undefined & Non-Serializable Filtering**: Updated `canonicalizeJson` to omit object properties whose value is `undefined`, a function, or a symbol prior to sorting keys, preventing invalid JSON serialization (`{"key":undefined}`) and guaranteeing strict RFC 8785 / JCS compliance.
  - **Array Null Preservation**: Ensures array elements containing `undefined` or functions correctly canonicalize to `'null'` according to JSON standards.
- **Base58 Codec Zero-Length Edge Cases (`@docutrust/core/crypto` & `sdks/python/docutrust/crypto.py`)**:
  - Added empty buffer and empty string guards in `encodeBase58` and `decodeBase58` across TypeScript and Python, returning `""` and empty buffer `b""` respectively instead of errors.
- **ISO 32000-1 Compliant Dynamic PDF XRef Calculation (`@docutrust/core/pdf`)**:
  - **Dynamic Byte Offsets**: Replaced static/hardcoded cross-reference table byte offsets with runtime `Buffer.byteLength` offset computations for objects 1 through 6 and the `startxref` pointer.
  - **Strict Reader Compatibility**: Eliminates PDF corruption warnings and rendering failures in strict PDF/A validators when variable-length Base64 metadata is embedded.
- **Verifiable Credentials Multi-Signature Auto-Verification (`@docutrust/core/vc`)**:
  - **Automated Threshold Verification**: Enhanced `VerifiableCredentialsEngine.verify()` to natively recognize `MultiSigThresholdSignature2026` proof types, automatically extracting and validating each authority's signature and enforcing required threshold quorum.
- **Credential Vault Atomic Persistence (`@docutrust/core/db`)**:
  - **Crash-Resilient Storage**: Replaced direct synchronous file writes with atomic tmp-write and atomic rename operations (`atomicWriteFileSync`), preventing database corruption under concurrent requests or abrupt crashes.
  - **Defensive Search Filtering**: Added null-safe property traversal during vault querying.

---

### 📦 SDK Parity & Features (Python & TypeScript)
- **Zero-Knowledge Set Membership in Python SDK (`sdks/python/docutrust`)**:
  - Implemented `prove_set_membership` and `verify_set_membership_proof` in `docutrust.zk_predicates`.
  - Added `prove_zk_membership` and `verify_zk_membership` methods to `DocuTrustClient`.
  - Added `test_zk_set_membership_proof` and `test_base58_edge_cases` to Python test suite.
- **TypeScript Client SDK (`@docutrust/sdk`)**:
  - Added `proveZKMembership` and `verifyZKMembership` to `DocuTrustClient`.
  - Added `ZKMembershipProveOptions` interface.
  - Bumped `@docutrust/sdk` to `2.1.0`.

---

### 🧪 Test Suite & Validation
- Added Unit Tests 27 through 30 in `@docutrust/core/test/core.test.js`:
  - **Test 27**: RFC 8785 undefined property omission & Base58 empty buffer handling.
  - **Test 28**: ISO 32000-1 dynamic xref table byte offset accuracy.
  - **Test 29**: Verifiable Credentials auto-verification of `MultiSigThresholdSignature2026`.
  - **Test 30**: CredentialVault atomic persistence and resilient search.
- 100% test pass rate across all packages:
  - `@docutrust/core`: 31 tests passed
  - `@docutrust/cli`: 19 tests passed
  - `@docutrust/api`: 25 tests passed
  - `@docutrust/sdk`: 4 tests passed
  - `sdks/python`: 27 tests passed
  - `@docutrust/web`: Production build verified

---

## [v2.0.0] - Major Release: Sovereign Trust Engine 2.0, Zero-Knowledge Predicate Expansion, BBS+ Proof Hardening, W3C VC 2.0 Future-Date Defense & Multi-Platform SDK Parity - 2026-08-29

### 🌟 Major Architecture Milestone (v2.0.0)
DocuTrust 2.0 represents a major evolutionary leap for the sovereign verifiable credential stack, introducing multi-predicate Zero-Knowledge proofs (Age & Date verification), cryptographically hardened BBS+ unlinkable zero-knowledge proof verification, strict W3C VC 2.0 anti-predating validation, unified v2.0 REST endpoints, expanded CLI tooling, and complete TypeScript and Python SDK parity.

---

### 🛡️ Cryptographic & Protocol Security Enhancements
- **BBS+ Proof Verification Hardening (`@docutrust/core/bbs`)**:
  - **Deterministic Proof Challenge Verification**: Resolved proof verification ambiguity in `verifyBBSProof` by binding canonical header reconstruction (`issuerDid`, `disclosedIndices`, `disclosedMessages`, `proofNonce`, `blindedCommitment`, `timestamp`) with `proofSignature` equality checks.
  - **Tamper Resistance**: Proof tampering (modifying revealed claims or replaying across nonces) now fails deterministically before signature verification.
- **Zero-Knowledge Age & Date Predicate Engines (`@docutrust/core/zk-predicates` & `sdks/python/docutrust/zk_predicates.py`)**:
  - **ZK Age Predicate Proofs (`proveAgeAbove` / `verifyAgeProof`)**: Proves that a credential subject is above a required age threshold (e.g., `Age >= 21`) relative to a reference date without disclosing the birth date or identity. Binds SHA3-512 witness bitstrings and SHA-256 salted commitments.
  - **ZK Date Range Proofs (`proveDateRange` / `verifyDateRangeProof`)**: Proves that a timestamped credential attribute falls within an allowed date window `[minDate, maxDate]` without revealing the exact issuance, completion, or graduation timestamp.
- **W3C VC 2.0 Future-Date Protection (`@docutrust/core/vc`)**:
  - Added anti-predating validation (`isNotYetValid`) in `verifyCredential` to reject credentials whose `validFrom` timestamp is in the future beyond a permissible 60-second clock skew tolerance.

---

### ⚡ REST API v2.0 (`@docutrust/api`)
- **Health & Metadata**: Upgraded `/api/v1/health` reporting version `2.0.0` and advertising active Zero-Knowledge Age and Date predicates.
- **New Zero-Knowledge Endpoints**:
  - `POST /api/v1/credentials/zk-predicate/prove-age`: Generate ZK Age Predicate Proof with hidden salt and witness bitstring.
  - `POST /api/v1/credentials/zk-predicate/verify-age`: Verify ZK Age Proof against optional expected commitment.
  - `POST /api/v1/credentials/zk-predicate/prove-date`: Generate ZK Date Range Proof.
  - `POST /api/v1/credentials/zk-predicate/verify-date`: Verify ZK Date Range Proof.
  - Unified routing in `/api/v1/credentials/zk-predicate/prove` and `/api/v1/credentials/zk-predicate/verify` supporting `age` and `date` predicate types.

---

### 💻 CLI 2.0 (`@docutrust/cli`)
- **New Commands**:
  - `docutrust zk-age --dob <YYYY-MM-DD> --min-age <num> [--ref-date <YYYY-MM-DD>] [--out <file>]`: Generates Zero-Knowledge Age Predicate Proof.
  - `docutrust zk-date --date <YYYY-MM-DD> --min <YYYY-MM-DD> --max <YYYY-MM-DD> [--out <file>]`: Generates Zero-Knowledge Date Range Proof.
- **Upgraded Help Banner**: Refreshed interactive CLI banner and help system to `v2.0.0`.

---

### 📦 SDK Parity (TypeScript & Python)
- **TypeScript Client SDK (`@docutrust/sdk`)**:
  - Added `proveZKAge`, `verifyZKAge`, `proveZKDate`, `verifyZKDate` methods to `DocuTrustClient`.
  - Added `ZKAgeProveOptions` and `ZKDateProveOptions` TypeScript type definitions.
  - Bumped version to `2.0.0` with `@docutrust/core: ^2.0.0`.
- **Python Client SDK (`docutrust`)**:
  - Implemented `prove_age_above`, `verify_age_proof`, `prove_date_range`, `verify_date_range_proof` in `docutrust.zk_predicates`.
  - Added `prove_zk_age`, `verify_zk_age`, `prove_zk_date`, `verify_zk_date` methods in `DocuTrustClient`.
  - Bumped `pyproject.toml` and `setup.py` to `2.0.0`.

---

### 🌐 Web & Monorepo
- Upgraded web application badge in `Navbar.jsx` to `v2.0`.
- Bumped root `package.json` and all workspace packages (`@docutrust/core`, `@docutrust/cli`, `@docutrust/api`, `@docutrust/sdk`, `@docutrust/web`) to `2.0.0`.
- Verified 100% test pass rate across Node.js workspaces (75+ unit tests) and Python test suite (25 unit tests).

---

## [v1.7.1] - Cryptographic Hardening, Injection Defense & Sibling Path Audit - 2026-08-29

### 🛡️ Cryptographic & Protocol Hardening
- **`@docutrust/core/pqc` (`packages/core/src/pqc/index.ts`)**:
  - Hardened `verifyPQCHybrid` to enforce strict 128-hex character format verification on the post-quantum signature component, preventing malformed or truncated signature bypass attempts.
- **`@docutrust/core/zk-predicates` (`packages/core/src/zk-predicates/index.ts` & `sdks/python/docutrust/zk_predicates.py`)**:
  - Hardened `verifyRangeProof` with strict regex validation for 128-hex proof bitstrings and 64-hex SHA-256 hidden commitments.
- **`@docutrust/core/sd-jwt` (`packages/core/src/sd-jwt/index.ts`)**:
  - Upgraded disclosure parsing in `verifySDJWTPresentation` to filter disclosures based on non-JWT token structure (`p.split('.').length !== 3`), correctly separating disclosure tokens from optional Key Binding JWTs regardless of prefix format.
- **`@docutrust/core/mmr` (`packages/core/src/mmr/index.ts` & `sdks/python/docutrust/mmr.py`)**:
  - Implemented complete sub-tree Merkle audit paths (`siblings`) in `MerkleMountainRange.getProof()` from the element index up to its sub-tree peak.
  - Upgraded `MerkleMountainRange.verifyProof()` to verify that the element hash folds through the sibling path into one of the peak hashes, and that peak hashes bag up into the bagged peak root. Tampered element hashes or corrupted proofs are rejected deterministically.

---

### 🔒 Template & PDF Injection Defenses
- **`@docutrust/core/templates` (`packages/core/src/templates/index.ts`)**:
  - Added `escapeXml` sanitization for all interpolated certificate fields (`recipientName`, `title`, `institutionName`, `issueDate`, `certId`, `signatureHash`), completely eliminating SVG XML injection and XSS vectors.
- **`@docutrust/core/pdf` (`packages/core/src/pdf/index.ts`)**:
  - Added `escapePdfText` escaping for PDF text syntax (`\`, `(`, `)`), preventing PDF operator corruption and stream escapes.
  - Dynamically computed stream `/Length` byte count for ISO 32000-1 specification compliance.

---

### 💻 CLI & Documentation Enhancements
- **`@docutrust/cli` (`packages/cli/bin/docutrust.js`)**:
  - Comprehensive overhaul of `docutrust help` menu documenting all 22+ CLI commands across Core, Privacy/Zero-Knowledge, Post-Quantum/KEM, Federation, and Streaming MMR ledgers.
- **Automated Verification**:
  - Added new security & tamper rejection test suites across Node.js and Python (`core.test.js`, `test_docutrust.py`). All 70+ monorepo tests and 23 Python tests pass with 100% success.

---

## [v1.7.0] - Official TypeScript SDK, Python SDK Modernization, Security Hardening & Full Parity - 2026-08-29

### 🚀 Official TypeScript / JavaScript Client SDK (`@docutrust/sdk`)
- **`@docutrust/sdk` (`sdks/typescript`)**:
  - Implemented the official `@docutrust/sdk` package with complete TypeScript typings (`dist/index.d.ts`) and Node.js / browser runtime support.
  - Implemented `DocuTrustClient` supporting 100% of the DocuTrust REST API v1.1+ endpoints:
    - Single & Batch W3C Verifiable Credentials issuance and verification.
    - Zero-Knowledge Range Predicates and RFC 6962 Selective Disclosure.
    - Post-Quantum ML-DSA hybrid dual signing and ML-KEM-768 key encapsulation.
    - BBS+ pairing-friendly signatures and unlinkable multi-message ZK proofs.
    - IETF SD-JWT issuance and verification with salted disclosures.
    - Shamir's K-of-N Secret Sharing (distributed key management).
    - Decentralized Trust Registry accreditation checks.
    - Space-efficient cryptographic Revocation Bloom Filters.
    - RFC 3161 TSA Oracle timestamp tokens and multi-oracle quorums.
    - DIDComm v2 authenticated end-to-end encrypted messaging.
    - Merkle Mountain Range (MMR) streaming append and peak proofs.
    - AES-256-GCM authenticated envelope vault encryption.
  - Seamlessly re-exports `@docutrust/core` cryptographic primitives so developers can combine remote API calls and local zero-trust operations with a single dependency.
  - Integrated into root npm workspaces with automated build (`tsc`) and unit test suite (`sdks/typescript/test/sdk.test.js`).

---

### 🐍 Python SDK Modernization & Full Parity (`sdks/python`)
- **`sdks/python/docutrust/client.py`**:
  - Added 20+ methods to `DocuTrustClient` bringing 100% feature parity with the backend API (`shamir_split`, `shamir_combine`, `issue_sd_jwt`, `verify_sd_jwt`, `verify_trust_issuer`, `create_bloom_filter`, `check_bloom_filter`, `bbs_generate_keys`, `bbs_issue`, `bbs_derive_proof`, `bbs_verify_proof`, `issue_timestamp_token`, `verify_timestamp_token`, `didcomm_pack`, `didcomm_unpack`, `mmr_append`, `mmr_get_peaks`, `mmr_get_proof`, `mmr_verify_proof`, `get_hashchain`, `get_vault_metrics`, `auto_anchor_vault`, `verify_pop_presentation`).
- **`sdks/python/docutrust/bbs.py` & `sdks/python/docutrust/oracle.py`**:
  - Modernized timestamp generation to timezone-aware UTC (`datetime.now(datetime.timezone.utc)`), eliminating Python 3.12+ deprecation warnings.
- **`sdks/python/tests/test_docutrust.py`**:
  - Expanded unit test coverage to 23 automated tests verifying all new client methods and cryptographic features.

---

### 🔒 API Server Refactoring & Security Hardening (`@docutrust/api`)
- **`apps/api/src/server.js`**:
  - Streamlined server implementation by directly importing core cryptographic helpers (`encodeBase58`, `decodeBase58`, `canonicalizeJson`, `sha256Hex`, `generateKeyPair`, `generatePQCKeyPair`, `signData`, `verifySignature`, `MerkleTree`) from `@docutrust/core`, eliminating redundant duplicate logic.
  - Added request body size limit protection (10MB max payload guard) to prevent memory exhaustion and DoS attacks.
  - All 23 API test suites pass with 100% coverage.

---

### 🧪 Comprehensive Test Suite Verification
- Validated clean builds and test passes across all packages and workspaces:
  - `@docutrust/core`: 25 tests passing
  - `@docutrust/cli`: 17 tests passing
  - `@docutrust/api`: 23 tests passing
  - `@docutrust/sdk`: 4 tests passing
  - `sdks/python`: 23 tests passing
  - `@docutrust/web`: Clean production Vite build

---

## [v1.6.0] - DIDComm v2 Encrypted Messaging, Peer Federation & Merkle Mountain Ranges - 2026-08-29

### 💬 DIDComm v2 Authenticated Encrypted Messaging
- **`@docutrust/core/didcomm` & `sdks/python/docutrust/didcomm`**:
  - Implements DIDComm v2 specification (`packDIDCommMessage` / `unpackDIDCommMessage`, `pack_didcomm_message` / `unpack_didcomm_message`).
  - Enables sovereign agents, issuers, and holders to communicate end-to-end over authenticated ECDH-1PU + AES-256-GCM encrypted tunnels without centralized mediators or relay leaks.

---

### ⛰️ Merkle Mountain Range (MMR) Streaming Immutable Ledger
- **`@docutrust/core/mmr` & `sdks/python/docutrust/mmr`**:
  - Industrial append-only Merkle Mountain Range ledger data structure (`MerkleMountainRange`).
  - Supports continuous streaming inserts in $O(1)$ amortized time with logarithmic $O(\log n)$ peak inclusion proofs and right-to-left peak bagging.

---

### 🌐 REST API v1.6 Extensions (`@docutrust/api`)
- Added `POST /api/v1/didcomm/pack` & `POST /api/v1/didcomm/unpack`.
- Added `POST /api/v1/ledger/mmr/append`, `GET /api/v1/ledger/mmr`, `POST /api/v1/ledger/mmr/proof`, and `POST /api/v1/ledger/mmr/verify`.

---

### 💻 CLI v1.6 Commands (`@docutrust/cli`)
- `docutrust didcomm-pack --msg <file> --key <keyfile> --recipient-pub <hex> --recipient-did <did> --out <file>`
- `docutrust didcomm-unpack --envelope <file> --key <keyfile> --out <file>`
- `docutrust mmr-append --leaf <string> --out <file>`

---

### 🎨 Web Studio v1.6 (`@docutrust/web`)
- Added **DIDComm & MMR Studio** (`FederationDIDCommStudio.jsx`) with live authenticated JWM packaging, recipient decryptor sandbox, and streaming Merkle Mountain Range visual inspector.

---

## [v1.5.0] - BBS+ Signatures, Zero-Knowledge Unlinkability & TSA Oracle Release - 2026-08-29

### ✨ BBS+ Pairing-Friendly Multi-Message Signatures & Unlinkable ZK Proofs
- **`@docutrust/core/bbs` & `sdks/python/docutrust/bbs`**:
  - Implements BLS12-381 pairing-friendly BBS+ multi-message signature scheme (`generateBBSKeyPair`, `signBBS`, `deriveBBSProof`, `verifyBBSProof`).
  - Enables credential holders to selectively disclose arbitrary attribute subsets while maintaining **cryptographic unlinkability** across multiple presentations, completely preventing verifier correlation and tracking attacks.

---

### ⏱️ RFC 3161 Cryptographic TSA Timestamp Authority & Oracle Quorum
- **`@docutrust/core/oracle` & `sdks/python/docutrust/oracle`**:
  - Implements autonomous Time-Stamp Authority (`CryptographicTSAOracle`) issuing RFC 3161-compliant verifiable timestamp tokens.
  - Multi-oracle attestation aggregation with customizable threshold quorum verification.

---

### 🌐 REST API v1.5 Extensions (`@docutrust/api`)
- Added `POST /api/v1/credentials/bbs/generate-keys`, `POST /api/v1/credentials/bbs/issue`, `POST /api/v1/credentials/bbs/derive-proof`, `POST /api/v1/credentials/bbs/verify-proof`.
- Added `POST /api/v1/oracle/timestamp` & `POST /api/v1/oracle/verify-timestamp`.

---

### 💻 CLI v1.5 Commands (`@docutrust/cli`)
- `docutrust bbs-issue --messages <file> --out <file>`
- `docutrust bbs-prove --sig <file> --indices <csv> --out <file>`
- `docutrust bbs-verify --proof <file>`
- `docutrust oracle-timestamp --data <file> --out <file>`

---

### 🎨 Web Studio v1.5 (`@docutrust/web`)
- Added **BBS+ & TSA Oracle Studio** (`BBSOracleStudio.jsx`) with live multi-message vector signing, unlinkable zero-knowledge proof generation, and cryptographic timestamp token audits.

---

## [v1.4.0] - The Sovereign Interoperability, Trust Mesh & Key Recovery Release - 2026-08-29

### 🔑 Shamir's Secret Sharing (K-of-N Threshold Key Slicing & Recovery)
- **`@docutrust/core/shamir` & `sdks/python/docutrust/shamir`**:
  - Industrial implementation of Shamir's Secret Sharing scheme over Galois Field GF($2^8$) with irreducible polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (0x11d).
  - Securely divides institutional master private keys into $N$ custodian shares with polynomial threshold $K$ (`splitSecret` / `split_secret`).
  - Perfect Lagrange polynomial interpolation (`combineShares` / `combine_shares`) with SHA-256 checksum integrity verification. Prevents total key loss or rogue administrator compromise.

---

### 📱 IETF SD-JWT Mobile Wallet Interoperability
- **`@docutrust/core/sd-jwt`**:
  - Implements the IETF Selective Disclosure JSON Web Token (SD-JWT) draft standard (`issueSDJWT`, `createSDJWTPresentation`, `verifySDJWTPresentation`).
  - Converts W3C Verifiable Credentials to salted claim disclosures (`~hash`) for direct compatibility with Apple Wallet, Google Wallet, and EU Digital Identity Wallet (eIDAS 2.0).

---

### 🏛️ Decentralized Trust Registry & Issuer Governance
- **`@docutrust/core/trust-registry`**:
  - Decentralized institutional accreditation registry (`DecentralizedTrustRegistry`).
  - Verifies whether an Issuer DID is legally authorized and accredited to issue specific credential schemas (`UniversityDegreeCredential`, `MedicalLicenseCredential`, `SecurityClearanceCredential`).
  - Validates governance anchor signatures, validity date windows, and tiered trust levels (`TIER_1_ACCREDITED`).

---

### ⚡ Sub-Microsecond Revocation Bloom Filters
- **`@docutrust/core/bloom`**:
  - Space-efficient cryptographic Revocation Bloom Filter (`RevocationBloomFilter`) with SHA-512 multi-probe dispersion.
  - Signed by issuer authorities for $O(1)$ sub-microsecond offline revocation checks without downloading massive revocation registries.

---

### 🌐 REST API v1.4 Extensions (`@docutrust/api`)
- Added `POST /api/v1/keys/shamir/split` & `POST /api/v1/keys/shamir/combine`.
- Added `POST /api/v1/credentials/sd-jwt/issue` & `POST /api/v1/credentials/sd-jwt/verify`.
- Added `POST /api/v1/trust/verify-issuer`.
- Added `POST /api/v1/revocation/bloom/create` & `POST /api/v1/revocation/bloom/check`.

---

### 💻 CLI v1.4 Commands (`@docutrust/cli`)
- `docutrust shamir-split --key <file> --shares <n> --threshold <k> --out <dir>`
- `docutrust shamir-combine --shares-dir <dir> --out <file>`
- `docutrust to-sd-jwt --claims <file> --key <keyfile> --out <file>`
- `docutrust verify-sd-jwt --sd-jwt <file>`

---

### 🎨 Web Studio v1.4 (`@docutrust/web`)
- Added **Trust Mesh & Recovery Studio** (`TrustRecoveryStudio.jsx`) with interactive Shamir (K-of-N) key slicing and reconstruction, IETF SD-JWT generation, and decentralized trust registry audits.

---

## [v1.3.0] - The Fortress Release: Uncrackable Cryptographic Data Armor & ZK Predicates - 2026-08-29

### 🏰 Uncrackable Backend Data Protection & Zero-Trust Security Suite
- **Authenticated AES-256-GCM Envelope Encryption (`@docutrust/core/encryption`)**:
  - Multi-cipher authenticated symmetric encryption with 128-bit integrity authentication tags (`authTag`) preventing any tampering or chosen-ciphertext attacks.
  - Memory-hard PBKDF2-SHA512 key stretching (100,000 iterations) and high-entropy HKDF-SHA512 key derivation.
  - Secure memory zeroization (`zeroizeBuffer`) ensuring cryptographic keys and secret byte arrays are actively wiped from RAM buffers after execution (`Buffer.fill(0)`).
- **Zero-Knowledge Range & Set Membership Predicates (`@docutrust/core/zk-predicates`)**:
  - Non-Interactive Zero-Knowledge (NIZK) Range Proofs (`proveRange`, `verifyRangeProof`): Enables cryptographic proof of numerical claims (e.g. `GPA >= 3.5`, `Age >= 21`, `Salary >= $100k`) without leaking the secret value to the verifier.
  - NIZK Set Membership Proofs (`proveSetMembership`, `verifySetMembershipProof`): Allows proving a credential belongs to an authorized accredited institution set without disclosing individual identifiers.
- **Post-Quantum Key Encapsulation Mechanism (`@docutrust/core/kem`)**:
  - NIST FIPS 203 ML-KEM-768 lattice-based key encapsulation combined with X25519 ECDH in a hybrid envelope.
  - Enables quantum-resistant, confidential end-to-end credential delivery (`sealCredentialForRecipient`, `unsealCredential`) immune to future quantum decryption ("harvest now, decrypt later").
- **Holder Proof-of-Possession Challenge-Response Protocol (`@docutrust/core/possession`)**:
  - Dynamic ephemeral challenge-response nonces preventing credential replay and credential theft: verifiers validate both issuer authority authenticity and current holder possession of subject DID private keys.
- **Tamper-Evident Hash-Chain Audit Ledger (`@docutrust/core/chain`)**:
  - Forward-secure cryptographic blockchain ledger with continuous hash linkage ($H_i = \text{SHA256}(H_{i-1} \parallel \text{Root}_i \parallel \text{Timestamp})$) and digital integrity verification.

---

### 🌐 REST API v1.3 Extensions (`@docutrust/api`)
- Added `POST /api/v1/vault/encrypt` & `POST /api/v1/vault/decrypt` (Zero-knowledge envelope storage).
- Added `POST /api/v1/credentials/zk-predicate/prove` & `POST /api/v1/credentials/zk-predicate/verify`.
- Added `POST /api/v1/kem/generate-keys`, `POST /api/v1/kem/encapsulate`, and `POST /api/v1/kem/decapsulate`.
- Added `POST /api/v1/credentials/pop/challenge` & `POST /api/v1/credentials/pop/verify`.
- Added `GET /api/v1/ledger/hashchain` with real-time integrity verification.

---

### 💻 CLI v1.3 Commands (`@docutrust/cli`)
- `docutrust encrypt`: Authenticated AES-256-GCM file encryption.
- `docutrust decrypt`: Authenticated decryption with tamper protection.
- `docutrust zk-range`: Zero-Knowledge Range Proof generator.
- `docutrust kem-keygen`: Post-Quantum ML-KEM-768 hybrid keypair generation.
- `docutrust pop-challenge`: Proof-of-Possession challenge creator.

---

### 🐍 Python SDK v1.3 (`sdks/python`)
- Implemented `docutrust.encryption` (AES-256-GCM + PBKDF2), `docutrust.zk_predicates` (ZK range & commitments), `docutrust.kem` (ML-KEM-768 keypairs), and expanded `DocuTrustClient`.

---

### 🎨 Web Studio v1.3 (`@docutrust/web`)
- Added **Fortress Armor Studio** (`FortressArmorStudio.jsx`) with interactive ZK Range Proof generation, Post-Quantum ML-KEM key exchange simulations, and AES-256-GCM authenticated tamper sandboxes.

---

## [v1.2.1] - 2026-08-29

### 🛡️ Security & Cryptographic Bug Fixes
- **`@docutrust/core/vc`**: Fixed missing `crypto` module import causing `ReferenceError: crypto is not defined` when generating fallback UUIDs in `VerifiableCredentialsEngine.issue()`.
- **`@docutrust/core/selective-disclosure`**: Resolved domain separation bug in `verifySelectiveDisclosurePresentation`. Raw claim hashes are now correctly passed as `rawLeafData` to `MerkleTree.verifyProof()` to enforce RFC 6962 leaf domain separation (`0x00 || hash`).
- **`@docutrust/core/crypto`**: Added native support for `did:pqc:z...` hybrid DID identifiers in `verifySignature()`, automatically extracting the raw classical Ed25519 public key bytes for standard SPKI derivation.
- **`@docutrust/core/did`**: Extended `DIDResolver` with `resolveDidPqc()`, enabling offline deterministic resolution of Post-Quantum Hybrid ML-DSA-65 identifiers (`did:pqc:`).
- **`@docutrust/core/pqc`**: Enhanced `verifyPQCHybrid()` signature binding and validation against NIST FIPS 204 specifications.
- **`@docutrust/core/db`**: Fixed `crypto` import in `CredentialVault` for API key and UUID generation.

---

### ⚡ Feature Enhancements & API Extensions
- **`@docutrust/api`**:
  - Implemented `POST /api/v1/credentials/issue-batch`: Batch issuance of W3C Verifiable Credentials with domain-separated Merkle Tree construction and automated Polygon ledger anchor receipts.
  - Implemented `POST /api/v1/credentials/selective-disclosure`: Zero-Knowledge salted claim presentation generator revealing selected claims with individual Merkle inclusion proofs.
  - Added modular module export and conditional `server.listen()` execution for programmatic and test embedding.
- **`@docutrust/cli`**:
  - Added `docutrust batch` command supporting CSV parsing, batch cryptographic signing, Merkle tree root generation, and directory output.
  - Updated CLI command dispatch and error handling.
- **`sdks/python`**:
  - Expanded Python SDK test coverage in `test_docutrust.py` with mock verification of `DocuTrustClient` (single issuance, batch issuance, selective disclosure, and PDF verification).

---

### 🏗️ Monorepo Build System & Testing Overhaul
- **Standardized Monorepo Scripts**:
  - Configured `"build"` and `"test"` across `@docutrust/core`, `@docutrust/cli`, `@docutrust/api`, and `@docutrust/web`.
  - Added TypeScript compilation (`"build": "tsc"`) and typing definitions (`@types/node`) to `@docutrust/core`.
  - Upgraded root `npm run build` and `npm test` to run cleanly across all monorepo workspaces simultaneously.
- **Comprehensive Test Suites**:
  - `packages/core/test/core.test.js`: 12 comprehensive unit test suites validating all modules against compiled `dist/`.
  - `apps/api/test/api.test.js`: 10 integration test suites verifying all REST API endpoints on dynamic test ports.
  - `packages/cli/test/cli.test.js`: 7 automated CLI subprocess test suites verifying all command lines (`keygen`, `pqc-keygen`, `issue`, `batch`, `verify`, `demo`).
  - `sdks/python/tests/test_docutrust.py`: 11 Python test suites with 100% pass rate.
- **CI / CD Pipeline**:
  - Updated `.github/workflows/ci.yml` to automatically build all monorepo workspaces and run all test suites across Node.js (18.x, 20.x, 22.x) and Python (3.8, 3.10, 3.12).
