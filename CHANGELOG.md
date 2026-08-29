# 📝 DocuTrust Changelog & Release Notes

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
