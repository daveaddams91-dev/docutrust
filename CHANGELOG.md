# 📝 DocuTrust Changelog & Release Notes

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
