# DocuTrust System Architecture & Cryptographic Specification

## 1. Overview
DocuTrust is a modular, high-performance open-source trust stack designed to issue, manage, and verify population-scale digital credentials. It implements the **W3C Verifiable Credentials Data Model v2.0**, **W3C Decentralized Identifiers (DID)**, and **JSON Canonicalization Scheme (RFC 8785)**.

```
+-------------------------------------------------------------------------+
|                        DOCUTRUST TRUST STACK                            |
+-------------------------------------------------------------------------+
|  [ Issuer Studio / CLI / SDKs ]       [ Verification Portal / Widget ] |
|  - CSV Batch Ingestion                - QR Code Scanner                 |
|  - Visual Certificate Renderer        - Offline Signature Verifier      |
|  - Salted Merkle Claim Blinding       - Audit Path Validation           |
+-------------------------------------------------------------------------+
|                     CRYPTOGRAPHIC ENGINE (Core)                         |
|  - Ed25519 / Secp256k1 Keypairs       - RFC 8785 JCS Normalization      |
|  - Domain-Separated Merkle Trees      - StatusList2021 Bitstrings       |
|  - ZK Salted Claim Trees              - did:key & did:web Resolvers     |
+-------------------------------------------------------------------------+
|                     LEDGER ANCHOR ADAPTERS                              |
|  - Polygon / Ethereum L2 Anchors      - Local Cryptographic Audit Log   |
+-------------------------------------------------------------------------+
```

---

## 2. Cryptographic Invariants & Protocols

### 2.1 Canonicalization & Asymmetric Signing
To prevent signature mismatch bugs caused by JSON whitespace, key order, or numeric format variations, all payloads are processed through RFC 8785 JCS:
$$\text{CanonicalHash} = \text{SHA-256}(\text{JCS}(\text{UnsignedCredential}))$$
$$\sigma = \text{Ed25519-Sign}(\text{PrivateKey}_{\text{Issuer}}, \text{CanonicalHash})$$

### 2.2 Domain-Separated Merkle Trees (RFC 6962)
When batch issuing credentials (e.g. university graduation batches), leaf nodes and interior nodes are domain-separated to eliminate second-preimage vulnerabilities:
$$\text{LeafHash}_i = \text{SHA-256}(0\text{x}00 \parallel \text{CanonicalHash}_i)$$
$$\text{NodeHash} = \text{SHA-256}(0\text{x}01 \parallel \text{LeftChild} \parallel \text{RightChild})$$

### 2.3 Zero-Knowledge Salted Claim Privacy
To enable selective disclosure without exposing private attributes:
$$\text{BlindedClaim}_i = \text{SHA-256}(\text{Salt}_i \parallel \text{"::"} \parallel \text{Key}_i \parallel \text{"::"} \parallel \text{JCS}(\text{Value}_i))$$
$$\text{ClaimsRoot} = \text{MerkleTree}(\{\text{BlindedClaim}_1, \dots, \text{BlindedClaim}_n\}).\text{Root}$$

When generating a Verifiable Presentation:
1. Disclosed claims provide: $(\text{Key}_i, \text{Value}_i, \text{Salt}_i, \text{MerkleProof}_i)$.
2. Hidden claims are omitted, only their sibling hashes in the audit path are revealed.
3. The verifier reconstructs $\text{ClaimsRoot}$ and verifies the Issuer's signature over it.

### 2.4 High-Performance Revocation (StatusList2021)
Credentials specify a `statusListIndex`. The authority publishes an encoded bitstring where bit $i = 0$ indicates valid and bit $i = 1$ indicates revoked:
$$\text{RevocationHeader} = \text{Base64Url}(\text{GZIP}(\text{Bitstring}))$$
Up to 1,000,000 credentials are represented in under 30KB of compressed bandwidth.

---

## 3. Directory Layout

```
docutrust/
├── packages/
│   ├── core/            # Cryptographic & W3C VC engine (Ed25519, Merkle, DIDs, ZK SD)
│   └── cli/             # Command-line tool ('docutrust keygen', 'issue', 'verify')
├── apps/
│   ├── api/             # High-performance Node.js REST API
│   └── web/             # Modern React/Tailwind Web Studio & Verification Explorer
├── sdks/
│   ├── python/          # Pip installable Python SDK ('docutrust')
│   └── typescript/      # TypeScript / JavaScript client
├── examples/            # Sample credentials, batch CSVs, and integration scripts
├── .github/workflows/   # CI/CD test automation
├── Dockerfile           # Production container build
└── docker-compose.yml   # Multi-service orchestration
```
