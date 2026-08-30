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

### 2.4 High-Performance Revocation & Status (StatusList2021 & W3C Bitstring Status List 2024)
Credentials specify status entries pointing to compressed bitstrings. In W3C Bitstring Status List 2024:
$$\text{EncodedList} = \text{"u"} \parallel \text{Base64Url}(\text{GZIP}(\text{Bitstring}))$$
Supporting 1-bit (valid/revoked), 2-bit (valid/revoked/suspended/review), 4-bit, and 8-bit multi-state tracking for 100,000+ credentials in under 2KB of compressed space.

### 2.5 DIF Presentation Exchange 2.0 Engine
Automates verifiable presentation querying through JSONPath filters, schema matching, constraint validation, and deterministic SHA-256 audit digest generation:
$$\text{AuditHash} = \text{SHA-256}(\text{JCS}(\{\text{definitionId}, \text{matchedDescriptors}, \text{submission}\}))$$

### 2.6 Dynamic RSA Accumulators & Bezout Non-Membership Proofs
Accumulates member primes $p_i$ into an RSA modulus $N$:
$$V = g^{\prod_{i=1}^n p_i} \pmod N$$
Non-membership of an element $x \notin S$ is proven in $O(1)$ constant size using Bezout coefficients $(a, b)$ from the Extended Euclidean Algorithm:
$$a \cdot x + b \cdot \prod_{i=1}^n p_i = \gcd\left(x, \prod p_i\right) = 1 \implies d = g^a \pmod N$$
$$\text{Verification: } (d^x \cdot V^b) \equiv g \pmod N$$

### 2.7 Recursive Zero-Knowledge Predicate Graphs
Hierarchical boolean DAGs (AND, OR, NOT, THRESHOLD) evaluated recursively over heterogeneous ZK atomic proofs (Range, Age, Date, Membership, Non-Membership, Set Intersection, Composite):
$$\text{GraphRootHash} = \text{SHA-256}(\text{JCS}(\text{RootNode}))$$

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
