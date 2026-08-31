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

### 2.8 1-of-N Linkable Ring Signatures (LSAG) & Key Images
Enables anonymous collective attestations and sovereign whistleblower disclosures across an $N$-member public key ring $\{P_0, P_1, \dots, P_{n-1}\}$ with signer index $\pi \in [0, n-1]$:
1. Deterministic Key Image computation:
$$I = \text{SHA-256}(\text{KEY\_IMAGE} \parallel \text{PrivateKey}_\pi \parallel P_\pi)$$
2. Schnorr ring verification loop:
$$c_{i+1} = \text{SHA-256}(\text{LSAG\_STEP} \parallel m \parallel L_i \parallel R_i) \pmod q$$
$$L_i = s_i \cdot G + c_i \cdot P_i, \quad R_i = s_i \cdot H(P_i) + c_i \cdot I$$
3. Ring closure verification:
$$c_0 \stackrel{?}{=} \text{SHA-256}(\text{LSAG\_STEP} \parallel m \parallel L_{n-1} \parallel R_{n-1}) \pmod q$$
Enforces single-action uniqueness in public ledgers without revealing $\pi$.

### 2.9 256-Bit Sparse Merkle Trees (SMT) for Key Transparency
Provides continuous, logarithmic $O(256)$ cryptographic inclusion and non-membership proofs over $2^{256}$ addressable state keys:
1. Interior node hashing:
$$\text{ParentHash} = \text{SHA-256}(\text{LeftChild} \parallel \text{RightChild})$$
2. Leaf node hashing:
$$\text{LeafHash} = \text{SHA-256}(\text{"SMT\_LEAF:"} \parallel \text{Key}_{256} \parallel \text{Value})$$
3. Verification path: Given leaf key bits $b_0 b_1 \dots b_{255}$ and sibling hashes $S_0 \dots S_{255}$, iteratively reconstruct the root:
$$H_{d} = \begin{cases} \text{SHA-256}(H_{d-1} \parallel S_{d-1}) & \text{if } b_{256-d} = 0 \\ \text{SHA-256}(S_{d-1} \parallel H_{d-1}) & \text{if } b_{256-d} = 1 \end{cases}$$
Verified on-chain via `DocuTrustSMTVerifier.sol`.

### 2.10 NIST FIPS 205 Stateless Hash-Based Signatures (SLH-DSA)
Post-quantum digital signatures based on WOTS+ and hypertree hash chains:
1. Public Key: $\text{PK} = (\text{PK.seed} \parallel \text{PK.root})$
2. Multicodec Prefix: `0x19, 0x05` $\implies \text{did:slh:z...}$
3. Stateless Signature Size: 1,120 bytes (Category 1 SLH-DSA-SHA2-128s).

### 2.11 WebAuthn / FIDO2 Hardware Passkey Attestations
Hardware enclave assertions over P-256 (secp256r1 / ES256):
1. Assertion digest: $M = \text{authenticatorData} \parallel \text{SHA-256}(\text{clientDataJSON})$
2. Hardware flags: Bit 0 = User Presence (UP `0x01`), Bit 2 = User Verification (UV `0x04`).
3. Multicodec Prefix: `0x12, 0x01` $\implies \text{did:webauthn:z...}$.

### 2.12 Multi-Chain Verifiable Attestation Bridge
Relayer routing across EVM chains with strict monotonic sequence nonces:
1. Message digest: $\text{MsgID} = \text{SHA-256}(\text{srcChain} \parallel \text{dstChain} \parallel \text{nonce} \parallel \text{stateRoot} \parallel \text{payloadHash})$
2. Quorum verification: Requires $T$-of-$N$ valid relayer signatures over EIP-191 personal sign format.
3. On-chain validation: Verified via `DocuTrustBridgeRelayer.sol`.

### 2.13 BN254 Groth16 Zero-Knowledge SNARK Engine
Constant-size zero-knowledge proof verification over elliptic curve BN254 (alt_bn128):
1. Proof points: $A \in G_1, B \in G_2, C \in G_1$
2. Pairing verification equation:
$$e(A, B) = e(\alpha, \beta) \cdot e\left(\sum_{i=0}^l x_i \cdot \text{IC}_i, \gamma\right) \cdot e(C, \delta)$$
3. EVM precompile verification via `DocuTrustGroth16Verifier.sol` at address `0x08`.

### 2.14 Recursive Zero-Knowledge Proof Aggregation & Fiat-Shamir Folding
Compresses $K$ heterogeneous ZK sub-proof statements into a single constant-size recursive proof:
1. Sub-proof commitments: $\vec{C} = [C_1, \dots, C_K]$
2. Fiat-Shamir non-interactive challenge derivation:
$$\alpha = \text{SHA-256}(\text{"DOCUTRUST_FS_FOLD_V13:"} \parallel \text{RootHash}(\vec{C})) \pmod q$$
3. Folded accumulator evaluation:
$$A_{\text{fold}} = \sum_{k=1}^K \alpha^k \cdot \text{Eval}(P_k)$$
4. Produces `DocuTrustRecursiveZKProof2026` with EVM on-chain calldata hex.

### 2.15 2D Temporal-Spatial Multi-Epoch Revocation Lattice
Matrix lattice spanning temporal epochs $e \in [0, E-1]$ and spatial shards $s \in [0, S-1]$:
1. Slice Prime Accumulator:
$$V_{(e, s)} = g^{\prod_{id \in \text{Slice}(e, s)} \text{Prime}(id)} \pmod N$$
2. $O(1)$ Constant-Size Witness generation:
$$W_{x} = g^{\prod_{id \in \text{Slice}(e, s) \setminus \{x\}} \text{Prime}(id)} \pmod N$$
3. Matrix Root: 2D Merkle commitment over all slice accumulators $V_{(e, s)}$ enabling time-travel audits without full history re-indexing.

### 2.16 Autonomous AI Agent Action Attestation & Guardrails
Cryptographic binding of autonomous AI agent actions to model card fingerprints:
1. Model Card Fingerprint:
$$F_{\text{model}} = \text{SHA-256}(\text{modelFamily} \parallel \text{weightsDigest} \parallel \text{temp} \parallel \text{version})$$
2. Merkle Hash-Chained Execution Trace:
$$H_t = \text{SHA-256}(H_{t-1} \parallel \text{Step}_t \parallel \text{ToolCall}_t \parallel \text{ResultHash}_t)$$
3. Attestation Signature: Ed25519 signature over $(F_{\text{model}} \parallel H_{\text{trace}} \parallel \text{PayloadHash})$ validated against deterministic safety guardrail policies.

### 2.17 Deterministic VRF & Multi-Oracle Consensus Mesh
1. Verifiable Random Function (VRF) evaluation:
$$\text{Output}_{\text{vrf}} \parallel \text{Proof}_{\text{vrf}} = \text{HMAC-SHA512}(\text{PrivateKey}, \text{"VRF\_EVAL:"} \parallel \text{Seed})$$
2. Multi-Oracle Threshold Beacon Randomness:
$$\text{Entropy}_{\text{beacon}} = \text{SHA-256}\left(\text{"BEACON\_RANDOMNESS:"} \parallel \text{epoch} \parallel \text{round} \parallel \text{Sorted}(\text{Outputs}_{1 \dots K})\right)$$
3. Threshold consensus verification ensuring $K \ge \text{Threshold}$ valid cryptographic evaluations.

### 2.18 Zero-Knowledge Multi-Attribute Predicate DSL Compiler
1. Declarative policy expressions compiled to ASTs and arithmetic constraint systems:
$$\mathcal{P} := \text{Atomic}(a_i, \text{op}, v_i) \mid \mathcal{P}_1 \land \mathcal{P}_2 \mid \mathcal{P}_1 \lor \mathcal{P}_2$$
2. Non-interactive ZK proof synthesis hiding private attributes:
$$\text{Commitment} = \text{SHA-256}(\text{JCS}(\text{Attributes}) \parallel \text{Salt})$$
$$\text{Proof}_{\text{ZK}} = \text{ZK-Synthesize}(\mathcal{P}, \text{Attributes}, \text{Salt})$$

### 2.19 AI Bill of Materials (AI-BOM) Neural Network Weights Merkle Trees
1. Per-layer tensor cryptographic digests:
$$L_i = \text{SHA-256}(\text{"AI\_LAYER:"} \parallel \text{JCS}(\{\text{index}_i, \text{name}_i, \text{shape}_i, \text{digest}_i\}))$$
2. Hierarchical weights Merkle tree root $R_{\text{weights}} = \text{MerkleTree}(\{L_1, \dots, L_N\}).\text{Root}$.
3. $O(\log N)$ single-layer Merkle inclusion proof verification for granular model auditing.

### 2.20 Post-Quantum Falcon-512/1024 Lattice Signatures
1. High-speed lattice signatures based on the Short Integer Solution (SIS) problem over NTRU lattices.
2. Compact signature and public key footprint with sub-millisecond on-chain / off-chain verification.
3. Native W3C `did:falcon` DID method resolution.

### 2.21 Post-Quantum Double Ratchet (ML-KEM-768 + X25519)
1. Asynchronous continuous forward secrecy and post-compromise security:
$$\text{DH}_{\text{hybrid}} = \text{X25519}(\text{Priv}_{\text{eph}}, \text{Pub}_{\text{their}}) \parallel \text{ML-KEM-Decaps}(\text{Priv}_{\text{kem}}, \text{Ciphertext}_{\text{kem}})$$
2. Symmetric root chain, sending chain, and receiving chain key derivation:
$$(\text{RootKey}_{i+1}, \text{ChainKey}_{i+1}) = \text{HKDF-SHA256}(\text{RootKey}_i, \text{DH}_{\text{hybrid}}, \text{"DT-PQR-RATCHET"})$$
3. Per-message key derivation: $\text{MessageKey} = \text{HMAC-SHA256}(\text{ChainKey}, \text{"DT-MSG-KEY"})$ with AES-256-GCM AEAD encryption.

### 2.22 Polynomial Commitments & KZG Evaluation on BN254
1. KZG Structured Reference String (SRS) in pairing groups $\mathbb{G}_1, \mathbb{G}_2$:
$$\text{SRS} = \left(\{ [s^i]_1 \}_{i=0}^{d}, \{ [s^j]_2 \}_{j=0}^{1} \right)$$
2. Commitment to polynomial $P(x) = \sum_{i=0}^d c_i x^i$: $C = [P(s)]_1 = \sum_{i=0}^d c_i [s^i]_1$.
3. Evaluation proof at point $z$: Quotient $Q(x) = \frac{P(x) - P(z)}{x - z}$, Proof $\pi = [Q(s)]_1$.
4. Bilinear pairing verification check: $e(C - [P(z)]_1, [1]_2) \stackrel{?}{=} e(\pi, [s - z]_2)$.

### 2.23 Hardware TEE Remote Attestation & Confidential Computing
1. Cryptographic validation of Intel SGX DCAP, AMD SEV-SNP, and AWS Nitro Enclave hardware quotes.
2. Verification of code measurement digests ($\text{MRENCLAVE}$), author authorities ($\text{MRSIGNER}$), and SVN levels.
3. Issuance of hardware-bound Verifiable Credentials:
$$\text{VC}_{\text{TEE}} = \text{Sign}_{\text{Issuer}}\left(\text{JCS}(\{\text{credentialSubject}, \text{enclaveKey}, \text{MRENCLAVE}, \text{ReportData}\})\right)$$

### 2.24 Cosmos IBC ICS-04 / ICS-23 Cross-Chain Interoperability & Relayer
1. ICS-04 Packet commitment hash over channel metadata, sequence, and payload:
$$\text{Commitment} = \text{SHA-256}(\text{timeoutTimestamp} \parallel \text{timeoutHeight} \parallel \text{SHA-256}(\text{data}))$$
2. ICS-23 Merkle multi-store state proof verification against Tendermint consensus `AppHash`.
3. Trust period verification and automated cross-chain packet relay execution.

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
