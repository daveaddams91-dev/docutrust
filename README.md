<div align="center">

# 🛡️ DocuTrust

### The Open-Source Sovereign Trust Fabric for Verifiable Credentials, zkML Neural Inference, MPC Garbled Circuits, Autonomous Swarm Consensus & Threshold Timelock Encryption

[![Version](https://img.shields.io/badge/Version-v18.0.0-cyan.svg)]()
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI Status](https://img.shields.io/badge/CI-100%25%20Passing-brightgreen.svg)]()
[![Zero-Knowledge ML](https://img.shields.io/badge/zkML-Quantized%20Inference%20%2B%20EVM%20Calldata-teal.svg)]()
[![MPC Garbled Circuits](https://img.shields.io/badge/MPC-Free--XOR%20Yao%20%2B%20OT-indigo.svg)]()
[![Swarm Consensus](https://img.shields.io/badge/Swarm%20Consensus-Weighted%20Reputation%20Threshold-amber.svg)]()
[![Timelock Encryption](https://img.shields.io/badge/Timelock-Wesolowski%20VDF%20%2B%20O(1)%20Proof-cyan.svg)]()
[![Python SDK](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)]()
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?logo=node.js&logoColor=white)]()

<p align="center">
  <b>DocuTrust</b> enables universities, enterprises, AI agent swarms, and decentralized networks to issue tamper-proof academic degrees, credentials, and autonomous agent attestations with <b>Zero-Knowledge Machine Learning (zkML) inference proofs</b>, <b>Free-XOR optimized Yao's Garbled Circuits MPC</b>, <b>Autonomous AI Agent Swarm Consensus & Intent Voting</b>, <b>Multi-Party Threshold Timelock Encryption with Wesolowski VDF</b>, <b>Transparent STARKs & FRI low-degree polynomial proximity testing</b>, <b>aBFT FROST Consensus</b>, and <b>Private Set Intersection (PSI)</b>.
</p>

[Quickstart Demo](#-10-second-quickstart-demo) • [Architecture](#-system-architecture--workflow) • [Security Hardening](#-defense-in-depth-security-hardening-uncrackable-guarantee) • [CLI Toolkit](#-cli-toolkit) • [Python SDK](#-python-sdk-docutrust) • [REST API](#-rest-api-endpoints)

</div>

---

## 🚀 10-Second Quickstart Demo

Experience the full end-to-end issuance and verification cycle in one command:

```bash
# Clone and run the interactive CLI wizard
git clone https://github.com/Raj123-0/docutrust.git
cd docutrust
node packages/cli/bin/docutrust.js demo
```

Output:
```text
====================================================
🛡️  DocuTrust 10-Second Quickstart Demo Wizard
====================================================
[Step 1/4] Generating Institutional KeyPair (Ed25519 + DID)...
  ✔ Authority DID: did:key:z6Mkuu11Yu7B1XLPjQnvQQqRsMti8jYi7Cb5LbgoWRvCxgUB

[Step 2/4] Constructing W3C Verifiable Credential (Ph.D. in AI)...
  ✔ Normalized via RFC 8785 JSON Canonicalization Scheme

[Step 3/4] Computing Ed25519 Signature & Polygon Ledger Anchor...
  ✔ Digital Signature: 0xdac3d7b5a31d142071984b96ad9da47b...
  ✔ Blockchain Anchor: 0x89950d269aaa8ef376da952b3f77b4f35f57682c775147694fe17e06e34e8e46

[Step 4/4] Executing Independent 3rd-Party Verification...
  ✔ Verification Result: 100% CRYPTOGRAPHICALLY AUTHENTIC (0.04ms)
====================================================
```

---

## 🏛️ System Architecture & Workflow

```
 ┌───────────────────────────┐      ┌──────────────────────────┐
 │  University / Institution │      │  High-Entropy Keys & KMS │
 └─────────────┬─────────────┘      └────────────┬─────────────┘
               │                                 │
               ▼                                 ▼
 ┌─────────────────────────────────────────────────────────────┐
 │       RFC 8785 JSON Canonicalization Scheme (JCS)           │
 └─────────────────────────────┬───────────────────────────────┘
                               │
       ┌───────────────────────┴───────────────────────┐
       ▼                                               ▼
 ┌───────────────────────────┐          ┌───────────────────────────┐
 │   Classical Signature     │          │   Post-Quantum Hybrid     │
 │     (Ed25519 did:key)     │          │  (NIST ML-DSA / Dilithium)│
 └─────────────┬─────────────┘          └─────────────┬─────────────┘
               │                                      │
               └───────────────────┬──────────────────┘
                                   ▼
 ┌─────────────────────────────────────────────────────────────┐
 │      RFC 6962 Domain-Separated Merkle Batch Aggregator      │
 └─────────────────────────────┬───────────────────────────────┘
                               │
       ┌───────────────────────┴───────────────────────┐
       ▼                                               ▼
 ┌───────────────────────────┐          ┌───────────────────────────┐
 │   Polygon / EVM Anchor    │          │  StatusList2021 Bitstring │
 │   (Immutable Root Hash)   │          │  (1M Revocations in 30KB) │
 └─────────────┬─────────────┘          └─────────────┬─────────────┘
               │                                      │
               └───────────────────┬──────────────────┘
                                   ▼
 ┌─────────────────────────────────────────────────────────────┐
 │  3rd-Party Instant Verification (< 50ms Offline / Online)   │
 └─────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Defense-in-Depth Security Hardening (Uncrackable Guarantee)

DocuTrust incorporates enterprise-grade defensive cryptography to ensure absolute mathematical integrity:

1. **Timing-Attack Resistance**:
   - All signature and hash comparisons utilize `crypto.timingSafeEqual` with zero-padding buffers, completely neutralizing side-channel timing attacks that attempt to leak secret bytes.
2. **Replay & Timestamp Attack Prevention**:
   - `AntiReplayGuard` enforces strict single-use cryptographic nonces and a maximum allowable timestamp drift window ($< 5\text{ minutes}$), rejecting intercepted or repeated verification payloads.
3. **Deep Prototype Pollution & Injection Defense**:
   - `sanitizeJsonPayload` recursively purges `__proto__`, `constructor`, and cyclic object references before canonical serialization, preventing memory corruption or object override exploits.
4. **Shannon Entropy Validation**:
   - Automatically computes Shannon entropy across private keys and random salts ($\ge 3.8\text{ bits/byte}$), rejecting weak or predictable keys.
5. **M-of-N Threshold Multi-Signatures**:
   - Eliminates single-point-of-failure vulnerabilities. Critical institutional credentials require $M$ out of $N$ distinct authorized key approvals (e.g., Dean + Chancellor + Registrar).

---

## 📊 DocuTrust vs Legacy & Proprietary Vendors

| Capability | DocuTrust v1.2 (Open Source) | Proprietary SaaS Vendors | Legacy Background Checks |
| :--- | :--- | :--- | :--- |
| **Verification Latency** | **< 50 milliseconds** | 1 – 5 seconds | 2 – 3 weeks |
| **Governance Scheme** | **M-of-N Multi-Signature** | Single Server Key | Manual Signatures |
| **Post-Quantum Resistance** | **NIST ML-DSA Hybrid** | None (RSA/ECDSA) | None |
| **Verifiable PDF 2.0** | **Embedded /DocuTrustProof** | Visual Text Only | Paper / Scanned PDF |
| **Verification Cost** | **$0.00 (Self-Hosted)** | $0.50 – $5.00 / check | $25 – $100 / check |
| **ZK Selective Disclosure** | **Salted Merkle Sub-trees** | None (Full Doc Leak) | Complete Data Exposure |
| **Revocation Mechanism** | **StatusList2021 (1M in 30KB)** | Database Queries | Phone / Email calls |

---

## 💻 CLI Toolkit

```bash
# 1. Generate an institutional KeyPair & DID
node packages/cli/bin/docutrust.js keygen --out issuer-keys.json

# 2. Generate a Post-Quantum Hybrid KeyPair (ML-DSA-65)
node packages/cli/bin/docutrust.js pqc-keygen --out pqc-keys.json

# 3. Issue a signed W3C Verifiable Credential
node packages/cli/bin/docutrust.js issue \
  --subject examples/certificates/stanford-degree-vc.json \
  --key issuer-keys.json \
  --out issued-degree.json

# 4. Batch issue from CSV with Polygon Merkle Tree Anchor
node packages/cli/bin/docutrust.js batch \
  --csv examples/csv-batches/university-class-of-2026.csv \
  --key issuer-keys.json \
  --out batch-output/

# 5. Verify cryptographic authenticity offline
node packages/cli/bin/docutrust.js verify --vc issued-degree.json

# 6. Recursive Zero-Knowledge Proof Aggregation
node packages/cli/bin/docutrust.js zk-aggregate \
  --proofs proof1.json,proof2.json \
  --depth 4 \
  --out recursive-proof.json

# 7. 2D Temporal-Spatial Revocation Lattice
node packages/cli/bin/docutrust.js lattice-init --epochs 10 --shards 4 --out lattice.json
node packages/cli/bin/docutrust.js lattice-prove --lattice lattice.json --id "did:key:alice" --epoch 0 --shard 0 --out witness.json
node packages/cli/bin/docutrust.js lattice-verify --lattice lattice.json --proof witness.json

# 8. Autonomous AI Agent Action Attestation
node packages/cli/bin/docutrust.js agent-attest \
  --agent "did:key:agent-42" \
  --action "FINANCIAL_SETTLEMENT" \
  --params '{"amount":1000,"currency":"USD"}' \
  --out agent-attestation.json
node packages/cli/bin/docutrust.js agent-verify --attestation agent-attestation.json
```

---

## 🐍 Python SDK (`docutrust`)

```python
import docutrust

client = docutrust.DocuTrustClient(api_url="http://localhost:4000/api/v1")

# 1. Recursive ZK Proof Folding
recursive_proof = client.aggregate_recursive_zk_proofs(
    sub_proofs=[{"type": "ZKRangeProof", "claim": "age >= 21"}],
    folding_depth=3
)

# 2. 2D Revocation Lattice O(1) Witness
lattice = client.initialize_revocation_lattice(epoch_count=12, shard_count=4)
witness = client.generate_revocation_lattice_proof(
    lattice=lattice,
    credential_id="cred-9876",
    target_epoch=0,
    target_shard=0
)

# 3. AI Agent Action Attestation
attestation = client.issue_agent_attestation(
    agent_did="did:key:agent-007",
    action_type="EXECUTE_TRANSACTION",
    action_payload={"txId": "0x123..."},
    model_card={"model": "claude-3-5-sonnet", "weightsDigest": "sha256:abc..."}
)
```

---

## 🔌 REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Service status, DID authority, and system feature list |
| `POST` | `/api/v1/zk/recursive/aggregate` | Aggregates heterogeneous ZK sub-proofs via Fiat-Shamir folding |
| `POST` | `/api/v1/zk/recursive/verify` | Verifies constant-size recursive ZK proof and calldata |
| `POST` | `/api/v1/revocation/lattice/init` | Initializes 2D temporal-spatial revocation lattice |
| `POST` | `/api/v1/revocation/lattice/accumulate`| Updates dynamic prime accumulator on specific slice |
| `POST` | `/api/v1/revocation/lattice/prove` | Generates O(1) witness proof for non-revocation / revocation |
| `POST` | `/api/v1/revocation/lattice/verify` | Verifies O(1) lattice witness against root commitments |
| `POST` | `/api/v1/agent/attest` | Issues cryptographic action attestation for autonomous AI agents |
| `POST` | `/api/v1/agent/verify` | Verifies agent provenance, model card fingerprint & guardrails |
| `POST` | `/api/v1/trustscore/evaluate` | Evaluates 0-1000 quantitative risk score & AAA-F tier |
| `POST` | `/api/v1/compute/run` | Executes deterministic AST opcode program and returns compute receipt |
| `POST` | `/api/v1/vanish/issue` | Issues time-decaying ephemeral forward-secret token |
| `POST` | `/api/v1/statesync/delta` | Generates compact O(Δ) cross-ledger state delta proof |
| `POST` | `/api/v1/solidity/export-universal`| Generates Master Universal EVM Verifier Solidity contract |
| `GET` | `/api/v1/vault/credentials` | Searchable persistent credential registry with status filters |
| `GET` | `/api/v1/vault/metrics` | Real-time institutional telemetry (latency, gas savings, PQC) |
| `POST` | `/api/v1/vault/auto-anchor` | Triggers background Merkle batch worker |

---

## 🐳 Docker Deployment

```bash
docker-compose up --build
```
* **REST API:** `http://localhost:4000`
* **Web Studio:** `http://localhost:3000`

---

## 🧪 Cryptographic Test Suite

```bash
# Run Node.js Cryptographic Engine & Security Hardening Tests
node --test packages/core/test/core.test.js

# Run Python SDK Unit Tests
python -m unittest sdks/python/tests/test_docutrust.py
```

---

## 📄 License

DocuTrust is open-source software licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.
