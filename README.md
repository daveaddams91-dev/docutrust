<div align="center">

# 🛡️ DocuTrust

### The Open-Source Sovereign Trust Stack for Verifiable Digital Credentials & Cryptographic Ledger Anchoring

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI Status](https://img.shields.io/badge/CI-Passing-brightgreen.svg)]()
[![W3C VC 2.0](https://img.shields.io/badge/Standard-W3C%20VC%202.0-purple.svg)](https://www.w3.org/TR/vc-data-model-2.0/)
[![DIDs](https://img.shields.io/badge/Identity-did%3Akey%20%7C%20did%3Aweb-orange.svg)]()
[![Python SDK](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)]()
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?logo=node.js&logoColor=white)]()
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)]()

<p align="center">
  <b>DocuTrust</b> enables universities, enterprises, and institutions to issue tamper-proof degrees, diplomas, employment proofs, and licenses with sub-50ms instant verification, batch Merkle ledger anchors, and Zero-Knowledge selective disclosure.
</p>

[Explore Web Studio](https://github.com/Raj123-0/docutrust) • [Architecture Docs](ARCHITECTURE.md) • [Python SDK](#-python-sdk) • [CLI Toolkit](#-cli-tool) • [REST API Reference](#-rest-api-reference)

</div>

---

## 🚀 Key Features

| Capability | Description | Standard / Implementation |
| :--- | :--- | :--- |
| **W3C Verifiable Credentials** | Universal interoperability across digital wallets and registries. | W3C VC Data Model v2.0 |
| **Decentralized Identifiers** | Sovereign identity without centralized Certificate Authorities. | `did:key` (Ed25519) & `did:web` |
| **Deterministic Canonicalization** | Immune to JSON key-order and whitespace variations. | RFC 8785 (JCS) |
| **Batch Merkle Anchoring** | Batch 10,000+ certificates into a single 32-byte on-chain anchor. | RFC 6962 Domain-Separated Binary Tree |
| **ZK Selective Disclosure** | Prove degree validity while concealing sensitive student GPA/SSN. | Salted Claim Merkle Sub-trees |
| **Instant Revocation** | Sub-millisecond revocation checking with compressed bitstrings. | StatusList2021 |
| **Zero Vendor Lock-In** | 100% Open Source and self-hostable with Docker or Kubernetes. | Apache-2.0 License |

---

## 📊 DocuTrust vs Legacy & Proprietary Vendors

| Feature | DocuTrust (Open Source) | Proprietary SaaS Vendors | Legacy Background Checks |
| :--- | :--- | :--- | :--- |
| **Verification Latency** | **< 50 milliseconds** | 1 – 5 seconds | 2 – 3 weeks |
| **Cost per Verification** | **$0.00 (Self-Hosted)** | $0.50 – $5.00 / check | $25 – $100 / check |
| **Vendor Lock-In** | **Zero (Apache 2.0)** | High (Proprietary platform) | N/A |
| **Privacy / ZK Proofs** | **Built-in Salted Merkle** | None (Exposes full doc) | Complete Data Exposure |
| **Ledger Interoperability** | **Polygon / Ethereum / Local** | Single Closed Database | Physical Paper / PDF |

---

## ⚡ Quickstart

### 1. Run with Docker Compose (1-Line Startup)
```bash
git clone https://github.com/Raj123-0/docutrust.git
cd docutrust
docker-compose up --build
```
* **REST API:** `http://localhost:4000`
* **Web Studio:** `http://localhost:3000`

---

## 💻 CLI Tool

Install and use the standalone `docutrust` CLI:

```bash
# 1. Generate an Institutional KeyPair & did:key
node packages/cli/bin/docutrust.js keygen --out issuer-keys.json

# 2. Issue a cryptographically signed Verifiable Credential
node packages/cli/bin/docutrust.js issue \
  --subject examples/certificates/stanford-degree-vc.json \
  --key issuer-keys.json \
  --out issued-degree.json

# 3. Independently verify any credential offline
node packages/cli/bin/docutrust.js verify --vc issued-degree.json
```

---

## 🐍 Python SDK

Install via pip:
```bash
pip install docutrust
```

```python
import docutrust

# 1. Initialize Client
client = docutrust.DocuTrustClient(api_url="http://localhost:4000/api/v1")

# 2. Issue a Verifiable Credential
credential = client.issue_credential(
    credential_subject={
        "name": "Elena Rostova",
        "degree": "Ph.D. in Artificial Intelligence",
        "graduationYear": 2026,
        "gpa": "3.98"
    },
    credential_type="UniversityDegreeCredential",
    enable_selective_disclosure=True
)

# 3. Verify Authenticity in < 50ms
audit = client.verify_credential(credential["credential"])
print("Signature Valid:", audit["signatureValid"])
print("Ledger Anchor Confirmed:", audit["anchorValid"])
```

---

## 🌐 REST API Reference

### Issue Single Credential
`POST /api/v1/credentials/issue`
```json
{
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuerName": "Stanford University",
  "credentialSubject": {
    "name": "Alex Rivera",
    "degree": "Master of Science in Computer Science",
    "graduationYear": 2026
  }
}
```

### Batch Issue with Merkle Anchor
`POST /api/v1/credentials/issue-batch`
```json
{
  "records": [
    { "name": "Marcus Vance", "degree": "M.Sc. Data Science", "gpa": "3.92" },
    { "name": "Sarah Jenkins", "degree": "B.Sc. Computer Engineering", "gpa": "3.88" }
  ],
  "anchorToLedger": true
}
```

### Instant Verification
`POST /api/v1/credentials/verify`
```json
{
  "credential": { ... }
}
```

---

## 🧪 Testing & Verification

Run the automated test suites:

```bash
# Run Node.js Cryptographic Engine Tests
node --test packages/core/test/core.test.js

# Run Python SDK Unit Tests
python -m unittest sdks/python/tests/test_docutrust.py
```

---

## 📄 License

DocuTrust is open-source software licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.
