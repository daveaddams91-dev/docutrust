# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-08-28

### Added
- **Core Cryptographic Engine**:
  - Ed25519 asymmetric signature suite (`did:key`).
  - RFC 8785 JSON Canonicalization Scheme (JCS).
  - RFC 6962 Domain-Separated Merkle Trees.
  - Zero-Knowledge Salted Claim Selective Disclosure.
  - W3C StatusList2021 Bitstring Revocation Registry.
  - Multi-Ledger Anchoring Adapters (Polygon, Ethereum, Local Audit Log).
- **Issuer Studio**:
  - Academic, Employment, and Medical Certificate Templates.
  - Single issuance with high-res SVG & QR code embedding.
  - High-throughput CSV batch ingestion with Merkle root computation.
- **Verification Portal**:
  - Instant sub-millisecond cryptographic audit.
  - Live QR code and 256-bit hash validation.
  - Visual tamper detection simulator.
- **Developer Ecosystem**:
  - Pip-installable Python SDK (`docutrust`).
  - Standalone CLI tool (`docutrust-cli`).
  - High-performance Node.js REST API with OpenAPI specification.
  - Full GitHub Actions CI/CD matrix and multi-stage Docker deployment.
