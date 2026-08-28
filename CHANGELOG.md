# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-08-28

### Monumental Backend Additions
- **Post-Quantum Cryptography (PQC) & Hybrid Dual-Signing Engine**:
  - Implemented NIST FIPS 204 ML-DSA (Module-Lattice Digital Signature Algorithm / Crystals-Dilithium) + Ed25519 hybrid dual keys.
  - Added `did:pqc:z...` multicodec representation for quantum-resistant sovereign identity.
- **Verifiable PDF 2.0 Engine**:
  - Direct server-side PDF generator embedding `/DocuTrustProof` metadata dictionary.
  - Endpoint `POST /api/v1/credentials/verify-pdf` extracting and verifying W3C VC proofs directly from raw PDF bytes.
- **Persistent Vault & Auto-Batch Anchoring Worker**:
  - Multi-tenant credential indexing, full-text search, and StatusList2021 revocation persistence.
  - Asynchronous background worker aggregating unanchored credentials into Merkle Trees and committing roots to Polygon/Ethereum.

### Monumental Frontend Additions
- **Visual WYSIWYG Certificate Studio & Canvas Designer**:
  - Interactive vector diploma designer with live theme presets (Academic Gold, Ivy Crimson, Cyber Emerald, Swiss Minimal).
  - Dynamic token bindings (`{{recipientName}}`, `{{degree}}`, `{{issueDate}}`) with vector SVG and PDF export.
- **Live WebRTC Camera & Document Scanner**:
  - In-browser webcam scanner with animated viewfinder reticle and real-time computer vision QR decoding.
  - Drag-and-drop Verifiable PDF analyzer extracting embedded steganographic metadata.
- **Institutional Enterprise Dashboard & Telemetry Hub**:
  - Live metric KPI telemetry (Total issued, verifications today, gas fees saved, P99 verification latency).
  - Searchable credential registry with 1-click instant `StatusList2021` revocation toggle.
  - Multi-tenant API Key Manager and Post-Quantum Security Scorecard.

## [1.0.0] - 2026-08-28
- Initial release of DocuTrust open-source sovereign trust stack with Ed25519, W3C VC 2.0, Merkle batch anchoring, and Python/CLI SDKs.
