# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2026-08-28

### Usability & User Experience
- **Interactive 10-Second Quickstart Wizard (`docutrust demo`)**:
  - Direct 1-command end-to-end issuance, signing, ledger anchoring, and verification walkthrough.
- **Threshold Multi-Signature Studio (`MultiSigStudio.jsx`)**:
  - Interactive UI for M-of-N institutional governance (Dean + Chancellor + Registrar).
- **Streamlined Web Navigation**:
  - Added Multi-Sig tab and simplified quick-fill workflows.

### Security Hardening ("Uncrackable" Defense-in-Depth)
- **Constant-Time Verification**:
  - Added `crypto.timingSafeEqual` comparison with length zero-padding to completely eliminate side-channel timing attacks on signatures and hashes.
- **Anti-Replay & Timestamp Drift Guard (`AntiReplayGuard`)**:
  - Cryptographic single-use nonce tracking and maximum 5-minute timestamp drift window.
- **Deep Prototype Pollution & Injection Defense (`sanitizeJsonPayload`)**:
  - Recursive sanitation purging `__proto__`, `constructor`, and circular references prior to canonical serialization.
- **Shannon Entropy Enforcer**:
  - Automated entropy validation ($\ge 3.8\text{ bits/byte}$) for keys and salts, blocking weak or predictable randomness.
- **M-of-N Multi-Signature Threshold Engine (`packages/core/src/multisig`)**:
  - Institutional threshold scheme requiring $M$ out of $N$ authorized key signatures.

### Documentation
- Completely revamped `README.md` with full ASCII architecture diagrams, defense-in-depth security breakdowns, CLI guides, and REST API cheat sheets.

## [1.1.0] - 2026-08-28
- Post-Quantum ML-DSA Hybrid dual signing.
- Verifiable PDF 2.0 with embedded `/DocuTrustProof` metadata.
- Persistent Vault and Auto-Batch Anchoring worker.
- WYSIWYG Visual Certificate Studio & WebRTC Camera Scanner.

## [1.0.0] - 2026-08-28
- Initial release of DocuTrust open-source sovereign trust stack.
