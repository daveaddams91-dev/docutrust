## 📌 Summary of Changes
<!-- Provide a brief description of what this PR introduces, fixes, or refactors. -->

## 🛡️ Cryptographic & Protocol Impact
- [ ] **W3C VC 2.0 / Standards**: No breaking changes to canonical serialization, context, or proof models.
- [ ] **Zero-Knowledge / PQC / Signatures**: Deterministic challenges and verification verified.
- [ ] **Cross-Platform SDK Parity**: TypeScript & Python implementations align with core specs.

## 🧪 Testing & Verification
- [ ] All unit tests pass in `@docutrust/core` (`npm test --workspace=@docutrust/core`)
- [ ] CLI commands verified (`npm test --workspace=@docutrust/cli`)
- [ ] API routes verified (`npm test --workspace=@docutrust/api`)
- [ ] Python SDK unit tests pass (`python -m unittest discover -s sdks/python/tests`)
- [ ] Web dashboard builds successfully (`npm run build --workspace=@docutrust/web`)

## 📝 Documentation & Changelog
- [ ] `CHANGELOG.md` updated with release notes and author attribution.
- [ ] Code comments, type annotations, and docstrings maintained.
