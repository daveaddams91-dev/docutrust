# Contributing to DocuTrust

We welcome contributions from cryptographers, software engineers, designers, and documentation enthusiasts!

## Getting Started

1. **Fork and Clone the Repository**:
   ```bash
   git clone https://github.com/Raj123-0/docutrust.git
   cd docutrust
   ```

2. **Run Tests**:
   ```bash
   # Run core cryptographic tests
   node --test packages/core/test/core.test.js

   # Run Python SDK tests
   python -m unittest sdks/python/tests/test_docutrust.py
   ```

3. **Start Local API Server**:
   ```bash
   node apps/api/src/server.js
   ```

4. **Start Web Frontend**:
   ```bash
   cd apps/web
   npm run dev
   ```

## Development Guidelines
- Strictly preserve deterministic hashing and JSON canonicalization conventions (RFC 8785).
- Always include automated unit tests when adding new cryptographic primitives or adapters.
- Follow Semantic Versioning.
