import React, { useState } from 'react';
import { Terminal, Copy, CheckCircle2, Code2, Globe2, Sparkles, BookOpen } from 'lucide-react';

export default function DeveloperHub() {
  const [activeLang, setActiveLang] = useState('python');
  const [copied, setCopied] = useState(false);

  const snippets = {
    python: `# Install via: pip install docutrust
import docutrust

# Initialize the DocuTrust Client
client = docutrust.DocuTrustClient(
    api_url="https://api.docutrust.org/api/v1",
    api_key="dt_live_sec_994a82b..."
)

# 1. Issue a W3C Verifiable Credential
credential = client.issue_credential(
    credential_subject={
        "name": "Alex Rivera",
        "title": "Master of Science in Computer Science",
        "graduationYear": "2026",
        "gpa": "3.98"
    },
    credential_type="UniversityDegreeCredential",
    enable_selective_disclosure=True
)
print("Issued Credential ID:", credential["credential"]["id"])

# 2. Verify any Credential in sub-millisecond time
result = client.verify_credential(credential["credential"])
print("Signature Valid:", result["signatureValid"])
print("Ledger Anchor Confirmed:", result["anchorValid"])`,

    typescript: `// Install via: npm install @docutrust/core
import { 
  VerifiableCredentialsEngine, 
  generateKeyPair, 
  DIDResolver 
} from '@docutrust/core';

// 1. Generate an Ed25519 Authority KeyPair (did:key)
const issuerKeys = generateKeyPair();
console.log('Issuer DID:', issuerKeys.did);

// 2. Issue a Verifiable Credential with Merkle Tree Anchor
const { credential, selectiveDisclosurePackage } = VerifiableCredentialsEngine.issue({
  type: ['UniversityDegreeCredential'],
  issuer: {
    id: issuerKeys.did,
    name: 'Stanford University'
  },
  credentialSubject: {
    name: 'Elena Rostova',
    title: 'Ph.D. in Artificial Intelligence',
    graduationYear: 2026
  },
  keyPair: issuerKeys,
  enableSelectiveDisclosure: true
});

// 3. Verify Authenticity against public key
const audit = await VerifiableCredentialsEngine.verify(credential);
console.log('Is Credential 100% Authentic?', audit.valid);`,

    curl: `# 1. Generate KeyPair
curl -X POST https://api.docutrust.org/api/v1/keys/generate \\
  -H "Content-Type: application/json"

# 2. Issue a Verifiable Credential
curl -X POST https://api.docutrust.org/api/v1/credentials/issue \\
  -H "Content-Type: application/json" \\
  -d '{
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "issuerName": "Massachusetts Institute of Technology",
    "credentialSubject": {
      "name": "Alex Rivera",
      "degree": "M.Sc. Computer Science",
      "year": "2026"
    }
  }'

# 3. Verify a Credential
curl -X POST https://api.docutrust.org/api/v1/credentials/verify \\
  -H "Content-Type: application/json" \\
  -d '{"credential": { ... }}'`,

    cli: `# 1. Confidential Paillier KeyGen & Homomorphic Arithmetic
$ docutrust confidential-keygen --out paillier.json
$ docutrust confidential-encrypt --key paillier.json --claim "salary" --val 125000 --out enc1.json
$ docutrust confidential-sum --key paillier.json --ciphertexts "enc1.json,enc2.json" --out sum.json

# 2. W3C URDNA2015 RDF Dataset Canonicalization & JSON-LD Signatures
$ docutrust jsonld-canonicalize --doc credential.jsonld
$ docutrust jsonld-sign --doc credential.jsonld --key issuer_key.json --out signed.jsonld

# 3. Hierarchical Trust Chain Issue & Path Verification
$ docutrust trustchain-issue --issuer "did:key:z6MkuRoot" --delegatee "did:key:z6MkuBoard" --out token1.json
$ docutrust trustchain-verify --chain "token1.json,token2.json" --cred signed.jsonld --roots "did:key:z6MkuRoot"

# 4. Post-Quantum Dual Hybrid KEM (NIST FIPS 203 ML-KEM-768 Kyber)
$ docutrust quantum-armor-keygen --out kem_keys.json
$ docutrust quantum-armor-seal --key kem_keys.json --payload sensitive_vc.json --out sealed.envelope
$ docutrust quantum-armor-unseal --key kem_keys.json --envelope sealed.envelope`
  };

  const copyCode = () => {
    navigator.clipboard.writeText(snippets[activeLang]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 text-left">
      {/* Header */}
      <div className="mb-10">
        <div className="flex items-center gap-2 text-xs font-mono text-blue-400 mb-2 uppercase tracking-widest">
          <Terminal className="w-3.5 h-3.5" />
          <span>Developer SDKs & OpenAPI Specification (v6.0.0)</span>
        </div>
        <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Developer Hub & Quickstart
        </h2>
        <p className="text-sm text-gray-400 mt-2">
          Integrate programmatic confidential homomorphic arithmetic, W3C URDNA2015 JSON-LD signatures, hierarchical trust chains, and post-quantum dual hybrid KEM armor directly into your stack.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Code Snippet Box */}
        <div className="lg:col-span-8 glass-card p-6 sm:p-8 rounded-2xl border border-gray-800 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4 pb-3 border-b border-gray-800">
            <div className="flex items-center gap-2">
              {['python', 'typescript', 'curl', 'cli'].map(lang => (
                <button
                  key={lang}
                  onClick={() => setActiveLang(lang)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium uppercase transition-all ${
                    activeLang === lang
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-gray-400 hover:text-white bg-gray-900 border border-gray-800'
                  }`}
                >
                  {lang}
                </button>
              ))}
            </div>

            <button
              onClick={copyCode}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-xs font-mono text-gray-300 hover:text-white transition-colors"
            >
              <Copy className="w-3.5 h-3.5" />
              {copied ? 'Copied Code!' : 'Copy Snippet'}
            </button>
          </div>

          <pre className="p-4 bg-black rounded-xl border border-gray-800 font-mono text-xs text-blue-300 overflow-x-auto leading-relaxed">
            {snippets[activeLang]}
          </pre>
        </div>

        {/* REST API Endpoints Quick Reference */}
        <div className="lg:col-span-4 glass-card p-6 rounded-2xl border border-gray-800 space-y-4 font-mono text-xs">
          <h3 className="text-sm font-bold text-white font-sans uppercase tracking-wider">
            REST API v1 Endpoints
          </h3>

          <div className="space-y-2.5">
            <div className="p-2.5 rounded-lg bg-gray-950 border border-gray-800 space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-indigo-500/10 text-indigo-400 font-bold">POST</span>
                <span className="text-white text-[11px]">/api/v1/anoncreds/blind-issue</span>
              </div>
              <p className="text-[10px] text-gray-400 font-sans">AnonCreds 2.0 blind BBS+ credential issuance</p>
            </div>

            <div className="p-2.5 rounded-lg bg-gray-950 border border-gray-800 space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-500/10 text-cyan-400 font-bold">POST</span>
                <span className="text-white text-[11px]">/api/v1/dkg/ceremony</span>
              </div>
              <p className="text-[10px] text-gray-400 font-sans">Initialize FROST K-of-N threshold ceremony</p>
            </div>

            <div className="p-2.5 rounded-lg bg-gray-950 border border-gray-800 space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-blue-500/10 text-blue-400 font-bold">POST</span>
                <span className="text-white text-[11px]">/api/v1/solidity/export-verifier</span>
              </div>
              <p className="text-[10px] text-gray-400 font-sans">Generate on-chain Solidity verifier contract</p>
            </div>

            <div className="p-2.5 rounded-lg bg-gray-950 border border-gray-800 space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 font-bold">POST</span>
                <span className="text-white text-[11px]">/api/v1/audit/bundle/create</span>
              </div>
              <p className="text-[10px] text-gray-400 font-sans">Package .dtbundle with SOC2 compliance</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
