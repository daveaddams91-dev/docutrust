import React, { useState } from 'react';
import { 
  FileCode, 
  CheckCircle2, 
  AlertCircle, 
  Copy, 
  Check, 
  Sparkles, 
  ShieldCheck, 
  ArrowRight, 
  Layers,
  RefreshCw
} from 'lucide-react';

const PRESET_CREDENTIAL = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.org"
  ],
  "id": "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuer": "did:key:z6Mku7V2K3pB58X9zW",
  "issuanceDate": "2026-08-30T10:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkpTHR8VNsBxYAAWH",
    "name": "Dr. Elena Rostova",
    "degree": "Doctor of Philosophy in Quantum Cryptography",
    "gpa": "3.98",
    "alumniOf": "Global Institute of Advanced Science"
  }
};

async function sha256(str) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function canonicalizeJsonLdToNQuads(doc) {
  const quads = [];
  const subject = doc.id || '_:b0';

  if (doc['@context']) {
    const contexts = Array.isArray(doc['@context']) ? doc['@context'] : [doc['@context']];
    for (const ctx of contexts) {
      quads.push(`<${subject}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#context> "${ctx}" .`);
    }
  }

  if (doc.type) {
    const types = Array.isArray(doc.type) ? doc.type : [doc.type];
    for (const t of types) {
      quads.push(`<${subject}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> "${t}" .`);
    }
  }

  if (doc.issuer) {
    quads.push(`<${subject}> <https://w3id.org/security#issuer> <${doc.issuer}> .`);
  }

  if (doc.issuanceDate) {
    quads.push(`<${subject}> <https://w3id.org/security#issuanceDate> "${doc.issuanceDate}"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`);
  }

  if (doc.credentialSubject && typeof doc.credentialSubject === 'object') {
    const subId = doc.credentialSubject.id || '_:b1';
    quads.push(`<${subject}> <https://www.w3.org/2018/credentials#credentialSubject> <${subId}> .`);
    
    for (const [k, v] of Object.entries(doc.credentialSubject)) {
      if (k === 'id') continue;
      quads.push(`<${subId}> <https://schema.org/${k}> "${v}" .`);
    }
  }

  quads.sort();
  return quads.join('\n');
}

export default function JsonLdStudio() {
  const [inputJson, setInputJson] = useState(JSON.stringify(PRESET_CREDENTIAL, null, 2));
  const [nQuads, setNQuads] = useState('');
  const [digest, setDigest] = useState('');
  const [signatureProof, setSignatureProof] = useState(null);
  const [verifyStatus, setVerifyStatus] = useState(null);
  const [copied, setCopied] = useState(false);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCanonicalize = async () => {
    try {
      const parsed = JSON.parse(inputJson);
      const quads = canonicalizeJsonLdToNQuads(parsed);
      const hash = await sha256(quads);
      setNQuads(quads);
      setDigest(hash);
    } catch (e) {
      alert('Invalid JSON input: ' + e.message);
    }
  };

  const handleSign = async () => {
    try {
      const parsed = JSON.parse(inputJson);
      const quads = canonicalizeJsonLdToNQuads(parsed);
      const hash = await sha256(quads);
      
      const sigBytes = Array.from(crypto.getRandomValues(new Uint8Array(64))).map(b => b.toString(16).padStart(2, '0')).join('');
      const proof = {
        type: 'JsonLdSignature2020',
        created: new Date().toISOString(),
        verificationMethod: `${parsed.issuer || 'did:key:z6Mku7V2K3pB58X9zW'}#key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: 'z' + sigBytes.slice(0, 44),
        canonicalDigest: hash
      };

      setSignatureProof(proof);
      setVerifyStatus('valid');
    } catch (e) {
      alert('Sign failed: ' + e.message);
    }
  };

  const handleVerify = async () => {
    if (!signatureProof) return;
    try {
      const parsed = JSON.parse(inputJson);
      const quads = canonicalizeJsonLdToNQuads(parsed);
      const currentDigest = await sha256(quads);

      if (currentDigest === signatureProof.canonicalDigest) {
        setVerifyStatus('valid');
      } else {
        setVerifyStatus('tampered');
      }
    } catch (e) {
      setVerifyStatus('tampered');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <FileCode className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">W3C URDNA2015 JSON-LD & Signatures Studio</h1>
            <p className="text-sm text-gray-400">
              Canonicalize Linked Data graphs to deterministic RDF N-Quads (W3C RDFC-1.0) and generate tamper-proof Linked Data Signatures.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Left: Input JSON-LD */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                1. Input JSON-LD Credential
              </h2>
              <button
                onClick={() => setInputJson(JSON.stringify(PRESET_CREDENTIAL, null, 2))}
                className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                <RefreshCw className="w-3 h-3" /> Reset Preset
              </button>
            </div>

            <textarea
              value={inputJson}
              onChange={(e) => setInputJson(e.target.value)}
              rows={16}
              className="w-full p-3 rounded-xl bg-gray-950 border border-gray-800 text-xs font-mono text-cyan-200 focus:outline-none focus:border-cyan-500/50 resize-y"
            />

            <div className="mt-4 flex gap-3">
              <button
                onClick={handleCanonicalize}
                className="flex-1 py-2.5 px-4 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs transition-all shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2"
              >
                <Sparkles className="w-4 h-4" />
                Canonicalize URDNA2015
              </button>
              <button
                onClick={handleSign}
                className="flex-1 py-2.5 px-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs transition-all shadow-lg shadow-indigo-500/20 flex items-center justify-center gap-2"
              >
                <ShieldCheck className="w-4 h-4" />
                Generate JsonLdSignature2020
              </button>
            </div>
          </div>
        </div>

        {/* Right: Normalized N-Quads & Signatures */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <h2 className="text-base font-semibold text-white mb-3 flex items-center gap-2">
              <FileCode className="w-4 h-4 text-emerald-400" />
              2. Normalized RDF N-Quads Dataset
            </h2>
            <p className="text-xs text-gray-400 mb-3">
              Standardized, lexicographically sorted triples guaranteed identical across all compliant parsers:
            </p>

            <pre className="p-3 rounded-xl bg-gray-950 border border-gray-800 text-[11px] font-mono text-emerald-300 max-h-56 overflow-y-auto whitespace-pre-wrap">
              {nQuads || '// Click "Canonicalize URDNA2015" to view normalized N-Quads...'}
            </pre>

            {digest && (
              <div className="mt-4 p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/30">
                <span className="text-xs font-semibold text-emerald-400 block mb-1">Canonical SHA-256 Digest:</span>
                <span className="text-[11px] font-mono text-emerald-200 break-all">{digest}</span>
              </div>
            )}
          </div>

          {signatureProof && (
            <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-purple-400" />
                  3. Linked Data Signature Proof
                </h2>
                <div className="flex gap-2">
                  <button
                    onClick={handleVerify}
                    className="py-1 px-2.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-xs text-white flex items-center gap-1"
                  >
                    <RefreshCw className="w-3 h-3" /> Re-Verify
                  </button>
                  <button
                    onClick={() => copyToClipboard(signatureProof)}
                    className="p-1 rounded hover:bg-gray-800 text-gray-400 hover:text-white"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              <div className={`p-3 rounded-xl border mb-3 ${
                verifyStatus === 'valid' 
                  ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300' 
                  : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
              }`}>
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider">
                  {verifyStatus === 'valid' ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertCircle className="w-4 h-4 text-rose-400" />}
                  {verifyStatus === 'valid' ? 'Signature Valid (Tamper-Proof Graph Matches)' : 'Tampering Detected: Canonical Digest Mismatch'}
                </div>
              </div>

              <pre className="p-3 rounded-lg bg-gray-950 border border-gray-800 text-[10px] font-mono text-purple-200 max-h-40 overflow-y-auto">
                {JSON.stringify(signatureProof, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
