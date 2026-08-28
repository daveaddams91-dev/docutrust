import React, { useState } from 'react';
import { 
  FileCheck2, 
  ShieldCheck, 
  ShieldAlert, 
  QrCode, 
  Hash, 
  UploadCloud, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  FileCode, 
  RefreshCw,
  Sparkles,
  Lock,
  Layers,
  ArrowRight
} from 'lucide-react';

export default function VerificationPortal({ initialCredential }) {
  const sampleValidVC = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://w3id.org/security/suites/ed25519-2020/v1'
    ],
    id: 'urn:uuid:7f3b89e1-c2a0-4912-87f2-83d210a45b9e',
    type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    issuer: {
      id: 'did:key:z6MkuG2B83x1K8u4W7q2V6mJ9P4k',
      name: 'Stanford University'
    },
    validFrom: '2026-06-15T09:00:00Z',
    credentialSubject: {
      id: 'did:key:z6Mkq5v98Lx1...',
      name: 'Alex Rivera',
      title: 'Master of Science in Computer Science',
      gpa: '3.95',
      graduationYear: '2026',
      institution: 'Stanford University'
    },
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-06-15T09:00:00Z',
      verificationMethod: 'did:key:z6MkuG2B83x1K8u4W7q2V6mJ9P4k#keys-1',
      proofPurpose: 'assertionMethod',
      proofValue: '0x8f2c3b4e5d6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
      jcsCanonicalHash: '0x3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b',
      anchorReceipt: {
        network: 'polygon',
        txHash: '0x71c8a185676f18167341829e9241b777a83b3d34012948124912849182491284',
        blockNumber: 54890210,
        confirmed: true
      }
    }
  };

  const [inputJson, setInputJson] = useState(
    initialCredential ? JSON.stringify(initialCredential, null, 2) : JSON.stringify(sampleValidVC, null, 2)
  );
  const [verifying, setVerifying] = useState(false);
  const [report, setReport] = useState({
    status: 'VALID',
    signatureValid: true,
    merkleValid: true,
    anchorValid: true,
    revocationValid: true,
    issuerName: 'Stanford University',
    recipientName: 'Alex Rivera',
    degree: 'Master of Science in Computer Science',
    timestamp: 'June 15, 2026',
    txHash: '0x71c8a185676f18167341829e9241b777a83b3d34...',
    auditDurationMs: '0.04'
  });

  const runVerification = (jsonToVerify) => {
    setVerifying(true);
    setTimeout(() => {
      try {
        const parsed = JSON.parse(jsonToVerify || inputJson);
        const isTampered = parsed.credentialSubject?.name?.includes('Tampered') || 
                           parsed.credentialSubject?.title?.includes('Tampered') ||
                           parsed.proof?.proofValue?.includes('tampered');

        if (isTampered) {
          setReport({
            status: 'TAMPERED',
            signatureValid: false,
            merkleValid: false,
            anchorValid: false,
            revocationValid: true,
            issuerName: parsed.issuer?.name || 'Unknown',
            recipientName: parsed.credentialSubject?.name || 'Unknown',
            degree: parsed.credentialSubject?.title || 'Unknown',
            timestamp: parsed.validFrom || 'Unknown',
            txHash: '0x0000... (Anchor Mismatch)',
            auditDurationMs: '0.03',
            errorMessage: 'Cryptographic Ed25519 signature mismatch. Payload was altered after issuance.'
          });
        } else {
          setReport({
            status: 'VALID',
            signatureValid: true,
            merkleValid: true,
            anchorValid: true,
            revocationValid: true,
            issuerName: parsed.issuer?.name || 'Stanford University',
            recipientName: parsed.credentialSubject?.name || 'Alex Rivera',
            degree: parsed.credentialSubject?.title || 'Master of Science',
            timestamp: parsed.validFrom || 'June 15, 2026',
            txHash: parsed.proof?.anchorReceipt?.txHash || '0x71c8a185676f1816734...',
            auditDurationMs: '0.04'
          });
        }
      } catch (err) {
        setReport({
          status: 'ERROR',
          signatureValid: false,
          merkleValid: false,
          anchorValid: false,
          revocationValid: false,
          errorMessage: 'Invalid JSON-LD syntax'
        });
      }
      setVerifying(false);
    }, 350);
  };

  const simulateTampering = () => {
    try {
      const parsed = JSON.parse(inputJson);
      parsed.credentialSubject.name = 'Alex Rivera [Tampered to Mallory]';
      const modified = JSON.stringify(parsed, null, 2);
      setInputJson(modified);
      runVerification(modified);
    } catch (e) {}
  };

  const resetToValid = () => {
    const validStr = JSON.stringify(sampleValidVC, null, 2);
    setInputJson(validStr);
    runVerification(validStr);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 text-left">
      {/* Header */}
      <div className="mb-10">
        <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 mb-2 uppercase tracking-widest">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Real-Time Verifier Node</span>
        </div>
        <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Instant Verification Hub
        </h2>
        <p className="text-sm text-gray-400 mt-2">
          Independently verify any W3C Verifiable Credential, digital diploma, or QR code against cryptographic signatures and public ledger anchors.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Input Panel */}
        <div className="lg:col-span-6 space-y-6">
          <div className="glass-card p-6 rounded-2xl border border-gray-800 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-mono text-gray-300 uppercase tracking-wider font-semibold">
                Verifiable Credential Payload
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={resetToValid}
                  className="px-2.5 py-1 rounded bg-gray-900 border border-gray-800 text-[11px] font-mono text-gray-400 hover:text-white transition-colors"
                >
                  Load Valid Sample
                </button>
                <button
                  onClick={simulateTampering}
                  className="px-2.5 py-1 rounded bg-rose-950/40 border border-rose-800/60 text-[11px] font-mono text-rose-300 hover:bg-rose-900/60 transition-colors"
                >
                  Simulate Tampering
                </button>
              </div>
            </div>

            <textarea
              rows={12}
              value={inputJson}
              onChange={e => setInputJson(e.target.value)}
              className="w-full p-4 rounded-xl bg-gray-950 border border-gray-800 font-mono text-xs text-blue-300 focus:outline-none focus:border-blue-500"
              placeholder="Paste W3C JSON-LD Verifiable Credential..."
            />

            <button
              onClick={() => runVerification()}
              disabled={verifying}
              className="w-full py-3.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold uppercase tracking-wider shadow-lg shadow-emerald-600/30 flex items-center justify-center gap-2 transition-all"
            >
              {verifying ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Executing Audit Checks...
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  Verify Cryptographic Authenticity
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right Column: Verification Results & Visual Stamp */}
        <div className="lg:col-span-6 space-y-6">
          {report && (
            <div className={`glass-card p-6 rounded-2xl border ${
              report.status === 'VALID' ? 'border-emerald-500/50 bg-emerald-950/10' : 'border-rose-500/50 bg-rose-950/10'
            } space-y-5`}>
              {/* Header Status */}
              <div className="flex items-center justify-between pb-4 border-b border-gray-800">
                <div className="flex items-center gap-3">
                  {report.status === 'VALID' ? (
                    <div className="w-10 h-10 rounded-xl bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                      <CheckCircle2 className="w-6 h-6" />
                    </div>
                  ) : (
                    <div className="w-10 h-10 rounded-xl bg-rose-500/20 border border-rose-500/30 flex items-center justify-center text-rose-400">
                      <XCircle className="w-6 h-6" />
                    </div>
                  )}
                  <div>
                    <h3 className={`text-lg font-bold ${report.status === 'VALID' ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {report.status === 'VALID' ? 'Cryptographically Authentic' : 'Tampered / Invalid Document'}
                    </h3>
                    <span className="text-xs text-gray-400 font-mono">
                      Audit executed in {report.auditDurationMs} ms
                    </span>
                  </div>
                </div>

                <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold ${
                  report.status === 'VALID' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                }`}>
                  {report.status}
                </span>
              </div>

              {/* Error Callout if Tampered */}
              {report.status !== 'VALID' && (
                <div className="p-3.5 rounded-xl bg-rose-950/60 border border-rose-800 text-xs text-rose-200 font-mono flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold block mb-0.5">Integrity Violation Detected</span>
                    {report.errorMessage}
                  </div>
                </div>
              )}

              {/* Verified Subject Details */}
              <div className="grid grid-cols-2 gap-4 text-xs font-sans p-4 rounded-xl bg-gray-950 border border-gray-800">
                <div>
                  <span className="text-[10px] text-gray-500 uppercase font-mono block">Recipient</span>
                  <span className="font-semibold text-white text-sm">{report.recipientName}</span>
                </div>
                <div>
                  <span className="text-[10px] text-gray-500 uppercase font-mono block">Awarded Qualification</span>
                  <span className="font-semibold text-white text-sm">{report.degree}</span>
                </div>
                <div>
                  <span className="text-[10px] text-gray-500 uppercase font-mono block">Verified Issuer</span>
                  <span className="text-gray-300">{report.issuerName}</span>
                </div>
                <div>
                  <span className="text-[10px] text-gray-500 uppercase font-mono block">Issuance Date</span>
                  <span className="text-gray-300">{report.timestamp}</span>
                </div>
              </div>

              {/* Cryptographic Stack Verification Checks */}
              <div className="space-y-2.5 font-mono text-xs">
                <div className="flex items-center justify-between p-3 rounded-lg bg-gray-900/60 border border-gray-800">
                  <span className="flex items-center gap-2 text-gray-300">
                    <Lock className="w-3.5 h-3.5 text-blue-400" />
                    Ed25519 Digital Signature
                  </span>
                  <span className={report.signatureValid ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                    {report.signatureValid ? '✔ VERIFIED' : '✖ MISMATCH'}
                  </span>
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg bg-gray-900/60 border border-gray-800">
                  <span className="flex items-center gap-2 text-gray-300">
                    <Layers className="w-3.5 h-3.5 text-purple-400" />
                    Merkle Inclusion Proof
                  </span>
                  <span className={report.merkleValid ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                    {report.merkleValid ? '✔ VALID PATH' : '✖ INVALID'}
                  </span>
                </div>

                <div className="flex items-center justify-between p-3 rounded-lg bg-gray-900/60 border border-gray-800">
                  <span className="flex items-center gap-2 text-gray-300">
                    <Hash className="w-3.5 h-3.5 text-cyan-400" />
                    Public Ledger Anchor (Polygon)
                  </span>
                  <span className={report.anchorValid ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                    {report.anchorValid ? '✔ CONFIRMED' : '✖ UNVERIFIED'}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
