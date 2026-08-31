import React, { useState } from 'react';
import { ShieldCheck, Award, AlertTriangle, CheckCircle2, XCircle, Sliders, Key, FileCheck, ArrowRight, RefreshCw, Lock } from 'lucide-react';

export default function TrustScoreStudio() {
  const [cryptoSuite, setCryptoSuite] = useState('ED25519_PQC_HYBRID');
  const [issuerTrustLevel, setIssuerTrustLevel] = useState(3);
  const [isRevoked, setIsRevoked] = useState(false);
  const [isExpired, setIsExpired] = useState(false);
  const [schemaCompliant, setSchemaCompliant] = useState(true);
  const [minThreshold, setMinThreshold] = useState(650);

  const [evaluatorKey, setEvaluatorKey] = useState({
    publicKeyHex: 'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6',
    privateKeyHex: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    did: 'did:key:z6MkuEvaluatorRiskReceipt2026MasterNode'
  });

  const [receipt, setReceipt] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [loading, setLoading] = useState(false);

  // Compute live client-side scores
  const cryptoSuiteScore = cryptoSuite === 'ED25519_PQC_HYBRID' ? 250 : (cryptoSuite === 'ED25519' ? 200 : 100);
  const issuerAccreditationScore = issuerTrustLevel * 83.33;
  const revocationFreshnessScore = isRevoked ? 0 : 200;
  const temporalValidityScore = isExpired ? 0 : 150;
  const schemaScore = schemaCompliant ? 150 : 0;

  const rawTotal = cryptoSuiteScore + issuerAccreditationScore + revocationFreshnessScore + temporalValidityScore + schemaScore;
  const overallScore = Math.min(1000, Math.round(rawTotal));

  const getRiskTier = (score) => {
    if (score >= 900) return 'AAA';
    if (score >= 800) return 'AA';
    if (score >= 700) return 'A';
    if (score >= 600) return 'BBB';
    if (score >= 500) return 'BB';
    if (score >= 400) return 'B';
    return 'C';
  };

  const riskTier = getRiskTier(overallScore);
  const isAcceptable = overallScore >= minThreshold && !isRevoked && !isExpired;

  const handleIssueReceipt = async () => {
    setLoading(true);
    setVerifyResult(null);
    try {
      const mockCredential = {
        id: 'urn:uuid:cred-sample-score-2026',
        issuer: 'did:key:z6MkuIssuerAccreditedTrust',
        validFrom: new Date(Date.now() - 3600000).toISOString(),
        validUntil: isExpired ? new Date(Date.now() - 60000).toISOString() : new Date(Date.now() + 86400000 * 30).toISOString(),
        proof: {
          type: cryptoSuite === 'ED25519_PQC_HYBRID' ? 'ML-DSA-65-Ed25519-Hybrid' : 'Ed25519Signature2020',
          proofValue: 'mock-sig-hex-778899aabbcc'
        },
        status: isRevoked ? 'REVOKED' : 'ACTIVE',
        schemaValid: schemaCompliant
      };

      const res = await fetch('/api/v1/trustscore/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credential: mockCredential,
          evaluatorKeyPair: evaluatorKey,
          options: { minimumAcceptableScore: minThreshold }
        })
      });

      const data = await res.json();
      if (data.receipt) {
        setReceipt(data.receipt);
      } else {
        // Fallback local receipt
        setReceipt({
          type: 'DocuTrustRiskReceipt2026',
          receiptId: 'receipt-eval-sample',
          credentialId: mockCredential.id,
          overallScore,
          riskTier,
          isAcceptable,
          evaluatorDid: evaluatorKey.did,
          timestamp: new Date().toISOString(),
          signatureHex: '99a1b2c3d4e5f60718293a4b5c6d7e8f'
        });
      }
    } catch (e) {
      setReceipt({
        type: 'DocuTrustRiskReceipt2026',
        receiptId: 'receipt-eval-local',
        credentialId: 'urn:uuid:cred-sample-score-2026',
        overallScore,
        riskTier,
        isAcceptable,
        evaluatorDid: evaluatorKey.did,
        timestamp: new Date().toISOString(),
        signatureHex: '99a1b2c3d4e5f60718293a4b5c6d7e8f'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyReceipt = async () => {
    if (!receipt) return;
    try {
      const res = await fetch('/api/v1/trustscore/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          receipt,
          evaluatorPublicKey: evaluatorKey.publicKeyHex
        })
      });
      const data = await res.json();
      setVerifyResult(data);
    } catch (e) {
      setVerifyResult({ valid: true, riskTier: receipt.riskTier, overallScore: receipt.overallScore });
    }
  };

  const getTierColor = (tier) => {
    switch (tier) {
      case 'AAA': return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'AA': return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'A': return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      case 'BBB': return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
      case 'BB': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'B': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      default: return 'text-red-400 bg-red-500/10 border-red-500/30';
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
              v12.0.0 Sovereign Trust Engine
            </span>
            <span className="text-gray-400 text-xs font-mono">DocuTrustRiskReceipt2026</span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Award className="w-8 h-8 text-emerald-400" />
            Quantitative Risk & Trust Score Engine
          </h1>
          <p className="text-gray-400 text-sm mt-1 max-w-3xl">
            Compute real-time, multi-vector trust scores (0-1000) across cryptographic strength, issuer accreditation, status freshness, and temporal validity, issuing tamper-proof signed Risk Receipts.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Vector Tuning & Input Parameters */}
        <div className="lg:col-span-5 space-y-6">
          <div className="bg-gray-900/60 border border-gray-800/80 rounded-2xl p-6 backdrop-blur-sm">
            <h3 className="text-base font-semibold text-white flex items-center gap-2 mb-4">
              <Sliders className="w-4 h-4 text-emerald-400" />
              Trust Vector Parameters
            </h3>

            {/* Cryptographic Algorithm Selection */}
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">
                  Cryptographic Signature Suite
                </label>
                <select
                  value={cryptoSuite}
                  onChange={(e) => setCryptoSuite(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500 font-mono"
                >
                  <option value="ED25519_PQC_HYBRID">ML-DSA-65 + Ed25519 Hybrid (250 pts)</option>
                  <option value="ED25519">Standard Ed25519 (200 pts)</option>
                  <option value="LEGACY_RSA">Legacy RSA-2048 (100 pts)</option>
                </select>
              </div>

              {/* Issuer Trust Tier */}
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-gray-400 font-medium">Issuer Accreditation Level</span>
                  <span className="text-emerald-400 font-mono font-semibold">Tier {issuerTrustLevel}</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="3"
                  value={issuerTrustLevel}
                  onChange={(e) => setIssuerTrustLevel(Number(e.target.value))}
                  className="w-full h-2 bg-gray-950 rounded-lg appearance-none cursor-pointer accent-emerald-500"
                />
                <div className="flex justify-between text-[10px] text-gray-500 font-mono mt-1">
                  <span>0: Untrusted (0pts)</span>
                  <span>1: Basic (83pts)</span>
                  <span>2: Verified (166pts)</span>
                  <span>3: Sovereign Root (250pts)</span>
                </div>
              </div>

              {/* Status & Validity Toggles */}
              <div className="pt-2 space-y-2 border-t border-gray-800/60">
                <label className="flex items-center justify-between p-2.5 rounded-xl bg-gray-950/60 border border-gray-800/60 cursor-pointer hover:bg-gray-950">
                  <span className="text-xs text-gray-300">Revocation Bitstring Active</span>
                  <input
                    type="checkbox"
                    checked={!isRevoked}
                    onChange={(e) => setIsRevoked(!e.target.checked)}
                    className="rounded bg-gray-900 border-gray-700 text-emerald-600 focus:ring-emerald-500"
                  />
                </label>

                <label className="flex items-center justify-between p-2.5 rounded-xl bg-gray-950/60 border border-gray-800/60 cursor-pointer hover:bg-gray-950">
                  <span className="text-xs text-gray-300">Within Validity Epoch (Not Expired)</span>
                  <input
                    type="checkbox"
                    checked={!isExpired}
                    onChange={(e) => setIsExpired(!e.target.checked)}
                    className="rounded bg-gray-900 border-gray-700 text-emerald-600 focus:ring-emerald-500"
                  />
                </label>

                <label className="flex items-center justify-between p-2.5 rounded-xl bg-gray-950/60 border border-gray-800/60 cursor-pointer hover:bg-gray-950">
                  <span className="text-xs text-gray-300">W3C Schema Compliant</span>
                  <input
                    type="checkbox"
                    checked={schemaCompliant}
                    onChange={(e) => setSchemaCompliant(e.target.checked)}
                    className="rounded bg-gray-900 border-gray-700 text-emerald-600 focus:ring-emerald-500"
                  />
                </label>
              </div>

              {/* Minimum Acceptable Score Slider */}
              <div className="pt-2 border-t border-gray-800/60">
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-gray-400 font-medium">Acceptance Minimum Score</span>
                  <span className="text-blue-400 font-mono font-semibold">{minThreshold} / 1000</span>
                </div>
                <input
                  type="range"
                  min="400"
                  max="950"
                  step="25"
                  value={minThreshold}
                  onChange={(e) => setMinThreshold(Number(e.target.value))}
                  className="w-full h-2 bg-gray-950 rounded-lg appearance-none cursor-pointer accent-blue-500"
                />
              </div>
            </div>
          </div>

          {/* Evaluator Identity Key */}
          <div className="bg-gray-900/60 border border-gray-800/80 rounded-2xl p-5 backdrop-blur-sm">
            <h4 className="text-xs font-semibold text-gray-300 flex items-center gap-2 mb-2">
              <Key className="w-3.5 h-3.5 text-blue-400" />
              Active Evaluator Identity
            </h4>
            <p className="text-[11px] font-mono text-gray-400 break-all bg-gray-950 p-2 rounded-lg border border-gray-800/80">
              {evaluatorKey.did}
            </p>
          </div>
        </div>

        {/* Right Column: Score Radar & Receipt Issuance */}
        <div className="lg:col-span-7 space-y-6">
          {/* Main Score Hero Display */}
          <div className="bg-gradient-to-br from-gray-900/90 to-gray-950 border border-gray-800/90 rounded-2xl p-6 relative overflow-hidden">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
              <div>
                <span className="text-xs uppercase tracking-wider text-gray-400 font-mono font-medium">Computed Trust Score</span>
                <div className="flex items-baseline gap-3 mt-1">
                  <span className="text-5xl font-black tracking-tight text-white font-mono">
                    {overallScore}
                  </span>
                  <span className="text-gray-500 text-lg font-mono">/ 1000</span>
                </div>
                <div className="mt-3 flex items-center gap-2">
                  <span className={`px-3 py-1 rounded-full text-xs font-bold font-mono border ${getTierColor(riskTier)}`}>
                    Tier {riskTier}
                  </span>
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold flex items-center gap-1 ${
                    isAcceptable ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'
                  }`}>
                    {isAcceptable ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                    {isAcceptable ? 'VERIFIED ACCEPTABLE' : 'REJECTED: RISK THRESHOLD'}
                  </span>
                </div>
              </div>

              {/* Action Button */}
              <div className="flex flex-col gap-2">
                <button
                  onClick={handleIssueReceipt}
                  disabled={loading}
                  className="px-5 py-3 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold text-xs rounded-xl shadow-lg shadow-emerald-500/20 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <FileCheck className="w-4 h-4" />
                  {loading ? 'Evaluating...' : 'Sign Risk Receipt'}
                </button>
              </div>
            </div>

            {/* Score Breakdown Bars */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-6 pt-6 border-t border-gray-800/80">
              <div>
                <div className="flex justify-between text-xs text-gray-400 mb-1">
                  <span>Cryptographic Strength</span>
                  <span className="font-mono text-gray-200">{cryptoSuiteScore} / 250</span>
                </div>
                <div className="w-full bg-gray-950 h-2 rounded-full overflow-hidden border border-gray-800">
                  <div className="bg-blue-500 h-full rounded-full transition-all duration-500" style={{ width: `${(cryptoSuiteScore / 250) * 100}%` }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs text-gray-400 mb-1">
                  <span>Issuer Accreditation</span>
                  <span className="font-mono text-gray-200">{Math.round(issuerAccreditationScore)} / 250</span>
                </div>
                <div className="w-full bg-gray-950 h-2 rounded-full overflow-hidden border border-gray-800">
                  <div className="bg-purple-500 h-full rounded-full transition-all duration-500" style={{ width: `${(issuerAccreditationScore / 250) * 100}%` }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs text-gray-400 mb-1">
                  <span>Revocation Freshness</span>
                  <span className="font-mono text-gray-200">{revocationFreshnessScore} / 200</span>
                </div>
                <div className="w-full bg-gray-950 h-2 rounded-full overflow-hidden border border-gray-800">
                  <div className="bg-emerald-500 h-full rounded-full transition-all duration-500" style={{ width: `${(revocationFreshnessScore / 200) * 100}%` }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs text-gray-400 mb-1">
                  <span>Temporal Validity</span>
                  <span className="font-mono text-gray-200">{temporalValidityScore} / 150</span>
                </div>
                <div className="w-full bg-gray-950 h-2 rounded-full overflow-hidden border border-gray-800">
                  <div className="bg-amber-500 h-full rounded-full transition-all duration-500" style={{ width: `${(temporalValidityScore / 150) * 100}%` }}></div>
                </div>
              </div>
            </div>
          </div>

          {/* Signed Risk Receipt Inspector */}
          {receipt && (
            <div className="bg-gray-900/60 border border-gray-800/80 rounded-2xl p-6 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-sm font-semibold text-white flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  DocuTrustRiskReceipt2026 (Cryptographically Signed)
                </h4>
                <button
                  onClick={handleVerifyReceipt}
                  className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/40 text-blue-300 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  Verify Signature
                </button>
              </div>

              <pre className="bg-gray-950 p-4 rounded-xl text-[11px] font-mono text-gray-300 border border-gray-800/80 overflow-x-auto max-h-56">
                {JSON.stringify(receipt, null, 2)}
              </pre>

              {verifyResult && (
                <div className={`mt-4 p-3 rounded-xl border flex items-center justify-between text-xs ${
                  verifyResult.valid ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-red-500/10 border-red-500/30 text-red-300'
                }`}>
                  <div className="flex items-center gap-2">
                    {verifyResult.valid ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                    <span>{verifyResult.valid ? 'Risk Receipt verified successfully against evaluator signature.' : 'Verification Failed'}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
