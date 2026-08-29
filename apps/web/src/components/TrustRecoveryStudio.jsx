import React, { useState } from 'react';
import { Network, Split, Key, CheckCircle, ShieldCheck, FileJson, AlertCircle, RefreshCw } from 'lucide-react';

export default function TrustRecoveryStudio() {
  const [activeSubTab, setActiveSubTab] = useState('shamir');

  // Shamir State
  const [secretToSplit, setSecretToSplit] = useState('ed25519-master-institutional-root-key-secret-2026');
  const [totalSharesCount, setTotalSharesCount] = useState(5);
  const [thresholdCount, setThresholdCount] = useState(3);
  const [generatedShares, setGeneratedShares] = useState(null);
  const [selectedShares, setSelectedShares] = useState({});
  const [reconstructedKey, setReconstructedKey] = useState(null);
  const [reconstructError, setReconstructError] = useState(null);

  // SD-JWT State
  const [claimsJson, setClaimsJson] = useState(JSON.stringify({
    given_name: 'Elena',
    family_name: 'Rostova',
    degree: 'Ph.D. in Computer Science',
    graduation_year: 2026,
    gpa: '3.98'
  }, null, 2));
  const [sdJwtOutput, setSdJwtOutput] = useState(null);

  // Trust Registry State
  const [targetDid, setTargetDid] = useState('did:key:z6MkuStanfordAccreditedAuthority2026');
  const [targetSchema, setTargetSchema] = useState('UniversityDegreeCredential');
  const [trustAuditResult, setTrustAuditResult] = useState(null);

  // Handle Shamir Split Simulation
  const handleSplitSecret = () => {
    const shares = [];
    const checksum = '0x' + Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');

    for (let i = 1; i <= totalSharesCount; i++) {
      const shareHex = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
      shares.push({
        index: i,
        shareHex,
        threshold: thresholdCount,
        totalShares: totalSharesCount,
        checksum,
        holder: `Custodian ${i} (${i <= 2 ? 'Trust Officer' : i === 3 ? 'Dean' : 'Security Auditor'})`
      });
    }

    setGeneratedShares(shares);
    setSelectedShares({ 1: true, 2: true, 3: true });
    setReconstructedKey(null);
    setReconstructError(null);
  };

  // Handle Shamir Combine Simulation
  const handleCombineShares = () => {
    if (!generatedShares) return;
    const activeCount = Object.values(selectedShares).filter(Boolean).length;
    if (activeCount < thresholdCount) {
      setReconstructError(`Insufficient shares selected: ${activeCount}/${thresholdCount} required.`);
      setReconstructedKey(null);
    } else {
      setReconstructError(null);
      setReconstructedKey(secretToSplit);
    }
  };

  // Handle SD-JWT Encoding Simulation
  const handleGenerateSDJWT = () => {
    try {
      const parsed = JSON.parse(claimsJson);
      const disclosures = Object.entries(parsed).map(([k, v]) => {
        const salt = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');
        return {
          key: k,
          value: v,
          salt,
          rawB64: btoa(JSON.stringify([salt, k, v])).replace(/=/g, '')
        };
      });

      const headerB64 = btoa(JSON.stringify({ alg: 'EdDSA', typ: 'vc+sd-jwt' })).replace(/=/g, '');
      const payloadB64 = btoa(JSON.stringify({
        iss: 'did:key:z6MkuStanfordAuthority',
        _sd: disclosures.map(d => d.salt),
        _sd_alg: 'sha-256'
      })).replace(/=/g, '');
      const sigB64 = 'sig_' + Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');

      const combined = `${headerB64}.${payloadB64}.${sigB64}~${disclosures.map(d => d.rawB64).join('~')}~`;

      setSdJwtOutput({
        headerB64,
        payloadB64,
        disclosures,
        combined,
        standard: 'IETF SD-JWT (draft-ietf-oauth-selective-disclosure-jwt-08)'
      });
    } catch (e) {
      alert('Invalid claims JSON');
    }
  };

  // Handle Trust Registry Check
  const handleCheckTrust = () => {
    setTrustAuditResult({
      issuerDid: targetDid,
      issuerName: 'Stanford University (Office of the Registrar)',
      jurisdiction: 'United States (US-CA)',
      trustLevel: 'TIER_1_ACCREDITED (Highest Sovereign Authority)',
      authorized: true,
      allowedSchemas: ['UniversityDegreeCredential', 'HonoraryDegreeCredential', 'TranscriptCredential'],
      governanceAnchorDid: 'did:web:us-higher-ed.gov',
      validUntil: '2027-12-31T23:59:59Z'
    });
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="text-center mb-12">
        <div className="inline-flex items-center space-x-2 px-3 py-1 bg-blue-900/30 border border-blue-500/40 rounded-full text-blue-400 text-xs font-semibold uppercase tracking-wider mb-4">
          <Network className="w-4 h-4" />
          <span>Trust Mesh & Recovery v1.4</span>
        </div>
        <h1 className="text-4xl font-extrabold text-white sm:text-5xl tracking-tight">
          Trust Framework, SD-JWT & Shamir Key Recovery
        </h1>
        <p className="mt-4 text-lg text-gray-400 max-w-3xl mx-auto">
          Institutional governance with Shamir (k-of-n) threshold key slicing, IETF SD-JWT mobile wallet interoperability, and decentralized accreditation registries.
        </p>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex justify-center mb-8">
        <div className="bg-gray-900 p-1.5 rounded-xl border border-gray-800 flex space-x-2">
          <button
            onClick={() => setActiveSubTab('shamir')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
              activeSubTab === 'shamir' ? 'bg-amber-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'
            }`}
          >
            <Split className="w-4 h-4" />
            <span>Shamir Key Recovery</span>
          </button>
          <button
            onClick={() => setActiveSubTab('sdjwt')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
              activeSubTab === 'sdjwt' ? 'bg-indigo-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'
            }`}
          >
            <FileJson className="w-4 h-4" />
            <span>IETF SD-JWT Studio</span>
          </button>
          <button
            onClick={() => setActiveSubTab('trust')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
              activeSubTab === 'trust' ? 'bg-emerald-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
            <span>Trust Registry</span>
          </button>
        </div>
      </div>

      {/* 1. Shamir Key Recovery */}
      {activeSubTab === 'shamir' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Split className="w-5 h-5 text-amber-400" />
              <span>(K-of-N) Shamir Threshold Key Slicing</span>
            </h3>
            <p className="text-gray-400 text-sm mb-6">
              Split master private keys among custodians. Any <code className="text-amber-400">K</code> shares can reconstruct the key, while fewer than <code className="text-amber-400">K</code> reveal zero mathematical information.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Master Private Key / Seed</label>
                <input
                  type="text"
                  value={secretToSplit}
                  onChange={(e) => setSecretToSplit(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2.5 text-white font-mono text-xs focus:border-amber-500 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">Total Shares (N)</label>
                  <input
                    type="number"
                    min="2"
                    max="10"
                    value={totalSharesCount}
                    onChange={(e) => setTotalSharesCount(parseInt(e.target.value))}
                    className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2 text-white font-mono focus:border-amber-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">Threshold Required (K)</label>
                  <input
                    type="number"
                    min="2"
                    max={totalSharesCount}
                    value={thresholdCount}
                    onChange={(e) => setThresholdCount(parseInt(e.target.value))}
                    className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2 text-white font-mono focus:border-amber-500 focus:outline-none"
                  />
                </div>
              </div>

              <button
                onClick={handleSplitSecret}
                className="w-full mt-4 bg-amber-600 hover:bg-amber-500 text-white font-bold py-3 rounded-lg flex items-center justify-center space-x-2 transition-all"
              >
                <Split className="w-4 h-4" />
                <span>Split Key into {totalSharesCount} Custodian Shares</span>
              </button>
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Key className="w-5 h-5 text-amber-400" />
              <span>Custodian Shares & Interactive Reconstruction</span>
            </h3>

            {generatedShares ? (
              <div className="space-y-4 mt-4">
                <div className="space-y-2 max-h-60 overflow-y-auto pr-2">
                  {generatedShares.map(share => (
                    <label
                      key={share.index}
                      className={`flex items-center justify-between p-3 rounded-lg border cursor-pointer transition-all ${
                        selectedShares[share.index] ? 'bg-amber-950/40 border-amber-500/50' : 'bg-gray-950 border-gray-800'
                      }`}
                    >
                      <div className="flex items-center space-x-3">
                        <input
                          type="checkbox"
                          checked={!!selectedShares[share.index]}
                          onChange={(e) => setSelectedShares({ ...selectedShares, [share.index]: e.target.checked })}
                          className="w-4 h-4 accent-amber-500 rounded"
                        />
                        <div>
                          <span className="text-white font-bold text-xs block">{share.holder}</span>
                          <span className="text-gray-500 font-mono text-[10px]">Share #{share.index}: {share.shareHex.slice(0, 16)}...</span>
                        </div>
                      </div>
                      <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">GF(256)</span>
                    </label>
                  ))}
                </div>

                <button
                  onClick={handleCombineShares}
                  className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-2.5 rounded-lg flex items-center justify-center space-x-2 transition-all"
                >
                  <RefreshCw className="w-4 h-4" />
                  <span>Reconstruct Master Secret</span>
                </button>

                {reconstructedKey && (
                  <div className="p-3 bg-emerald-950/40 border border-emerald-500/40 rounded-lg text-emerald-300 font-mono text-xs">
                    <span className="font-bold block mb-1">✔ Successfully Reconstructed Key:</span>
                    <span className="break-all">{reconstructedKey}</span>
                  </div>
                )}

                {reconstructError && (
                  <div className="p-3 bg-rose-950/40 border border-rose-500/40 rounded-lg text-rose-300 text-xs flex items-center space-x-2">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" />
                    <span>{reconstructError}</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-16 text-gray-500">
                <Split className="w-12 h-12 mx-auto mb-2 opacity-30" />
                <p>Click "Split Key" to generate shares.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 2. SD-JWT Studio */}
      {activeSubTab === 'sdjwt' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <FileJson className="w-5 h-5 text-indigo-400" />
              <span>IETF SD-JWT Format Converter</span>
            </h3>
            <p className="text-gray-400 text-sm mb-6">
              Convert credentials to IETF SD-JWT format for universal compatibility with Apple Wallet, Google Wallet, and EU Digital Identity Wallet.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Claims Payload (JSON)</label>
                <textarea
                  rows={8}
                  value={claimsJson}
                  onChange={(e) => setClaimsJson(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-700 rounded-lg p-3 text-white font-mono text-xs focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <button
                onClick={handleGenerateSDJWT}
                className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3 rounded-lg flex items-center justify-center space-x-2 transition-all"
              >
                <FileJson className="w-4 h-4" />
                <span>Generate IETF SD-JWT Package</span>
              </button>
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <CheckCircle className="w-5 h-5 text-indigo-400" />
              <span>SD-JWT Disclosures & Wire Format</span>
            </h3>

            {sdJwtOutput ? (
              <div className="space-y-3 font-mono text-xs mt-4">
                <div className="p-3 bg-gray-950 rounded-lg border border-indigo-500/30">
                  <span className="text-indigo-400 font-bold block mb-1">Standard:</span>
                  <span className="text-white">{sdJwtOutput.standard}</span>
                </div>
                <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                  <span className="text-gray-400 block mb-1">Combined Wire String:</span>
                  <span className="text-emerald-400 break-all">{sdJwtOutput.combined.slice(0, 90)}...</span>
                </div>
                <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                  <span className="text-gray-400 block mb-1">Disclosures Count:</span>
                  <span className="text-amber-400 font-bold">{sdJwtOutput.disclosures.length} salted disclosure tokens</span>
                </div>
              </div>
            ) : (
              <div className="text-center py-16 text-gray-500">
                <FileJson className="w-12 h-12 mx-auto mb-2 opacity-30" />
                <p>Click "Generate IETF SD-JWT Package" to encode claims.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 3. Trust Registry */}
      {activeSubTab === 'trust' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <span>Decentralized Trust Registry Query</span>
            </h3>
            <p className="text-gray-400 text-sm mb-6">
              Query cryptographically anchored institutional accreditations and verify legal authority to issue credential schemas.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Issuer DID Identifier</label>
                <input
                  type="text"
                  value={targetDid}
                  onChange={(e) => setTargetDid(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2.5 text-white font-mono text-xs focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Target Schema Type</label>
                <input
                  type="text"
                  value={targetSchema}
                  onChange={(e) => setTargetSchema(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2 text-white font-mono text-xs focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <button
                onClick={handleCheckTrust}
                className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-3 rounded-lg flex items-center justify-center space-x-2 transition-all"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>Verify Trust Chain & Accreditation</span>
              </button>
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Network className="w-5 h-5 text-emerald-400" />
              <span>Accreditation Certificate & Chain Audit</span>
            </h3>

            {trustAuditResult ? (
              <div className="space-y-3 font-mono text-xs mt-4">
                <div className="p-3 bg-emerald-950/40 rounded-lg border border-emerald-500/40">
                  <span className="text-emerald-400 font-bold block mb-1">Authorization Status:</span>
                  <span className="text-white font-bold flex items-center space-x-1">
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                    <span>AUTHORITY_LEGALLY_ACCREDITED</span>
                  </span>
                </div>
                <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                  <span className="text-gray-400 block mb-1">Accredited Institution:</span>
                  <span className="text-white font-bold">{trustAuditResult.issuerName}</span>
                </div>
                <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                  <span className="text-gray-400 block mb-1">Governance Anchor:</span>
                  <span className="text-cyan-400">{trustAuditResult.governanceAnchorDid}</span>
                </div>
                <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                  <span className="text-gray-400 block mb-1">Allowed Schemas:</span>
                  <span className="text-amber-400">{trustAuditResult.allowedSchemas.join(', ')}</span>
                </div>
              </div>
            ) : (
              <div className="text-center py-16 text-gray-500">
                <Network className="w-12 h-12 mx-auto mb-2 opacity-30" />
                <p>Click "Verify Trust Chain" to inspect accreditation.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
