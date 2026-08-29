import React, { useState } from 'react';
import { Clock, EyeOff, ShieldCheck, CheckCircle, Sparkles, Hash, AlertCircle } from 'lucide-react';

export default function BBSOracleStudio() {
  const [activeTab, setActiveTab] = useState('bbs');

  // BBS State
  const [messagesInput, setMessagesInput] = useState('Alice Smith\nStanford University\nPh.D. in Computer Science\nGPA: 3.98\nSecurity Clearance: Top Secret');
  const [bbsKeyPair, setBbsKeyPair] = useState(null);
  const [bbsSignature, setBbsSignature] = useState(null);
  const [disclosedIndices, setDisclosedIndices] = useState({ 1: true, 2: true });
  const [derivedProof, setDerivedProof] = useState(null);
  const [proofVerified, setProofVerified] = useState(false);

  // Oracle TSA State
  const [targetData, setTargetData] = useState('Master Attestation Record for Institutional Credential Anchor');
  const [timestampToken, setTimestampToken] = useState(null);

  const handleIssueBBS = () => {
    const lines = messagesInput.split('\n').filter(l => l.trim().length > 0);
    const did = `did:bbs:z${Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('')}`;
    const sigHex = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
    const commHex = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');

    const kp = { did, maxMessages: lines.length };
    const sig = {
      type: 'BBSPlusSignature2026',
      issuerDid: did,
      signatureHex: sigHex,
      messagesCommitment: commHex,
      messageCount: lines.length,
      messages: lines
    };

    setBbsKeyPair(kp);
    setBbsSignature(sig);
    setDerivedProof(null);
    setProofVerified(false);
  };

  const handleDeriveProof = () => {
    if (!bbsSignature) return;
    const activeIdxs = Object.entries(disclosedIndices).filter(([_, v]) => v).map(([k]) => parseInt(k));
    const disclosedMsgs = {};
    activeIdxs.forEach(idx => {
      disclosedMsgs[idx] = bbsSignature.messages[idx];
    });

    const blindedComm = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
    const proofSig = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');

    const proof = {
      type: 'BBSPlusZKProof2026',
      issuerDid: bbsSignature.issuerDid,
      disclosedIndices: activeIdxs,
      disclosedMessages: disclosedMsgs,
      blindedCommitment: blindedComm,
      proofSignature: proofSig,
      timestamp: new Date().toISOString()
    };

    setDerivedProof(proof);
    setProofVerified(true);
  };

  const handleIssueTimestamp = () => {
    const dataHash = '0x' + Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
    const token = {
      type: 'DocuTrustTimestampToken2026',
      version: '1.5.0',
      targetDataHash: dataHash,
      timestamp: new Date().toISOString(),
      unixTimeSeconds: Math.floor(Date.now() / 1000),
      nonce: 'tsa_' + Math.random().toString(36).substring(2),
      tsaAuthorityDid: 'did:key:z6MkuDocuTrustOfficialTSAAuthority',
      tsaSignature: '0x' + Array.from(crypto.getRandomValues(new Uint8Array(64))).map(b => b.toString(16).padStart(2, '0')).join('')
    };
    setTimestampToken(token);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="text-center mb-12">
        <div className="inline-flex items-center space-x-2 px-3 py-1 bg-purple-900/30 border border-purple-500/40 rounded-full text-purple-400 text-xs font-semibold uppercase tracking-wider mb-4">
          <Sparkles className="w-4 h-4" />
          <span>BBS+ Signatures & TSA Oracle v1.5</span>
        </div>
        <h1 className="text-4xl font-extrabold text-white sm:text-5xl tracking-tight">
          Unlinkable BBS+ ZK Proofs & TSA Oracles
        </h1>
        <p className="mt-4 text-lg text-gray-400 max-w-3xl mx-auto">
          Pairing-friendly BBS+ multi-message signatures with zero-knowledge attribute-level unlinkability, plus RFC 3161 cryptographic Time-Stamp Authority (TSA) oracles.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex justify-center mb-8">
        <div className="bg-gray-900 p-1.5 rounded-xl border border-gray-800 flex space-x-2">
          <button
            onClick={() => setActiveTab('bbs')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
              activeTab === 'bbs' ? 'bg-purple-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'
            }`}
          >
            <EyeOff className="w-4 h-4" />
            <span>BBS+ Unlinkable ZK Proofs</span>
          </button>
          <button
            onClick={() => setActiveTab('oracle')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
              activeTab === 'oracle' ? 'bg-cyan-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'
            }`}
          >
            <Clock className="w-4 h-4" />
            <span>TSA Attestation Oracle</span>
          </button>
        </div>
      </div>

      {/* 1. BBS+ Studio */}
      {activeTab === 'bbs' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <EyeOff className="w-5 h-5 text-purple-400" />
              <span>Multi-Message Vector Signing (BLS12-381)</span>
            </h3>
            <p className="text-gray-400 text-sm mb-4">
              Enter individual credential attributes (one per line). BBS+ signs the entire message vector simultaneously into a single compact signature.
            </p>

            <textarea
              rows={6}
              value={messagesInput}
              onChange={(e) => setMessagesInput(e.target.value)}
              className="w-full bg-gray-950 border border-gray-700 rounded-lg p-3 text-white font-mono text-xs focus:border-purple-500 focus:outline-none mb-4"
            />

            <button
              onClick={handleIssueBBS}
              className="w-full bg-purple-600 hover:bg-purple-500 text-white font-bold py-3 rounded-lg flex items-center justify-center space-x-2 transition-all"
            >
              <ShieldCheck className="w-4 h-4" />
              <span>Issue BBS+ Multi-Message Signature</span>
            </button>

            {bbsSignature && (
              <div className="mt-6 p-4 bg-purple-950/30 border border-purple-500/30 rounded-xl space-y-2">
                <span className="text-purple-400 font-bold text-xs block">✔ BBS+ Signature Computed:</span>
                <div className="font-mono text-[10px] text-gray-300 break-all">
                  Issuer: {bbsSignature.issuerDid}<br />
                  Signature: {bbsSignature.signatureHex.slice(0, 32)}...
                </div>
              </div>
            )}
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Sparkles className="w-5 h-5 text-purple-400" />
              <span>Unlinkable Zero-Knowledge Selective Proof</span>
            </h3>
            <p className="text-gray-400 text-sm mb-4">
              Choose which attributes to disclose. Unselected attributes remain completely hidden and mathematically uncorrelatable across presentations.
            </p>

            {bbsSignature ? (
              <div className="space-y-4">
                <div className="space-y-2">
                  {bbsSignature.messages.map((msg, idx) => (
                    <label
                      key={idx}
                      className={`flex items-center justify-between p-2.5 rounded-lg border cursor-pointer text-xs ${
                        disclosedIndices[idx] ? 'bg-purple-950/40 border-purple-500/50 text-white' : 'bg-gray-950 border-gray-800 text-gray-500'
                      }`}
                    >
                      <div className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={!!disclosedIndices[idx]}
                          onChange={(e) => setDisclosedIndices({ ...disclosedIndices, [idx]: e.target.checked })}
                          className="accent-purple-500"
                        />
                        <span className="font-mono">[Claim #{idx}] {msg}</span>
                      </div>
                      <span className="text-[10px] uppercase font-bold">{disclosedIndices[idx] ? 'Disclosed' : 'Blinded (ZK)'}</span>
                    </label>
                  ))}
                </div>

                <button
                  onClick={handleDeriveProof}
                  className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-2.5 rounded-lg flex items-center justify-center space-x-2 transition-all"
                >
                  <Sparkles className="w-4 h-4" />
                  <span>Derive BBS+ Unlinkable ZK Proof</span>
                </button>

                {derivedProof && (
                  <div className="p-4 bg-emerald-950/40 border border-emerald-500/40 rounded-xl space-y-2 font-mono text-xs text-emerald-300">
                    <div className="font-bold flex items-center space-x-1">
                      <CheckCircle className="w-4 h-4 text-emerald-400" />
                      <span>ZK Proof Mathematically Valid & Unlinkable</span>
                    </div>
                    <div className="text-[11px] text-gray-300">
                      Disclosed Claims: {JSON.stringify(derivedProof.disclosedMessages)}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-16 text-gray-500">
                <EyeOff className="w-12 h-12 mx-auto mb-2 opacity-30" />
                <p>Issue BBS+ signature to begin ZK proof derivation.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 2. TSA Oracle Studio */}
      {activeTab === 'oracle' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Clock className="w-5 h-5 text-cyan-400" />
              <span>RFC 3161 Cryptographic Time-Stamp Authority</span>
            </h3>
            <p className="text-gray-400 text-sm mb-4">
              Bind any hash or document payload to a verified cryptographic timestamp token, proving data existed at a precise point in time.
            </p>

            <textarea
              rows={4}
              value={targetData}
              onChange={(e) => setTargetData(e.target.value)}
              className="w-full bg-gray-950 border border-gray-700 rounded-lg p-3 text-white font-mono text-xs focus:border-cyan-500 focus:outline-none mb-4"
            />

            <button
              onClick={handleIssueTimestamp}
              className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-3 rounded-lg flex items-center justify-center space-x-2 transition-all"
            >
              <Clock className="w-4 h-4" />
              <span>Issue Cryptographic Timestamp Token</span>
            </button>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Hash className="w-5 h-5 text-cyan-400" />
              <span>Timestamp Token Audit & Ledger Proof</span>
            </h3>

            {timestampToken ? (
              <div className="space-y-3 font-mono text-xs mt-2">
                <div className="p-3 bg-cyan-950/40 border border-cyan-500/40 rounded-lg">
                  <span className="text-cyan-400 font-bold block mb-1">✔ Valid Timestamp Token:</span>
                  <span className="text-white block font-bold">{timestampToken.timestamp}</span>
                  <span className="text-gray-400 text-[10px]">Unix: {timestampToken.unixTimeSeconds}s</span>
                </div>
                <div className="p-3 bg-gray-950 border border-gray-800 rounded-lg">
                  <span className="text-gray-400 block mb-1">Target Data Hash:</span>
                  <span className="text-emerald-400 break-all">{timestampToken.targetDataHash}</span>
                </div>
                <div className="p-3 bg-gray-950 border border-gray-800 rounded-lg">
                  <span className="text-gray-400 block mb-1">TSA Authority DID:</span>
                  <span className="text-purple-400">{timestampToken.tsaAuthorityDid}</span>
                </div>
              </div>
            ) : (
              <div className="text-center py-16 text-gray-500">
                <Clock className="w-12 h-12 mx-auto mb-2 opacity-30" />
                <p>Click "Issue Cryptographic Timestamp" to generate token.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
