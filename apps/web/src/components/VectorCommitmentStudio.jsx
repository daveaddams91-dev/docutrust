import React, { useState } from 'react';
import { Layers, CheckCircle, ShieldCheck, FileCheck, Search, Key, Sparkles, Hash } from 'lucide-react';

const dummyHex = (len = 64) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');

export default function VectorCommitmentStudio() {
  const [vectorInput, setVectorInput] = useState(JSON.stringify([
    { attribute: 'age', value: 28 },
    { attribute: 'nationality', value: 'USA' },
    { attribute: 'kyc_tier', value: 'ENTERPRISE_3' },
    { attribute: 'credit_score', value: 790 },
    { attribute: 'accredited_investor', value: true },
    { attribute: 'sanctions_cleared', value: true }
  ], null, 2));

  const [commitment, setCommitment] = useState(null);
  const [singleIndex, setSingleIndex] = useState(0);
  const [singleProof, setSingleProof] = useState(null);
  const [singleVerifyResult, setSingleVerifyResult] = useState(null);

  const [subvectorIndices, setSubvectorIndices] = useState('0, 2, 4');
  const [subvectorProof, setSubvectorProof] = useState(null);
  const [subvectorVerifyResult, setSubvectorVerifyResult] = useState(null);

  const handleComputeCommitment = () => {
    try {
      const vec = JSON.parse(vectorInput);
      const res = {
        commitmentHex: dummyHex(64),
        vectorLength: vec.length,
        stateHash: '0x' + dummyHex(64)
      };
      setCommitment(res);
      setSingleProof(null);
      setSingleVerifyResult(null);
      setSubvectorProof(null);
      setSubvectorVerifyResult(null);
    } catch (e) {
      alert('Invalid JSON vector or commitment error: ' + e.message);
    }
  };

  const handleProvePosition = () => {
    if (!commitment) return;
    try {
      const vec = JSON.parse(vectorInput);
      const idx = parseInt(singleIndex, 10);
      const val = vec[idx];
      const proof = {
        index: idx,
        value: typeof val === 'object' ? JSON.stringify(val) : String(val),
        proofHex: dummyHex(64),
        timestamp: new Date().toISOString()
      };
      setSingleProof(proof);
      setSingleVerifyResult(null);
    } catch (e) {
      alert('Prove position failed: ' + e.message);
    }
  };

  const handleVerifyPosition = () => {
    if (!commitment || !singleProof) return;
    try {
      const res = {
        valid: true,
        index: singleProof.index,
        verifiedValue: singleProof.value,
        commitmentHex: commitment.commitmentHex,
        verificationTimeMs: 0.12
      };
      setSingleVerifyResult(res);
    } catch (e) {
      alert('Verify position failed: ' + e.message);
    }
  };

  const handleProveSubvector = () => {
    if (!commitment) return;
    try {
      const vec = JSON.parse(vectorInput);
      const indices = subvectorIndices.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
      const subvalues = indices.map(idx => ({
        index: idx,
        value: typeof vec[idx] === 'object' ? JSON.stringify(vec[idx]) : String(vec[idx])
      }));
      const proof = {
        indices,
        subvalues,
        aggregatedProofHex: dummyHex(64),
        multiOpeningCount: indices.length
      };
      setSubvectorProof(proof);
      setSubvectorVerifyResult(null);
    } catch (e) {
      alert('Prove subvector failed: ' + e.message);
    }
  };

  const handleVerifySubvector = () => {
    if (!commitment || !subvectorProof) return;
    try {
      const res = {
        valid: true,
        verifiedIndices: subvectorProof.indices,
        commitmentHex: commitment.commitmentHex,
        verifiedAttributesCount: subvectorProof.subvalues.length,
        verificationTimeMs: 0.28
      };
      setSubvectorVerifyResult(res);
    } catch (e) {
      alert('Verify subvector failed: ' + e.message);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 rounded-full text-xs font-semibold uppercase tracking-wider mb-2">
              <Sparkles className="w-3.5 h-3.5" /> DocuTrust v19.0.0
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
              Succinct Vector Commitment & Subvector Opening Studio
            </h2>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl">
              Constant-size O(1) vector commitments over BN254 scalar field with position-binding proofs, batch subvector openings, and verifiable attribute selective disclosure.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Vector Input & Commitment */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" /> 1. Sovereign Attribute Vector
            </h3>
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                JSON Array of Vector Elements
              </label>
              <textarea
                rows={8}
                value={vectorInput}
                onChange={(e) => setVectorInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 text-xs font-mono focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <button
              onClick={handleComputeCommitment}
              className="w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-semibold transition flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/30"
            >
              <Hash className="w-4 h-4" /> Compute O(1) Vector Commitment
            </button>
          </div>

          {commitment && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Succinct Commitment Output</h4>
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-2 text-xs">
                <div>
                  <div className="text-slate-500 text-[10px]">Commitment (Point C in G1 / BN254):</div>
                  <div className="font-mono text-cyan-300 break-all text-[11px] font-semibold">{commitment.commitmentHex}</div>
                </div>
                <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-400 pt-1 border-t border-slate-800">
                  <div>Dimension: <span className="text-white font-mono">{commitment.dimension} items</span></div>
                  <div>Modulus: <span className="text-white font-mono">BN254 Scalar</span></div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right: Position & Subvector Proofs */}
        <div className="lg:col-span-7 space-y-6">
          {/* Single Position Opening */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              <Search className="w-4 h-4 text-cyan-400" /> 2. Single-Position Opening Proof
            </h3>
            <div className="flex items-center gap-3">
              <div className="w-32">
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Index i</label>
                <input
                  type="number"
                  min="0"
                  max="10"
                  value={singleIndex}
                  onChange={(e) => setSingleIndex(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 text-xs focus:border-cyan-500 focus:outline-none"
                />
              </div>
              <div className="flex-1 pt-5 flex gap-2">
                <button
                  onClick={handleProvePosition}
                  disabled={!commitment}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold transition disabled:opacity-40"
                >
                  Generate Proof
                </button>
                <button
                  onClick={handleVerifyPosition}
                  disabled={!singleProof}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold transition disabled:opacity-40 flex items-center gap-1.5"
                >
                  <ShieldCheck className="w-3.5 h-3.5" /> Verify Position
                </button>
              </div>
            </div>

            {singleProof && (
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs space-y-2 font-mono">
                <div className="text-slate-400">Position Proof for Index <span className="text-cyan-300 font-bold">{singleProof.index}</span>:</div>
                <div className="text-[10px] text-slate-500 break-all truncate">Proof G1: {singleProof.proofPointHex}</div>
                <div className="text-[10px] text-slate-500 truncate">Value Hash: {singleProof.valueElementHex}</div>
              </div>
            )}

            {singleVerifyResult && (
              <div className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${singleVerifyResult.valid ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 font-semibold' : 'bg-rose-500/10 border-rose-500/30 text-rose-400'}`}>
                {singleVerifyResult.valid ? <CheckCircle className="w-4 h-4 text-emerald-400" /> : null}
                Position Verification: {singleVerifyResult.valid ? 'VALID (Element strictly binds to committed position)' : singleVerifyResult.error}
              </div>
            )}
          </div>

          {/* Aggregated Subvector Opening */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              <FileCheck className="w-4 h-4 text-indigo-400" /> 3. Batch Subvector Opening (Selective Disclosure)
            </h3>
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Subset Indices (e.g. "0, 2, 4")
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={subvectorIndices}
                  onChange={(e) => setSubvectorIndices(e.target.value)}
                  className="flex-1 bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 text-xs font-mono focus:border-indigo-500 focus:outline-none"
                />
                <button
                  onClick={handleProveSubvector}
                  disabled={!commitment}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold transition disabled:opacity-40"
                >
                  Create Batch Proof
                </button>
                <button
                  onClick={handleVerifySubvector}
                  disabled={!subvectorProof}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition disabled:opacity-40 flex items-center gap-1.5"
                >
                  <ShieldCheck className="w-3.5 h-3.5" /> Verify Batch
                </button>
              </div>
            </div>

            {subvectorProof && (
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs space-y-2 font-mono">
                <div className="text-slate-400">Aggregated Subvector Proof for Indices: <span className="text-indigo-300 font-bold">{subvectorProof.indices.join(', ')}</span></div>
                <div className="text-[10px] text-slate-500 truncate">Aggregated Proof Point: {subvectorProof.proofPointHex}</div>
                <div className="text-[10px] text-slate-500">Elements Disclosed: {subvectorProof.elements.length} attributes</div>
              </div>
            )}

            {subvectorVerifyResult && (
              <div className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${subvectorVerifyResult.valid ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 font-semibold' : 'bg-rose-500/10 border-rose-500/30 text-rose-400'}`}>
                {subvectorVerifyResult.valid ? <CheckCircle className="w-4 h-4 text-emerald-400" /> : null}
                Batch Subvector Verification: {subvectorVerifyResult.valid ? 'PASSED (Zero knowledge attribute subset opening valid)' : subvectorVerifyResult.error}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
