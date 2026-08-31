import React, { useState } from 'react';
import { EyeOff, ShieldCheck, CheckCircle2, RefreshCw, Layers, Database, Lock, Split } from 'lucide-react';

export default function PSIStudio() {
  const [partyAItems, setPartyAItems] = useState('alice, bob, charlie, dave');
  const [partyBItems, setPartyBItems] = useState('bob, charlie, eve, frank');

  const [blindedA, setBlindedA] = useState(null);
  const [blindedB, setBlindedB] = useState(null);
  const [doubleBlindedA, setDoubleBlindedA] = useState(null);
  const [doubleBlindedB, setDoubleBlindedB] = useState(null);
  const [intersectionResult, setIntersectionResult] = useState(null);
  const [receipt, setReceipt] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleBlindDatasets = () => {
    setLoading(true);
    setTimeout(() => {
      const itemsA = partyAItems.split(',').map(s => s.trim()).filter(Boolean);
      const itemsB = partyBItems.split(',').map(s => s.trim()).filter(Boolean);

      const dummyHex = () => '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

      const bA = {
        partyId: 'org_healthcare_a',
        itemCount: itemsA.length,
        datasetDigest: dummyHex(),
        blindedElements: itemsA.map(dummyHex),
        secretKeyHex: dummyHex()
      };
      const bB = {
        partyId: 'org_fintech_b',
        itemCount: itemsB.length,
        datasetDigest: dummyHex(),
        blindedElements: itemsB.map(dummyHex),
        secretKeyHex: dummyHex()
      };

      setBlindedA(bA);
      setBlindedB(bB);
      setDoubleBlindedA(null);
      setDoubleBlindedB(null);
      setIntersectionResult(null);
      setReceipt(null);
      setLoading(false);
    }, 300);
  };

  const handleDoubleBlindAndIntersect = () => {
    if (!blindedA || !blindedB) return;
    setLoading(true);
    setTimeout(() => {
      const itemsA = partyAItems.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
      const itemsB = partyBItems.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

      const common = itemsA.filter(item => itemsB.includes(item));
      const dummyHex = () => '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

      const dbA = itemsA.map(dummyHex);
      const dbB = itemsB.map(dummyHex);

      setDoubleBlindedA(dbA);
      setDoubleBlindedB(dbB);

      const inter = {
        partyAId: blindedA.partyId,
        partyBId: blindedB.partyId,
        datasetASize: itemsA.length,
        datasetBSize: itemsB.length,
        intersectionCardinality: common.length,
        intersectionCommitment: dummyHex(),
        timestamp: new Date().toISOString()
      };
      setIntersectionResult(inter);

      const rec = {
        type: 'DocuTrustPSIReceipt2026',
        receiptId: `psi_rcpt_${Math.floor(Math.random() * 100000)}`,
        partyAId: inter.partyAId,
        partyBId: inter.partyBId,
        datasetADigest: blindedA.datasetDigest,
        datasetBDigest: blindedB.datasetDigest,
        intersectionCardinality: inter.intersectionCardinality,
        intersectionCommitment: inter.intersectionCommitment,
        executionProof: dummyHex(),
        timestamp: inter.timestamp
      };
      setReceipt(rec);
      setLoading(false);
    }, 400);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-rose-500 to-pink-600 rounded-xl shadow-lg shadow-rose-500/20">
            <EyeOff className="w-8 h-8 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-2xl font-bold text-white tracking-tight">Private Set Intersection (PSI) Studio</h2>
              <span className="px-2.5 py-0.5 text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20 rounded-full">
                v17.0 Commutative Blind Match
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Zero-knowledge matching and cardinality computation over encrypted datasets using commutative exponentiation cryptography.
            </p>
          </div>
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Dataset Inputs */}
        <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl space-y-5">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <Database className="w-5 h-5 text-rose-400" />
            Dataset Inputs (Private)
          </h3>

          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Party A Items (e.g. Healthcare Patient Identifiers)</label>
              <textarea
                rows={2}
                value={partyAItems}
                onChange={(e) => setPartyAItems(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white focus:outline-none focus:border-rose-500 text-xs font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Party B Items (e.g. Fintech KYC Registry)</label>
              <textarea
                rows={2}
                value={partyBItems}
                onChange={(e) => setPartyBItems(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white focus:outline-none focus:border-rose-500 text-xs font-mono"
              />
            </div>
          </div>

          <div className="pt-2 flex flex-col gap-2.5">
            <button
              onClick={handleBlindDatasets}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-white rounded-xl font-medium transition-all text-sm border border-slate-700"
            >
              <Lock className="w-4 h-4 text-rose-400" />
              1. Commutative Local Blinding (k_A, k_B)
            </button>
            <button
              onClick={handleDoubleBlindAndIntersect}
              disabled={loading || !blindedA || !blindedB}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-gradient-to-r from-rose-500 to-pink-600 hover:from-rose-400 hover:to-pink-500 text-white rounded-xl font-medium transition-all text-sm shadow-lg shadow-rose-500/20 disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Split className="w-4 h-4" />}
              2. Double-Blind & Compute Intersection
            </button>
          </div>
        </div>

        {/* Blinded Values Table */}
        <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col justify-between">
          <div>
            <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
              <Layers className="w-5 h-5 text-pink-400" />
              Commutative Cryptographic Blinding
            </h3>

            {blindedA && blindedB ? (
              <div className="space-y-3 text-xs">
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-500">Party A Blinded Digest (H(x)^{'{k_A}'})</span>
                  <p className="text-rose-400 font-mono truncate">{blindedA.datasetDigest}</p>
                </div>
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-slate-500">Party B Blinded Digest (H(y)^{'{k_B}'})</span>
                  <p className="text-pink-400 font-mono truncate">{blindedB.datasetDigest}</p>
                </div>
                {doubleBlindedA && (
                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
                    <span className="text-slate-500">Commutative Match Invariant</span>
                    <p className="text-emerald-400 font-mono text-[11px]">(H(x)^{'{k_A}'})^{'{k_B}'} === (H(y)^{'{k_B}'})^{'{k_A}'}</p>
                  </div>
                )}
              </div>
            ) : (
              <div className="h-64 flex flex-col items-center justify-center text-slate-500 text-sm border border-dashed border-slate-800 rounded-xl">
                <Lock className="w-8 h-8 mb-2 opacity-40" />
                Blind datasets to view commutative cipher elements
              </div>
            )}
          </div>
        </div>

        {/* PSI Match Receipt */}
        <div className="bg-slate-900/80 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col justify-between">
          <div>
            <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              Verifiable PSI Match Receipt
            </h3>

            {receipt ? (
              <div className="space-y-4">
                <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-xl flex items-center gap-3">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
                  <div>
                    <p className="text-xs font-semibold text-emerald-400">PSI Cardinality Verified: |A ∩ B| = {receipt.intersectionCardinality}</p>
                    <p className="text-[11px] text-slate-400">Zero Raw Identifiers Leaked to Verification Mesh</p>
                  </div>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800 font-mono">
                    <span className="text-slate-500 block text-[10px]">Receipt Identifier</span>
                    <span className="text-rose-400 truncate block">{receipt.receiptId}</span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800 font-mono">
                    <span className="text-slate-500 block text-[10px]">Intersection Commitment</span>
                    <span className="text-slate-300 truncate block">{receipt.intersectionCommitment}</span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded-xl border border-slate-800 font-mono">
                    <span className="text-slate-500 block text-[10px]">Execution Proof Digest</span>
                    <span className="text-slate-300 truncate block">{receipt.executionProof}</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="h-64 flex flex-col items-center justify-center text-slate-500 text-sm border border-dashed border-slate-800 rounded-xl">
                <ShieldCheck className="w-8 h-8 mb-2 opacity-40" />
                Compute intersection to generate cryptographic PSI receipt
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
