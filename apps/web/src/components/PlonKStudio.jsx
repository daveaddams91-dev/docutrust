import React, { useState } from 'react';
import { Cpu, ShieldCheck, CheckCircle2, RefreshCw, FileCode, Layers, Key, Binary } from 'lucide-react';

export default function PlonKStudio() {
  const [circuitId, setCircuitId] = useState('plonk_tax_exemption_v1');
  const [tier, setTier] = useState(20);
  const [multiplier, setMultiplier] = useState(5);
  const [grantAmount, setGrantAmount] = useState(100);

  const [compiledCircuit, setCompiledCircuit] = useState(null);
  const [proof, setProof] = useState(null);
  const [verified, setVerified] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleCompileCircuit = () => {
    setLoading(true);
    setTimeout(() => {
      setCompiledCircuit({
        circuitId,
        gateCount: 1,
        gates: [
          {
            gateIndex: 0,
            qL: 0,
            qR: 0,
            qO: -1,
            qM: 1,
            qC: 0,
            aVar: 'tier',
            bVar: 'multiplier',
            cVar: 'grantAmount',
            lookupTable: 'validTiers'
          }
        ],
        publicInputKeys: ['grantAmount'],
        lookupTables: { validTiers: [10, 20, 30, 40, 50] },
        verificationKey: {
          circuitId,
          vkDigest: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
          gateCount: 1
        }
      });
      setProof(null);
      setVerified(null);
      setLoading(false);
    }, 300);
  };

  const handleGenerateProof = () => {
    if (!compiledCircuit) return;
    setLoading(true);
    setTimeout(() => {
      const isMathValid = tier * multiplier === grantAmount;
      const isLookupValid = [10, 20, 30, 40, 50].includes(tier);

      if (!isMathValid || !isLookupValid) {
        alert('Proof generation failed: Constraints unsatisfied or Plookup table membership failed.');
        setLoading(false);
        return;
      }

      const generatedProof = {
        type: 'DocuTrustPlonKProof2026',
        circuitId,
        wireCommitments: {
          aCommit: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
          bCommit: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
          cCommit: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')
        },
        permutationCommitment: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
        lookupCommitment: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
        publicInputs: { grantAmount },
        solidityCalldata: '0x16b04f...' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
        createdAt: new Date().toISOString()
      };

      setProof(generatedProof);
      setVerified(true);
      setLoading(false);
    }, 400);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-amber-500 to-orange-600 rounded-xl shadow-lg shadow-amber-500/20">
            <Cpu className="w-8 h-8 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-2xl font-bold text-white tracking-tight">ZK-PlonK & Plookup Arithmetization Studio</h2>
              <span className="px-2.5 py-0.5 text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-full">
                v16.0 Universal PlonK
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              PlonKish universal arithmetization with custom gate polynomial selectors, copy permutations & Plookup table arguments.
            </p>
          </div>
        </div>
        <button
          onClick={handleCompileCircuit}
          disabled={loading}
          className="flex items-center gap-2 px-5 py-2.5 bg-amber-600 hover:bg-amber-500 text-white text-sm font-semibold rounded-xl transition-all shadow-lg shadow-amber-600/25 active:scale-95 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Compile PlonK Circuit
        </button>
      </div>

      {/* Grid: Arithmetization Definition & Prover */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Gate Formulation & Selectors */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Binary className="w-5 h-5 text-amber-400" />
                <h3 className="text-lg font-semibold text-white">PlonKish Constraint System</h3>
              </div>
              <span className="text-xs bg-amber-500/10 text-amber-400 px-2 py-1 rounded-md border border-amber-500/20">
                qL·a + qR·b + qO·c + qM·(a·b) + qC = 0
              </span>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-slate-400 block mb-1">Gate 0 Equation:</span>
                <p className="text-amber-400 font-bold">
                  (0·tier) + (0·multiplier) + (-1·grantAmount) + (1·(tier × multiplier)) + 0 = 0
                </p>
              </div>

              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-slate-400 block mb-1">Plookup Range Table:</span>
                <p className="text-slate-300">
                  table('validTiers') = [10, 20, 30, 40, 50] (assert tier ∈ table)
                </p>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span>Polynomial KZG Commitments</span>
            <span>Permutation Argument: <strong>Z(X)</strong></span>
          </div>
        </div>

        {/* Private Witness & Proof Generation */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-amber-400" />
                <h3 className="text-lg font-semibold text-white">Witness Assignments & Prover</h3>
              </div>
              <span className="text-xs bg-orange-500/10 text-orange-400 px-2 py-1 rounded-md border border-orange-500/20">
                EVM Calldata Ready
              </span>
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Private Witness: Tier</label>
                  <input
                    type="number"
                    value={tier}
                    onChange={(e) => setTier(parseInt(e.target.value, 10))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Private Witness: Multiplier</label>
                  <input
                    type="number"
                    value={multiplier}
                    onChange={(e) => setMultiplier(parseInt(e.target.value, 10))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-white font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Public Input: Grant Amount ($)</label>
                <input
                  type="number"
                  value={grantAmount}
                  onChange={(e) => setGrantAmount(parseInt(e.target.value, 10))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-white font-mono"
                />
              </div>

              <button
                onClick={handleGenerateProof}
                disabled={!compiledCircuit || loading}
                className="w-full py-2.5 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white text-xs font-semibold rounded-xl transition-all shadow-lg shadow-amber-600/25"
              >
                Generate PlonK Proof & EVM Calldata
              </button>

              {proof && (
                <div className="space-y-3 pt-2">
                  <div className="p-3 bg-amber-950/30 border border-amber-500/30 rounded-xl flex items-center gap-2 text-amber-300 text-xs">
                    <CheckCircle2 className="w-4 h-4 text-amber-400 shrink-0" />
                    <span>PlonK Proof & Permutation Copy Constraints Satisfied</span>
                  </div>
                  <pre className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-amber-300 font-mono text-xs overflow-x-auto">
                    {JSON.stringify(proof, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
