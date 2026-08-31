import React, { useState, useEffect } from 'react';
import { Network, Code2, Copy, Download, CheckCircle2, GitMerge, Layers, RefreshCw, ArrowRight } from 'lucide-react';

export default function UniversalVerifierStudio() {
  const [contractName, setContractName] = useState('DocuTrustUniversalVerifier');
  const [solidityVersion, setSolidityVersion] = useState('^0.8.20');
  const [copied, setCopied] = useState(false);
  const [generatedSolidity, setGeneratedSolidity] = useState('');

  const [relayerKey, setRelayerKey] = useState({
    publicKeyHex: 'f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2',
    privateKeyHex: '2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c',
    did: 'did:key:z6MkuRelayerStateSync2026MasterNode'
  });

  const [baseStateJson, setBaseStateJson] = useState(() => JSON.stringify({
    'did:key:z6MkuIssuerAlpha': {
      entityDid: 'did:key:z6MkuIssuerAlpha',
      status: 'ACTIVE',
      accreditationLevel: 3,
      updatedEpoch: 1772410000,
      metadataHash: 'a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef'
    }
  }, null, 2));

  const [targetStateJson, setTargetStateJson] = useState(() => JSON.stringify({
    'did:key:z6MkuIssuerAlpha': {
      entityDid: 'did:key:z6MkuIssuerAlpha',
      status: 'ACTIVE',
      accreditationLevel: 3,
      updatedEpoch: 1772410000,
      metadataHash: 'a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef'
    },
    'did:key:z6MkuIssuerBeta': {
      entityDid: 'did:key:z6MkuIssuerBeta',
      status: 'ACTIVE',
      accreditationLevel: 2,
      updatedEpoch: 1772410500,
      metadataHash: 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321'
    }
  }, null, 2));

  const [deltaProof, setDeltaProof] = useState(null);
  const [syncResult, setSyncResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchSolidity = async () => {
    try {
      const res = await fetch('/api/v1/solidity/export-universal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contractName,
          solidityVersion
        })
      });
      const data = await res.json();
      if (data.soliditySource) {
        setGeneratedSolidity(data.soliditySource);
      }
    } catch (e) {
      // Fallback
      setGeneratedSolidity(`// SPDX-License-Identifier: Apache-2.0\npragma solidity ${solidityVersion};\n\ncontract ${contractName} {\n    // Universal Verifier Contract (Groth16, SMT-256, Merkle, Bridge)\n}`);
    }
  };

  useEffect(() => {
    fetchSolidity();
  }, [contractName, solidityVersion]);

  const handleCopyCode = () => {
    navigator.clipboard.writeText(generatedSolidity);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadSol = () => {
    const blob = new Blob([generatedSolidity], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${contractName}.sol`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleGenerateDelta = async () => {
    setLoading(true);
    try {
      const baseState = JSON.parse(baseStateJson);
      const targetState = JSON.parse(targetStateJson);

      const res = await fetch('/api/v1/statesync/delta', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          baseState,
          targetState,
          relayerKeyPair: relayerKey,
          options: {
            source: 'EVM:Ethereum',
            destination: 'Sovereign:Mesh'
          }
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to generate delta proof');
      setDeltaProof(data.deltaProof);
      setSyncResult(null);
    } catch (e) {
      alert(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyDelta = async () => {
    if (!deltaProof) return;
    try {
      const baseState = JSON.parse(baseStateJson);
      const res = await fetch('/api/v1/statesync/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          baseState,
          deltaProof,
          relayerPublicKey: relayerKey.publicKeyHex
        })
      });

      const data = await res.json();
      setSyncResult(data);
    } catch (e) {
      setSyncResult({ valid: false, errors: [e.message] });
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
              v12.0.0 Sovereign Interop
            </span>
            <span className="text-gray-400 text-xs font-mono">DocuTrustUniversalVerifier.sol</span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Network className="w-8 h-8 text-cyan-400" />
            Cross-Ledger StateSync & Master Universal Verifier
          </h1>
          <p className="text-gray-400 text-sm mt-1 max-w-3xl">
            Synchronize decentralized sovereign registries across chains with compact $O(\Delta)$ delta proofs and verify Merkle, SMT-256, Cross-Chain Bridge Quorum, and BN254 Groth16 pairings in a single master Solidity smart contract.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: StateSync Delta Proof Generator */}
        <div className="lg:col-span-6 space-y-6">
          <div className="bg-gray-900/60 border border-gray-800/80 rounded-2xl p-6 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <GitMerge className="w-4 h-4 text-cyan-400" />
                Cross-Ledger State Delta Engine
              </h3>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Base Registry State (Origin)</label>
                <textarea
                  rows={4}
                  value={baseStateJson}
                  onChange={(e) => setBaseStateJson(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl p-2.5 text-[11px] font-mono text-gray-300 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Target Registry State (Updated Replica)</label>
                <textarea
                  rows={4}
                  value={targetStateJson}
                  onChange={(e) => setTargetStateJson(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl p-2.5 text-[11px] font-mono text-gray-300 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex gap-3">
                <button
                  onClick={handleGenerateDelta}
                  disabled={loading}
                  className="flex-1 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs rounded-xl shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <GitMerge className="w-4 h-4" />
                  {loading ? 'Computing...' : 'Compute O(Δ) Proof'}
                </button>
                {deltaProof && (
                  <button
                    onClick={handleVerifyDelta}
                    className="px-4 py-2.5 bg-gray-800 hover:bg-gray-700 text-cyan-300 border border-gray-700 text-xs font-medium rounded-xl flex items-center gap-1.5 cursor-pointer"
                  >
                    Reconcile & Verify
                  </button>
                )}
              </div>
            </div>

            {deltaProof && (
              <div className="mt-4 pt-4 border-t border-gray-800/80">
                <span className="text-xs font-semibold text-gray-300 block mb-2">Generated Delta Proof</span>
                <pre className="bg-gray-950 p-3 rounded-xl text-[10px] font-mono text-gray-300 border border-gray-800 overflow-x-auto max-h-36">
                  {JSON.stringify(deltaProof, null, 2)}
                </pre>
              </div>
            )}

            {syncResult && (
              <div className={`mt-3 p-3 rounded-xl border flex items-center justify-between text-xs ${
                syncResult.valid ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-red-500/10 border-red-500/30 text-red-300'
              }`}>
                <div className="flex items-center gap-2">
                  {syncResult.valid ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Layers className="w-4 h-4 text-red-400" />}
                  <span>{syncResult.valid ? `State Reconciled to Root: ${syncResult.reconciledTargetRoot?.slice(0, 16)}...` : `Reconciliation Failed: ${syncResult.errors?.join(', ') || 'Verification error'}`}</span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Master Universal Solidity Smart Contract Generator */}
        <div className="lg:col-span-6 space-y-6">
          <div className="bg-gray-900/60 border border-gray-800/80 rounded-2xl p-6 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Code2 className="w-4 h-4 text-indigo-400" />
                DocuTrustUniversalVerifier.sol (Master EVM Verifier)
              </h3>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyCode}
                  className="px-2.5 py-1 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-xs font-medium flex items-center gap-1 border border-gray-700 cursor-pointer"
                >
                  {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
                <button
                  onClick={handleDownloadSol}
                  className="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded-lg text-xs font-medium flex items-center gap-1 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download .sol
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 mb-4">
              <div>
                <label className="block text-[10px] font-mono text-gray-400 mb-1">Contract Name</label>
                <input
                  type="text"
                  value={contractName}
                  onChange={(e) => setContractName(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-gray-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-[10px] font-mono text-gray-400 mb-1">Solidity Pragma</label>
                <input
                  type="text"
                  value={solidityVersion}
                  onChange={(e) => setSolidityVersion(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-gray-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <pre className="bg-gray-950 p-4 rounded-xl text-[10px] font-mono text-emerald-300 border border-gray-800/80 overflow-x-auto max-h-96 leading-relaxed">
              {generatedSolidity || '// Loading Master Universal Verifier Solidity contract...'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
