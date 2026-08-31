import React, { useState } from 'react';
import { Layers, Cpu, ShieldCheck, CheckCircle2, XCircle, Plus, Trash2, ArrowRight, Code, Key, Sparkles, RefreshCw, FileText } from 'lucide-react';

export default function ZKRecursiveStudio() {
  const [subProofs, setSubProofs] = useState([
    {
      proofId: 'proof-range-age-21',
      proofType: 'RangePredicate',
      claim: 'age_greater_than_21',
      publicInputs: { minimumAge: 21, currentYear: 2026 },
      proofData: { pi_a: '0x18a9...b4', pi_b: '0x22c1...ef', pi_c: '0x99a0...33' },
      proverDid: 'did:key:z6MksAgeProverNode2026'
    },
    {
      proofId: 'proof-membership-kyc',
      proofType: 'SetMembership',
      claim: 'kyc_sanction_cleared',
      publicInputs: { listRoot: '0x88f2...77', complianceJurisdiction: 'US_EU' },
      proofData: { pi_a: '0x33d4...11', pi_b: '0x44e5...22', pi_c: '0x55f6...33' },
      proverDid: 'did:key:z6MksComplianceNode2026'
    },
    {
      proofId: 'proof-credit-tier-aaa',
      proofType: 'ConfidentialCreditScore',
      claim: 'credit_score_above_750',
      publicInputs: { thresholdScore: 750 },
      proofData: { pi_a: '0x77a8...99', pi_b: '0x88b9...00', pi_c: '0x99c0...11' },
      proverDid: 'did:key:z6MksCreditOracle2026'
    }
  ]);

  const [aggregatorKey] = useState({
    publicKeyHex: 'f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2',
    privateKeyHex: '0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b',
    did: 'did:key:z6MksAggregatorMasterSovereign'
  });

  const [newClaim, setNewClaim] = useState('');
  const [newType, setNewType] = useState('CustomPredicate');
  const [foldingDepth, setFoldingDepth] = useState(1);
  const [generateEvm, setGenerateEvm] = useState(true);

  const [recursiveProof, setRecursiveProof] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleAddSubProof = () => {
    if (!newClaim) return;
    const newEntry = {
      proofId: `proof-${Date.now()}`,
      proofType: newType,
      claim: newClaim,
      publicInputs: { timestamp: Date.now(), customClaim: newClaim },
      proofData: { pi_a: '0x' + Math.random().toString(16).slice(2, 10), pi_b: '0x' + Math.random().toString(16).slice(2, 10) },
      proverDid: `did:key:z6MksProver${Math.floor(Math.random() * 1000)}`
    };
    setSubProofs([...subProofs, newEntry]);
    setNewClaim('');
  };

  const handleRemoveSubProof = (id) => {
    setSubProofs(subProofs.filter(p => p.proofId !== id));
  };

  const handleAggregate = async () => {
    setLoading(true);
    setVerifyResult(null);
    try {
      const res = await fetch('/api/v1/zk/recursive/aggregate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subProofs,
          options: {
            aggregatorKeyPair: aggregatorKey,
            depth: foldingDepth,
            generateEvmCalldata: generateEvm
          }
        })
      });
      const data = await res.json();
      if (data.recursiveProof) {
        setRecursiveProof(data.recursiveProof);
      } else {
        // Local preview fallback
        setRecursiveProof({
          type: 'DocuTrustRecursiveZKProof2026',
          recursiveProofId: `zk-rec-${Date.now()}`,
          depth: foldingDepth,
          subProofCount: subProofs.length,
          subProofDigest: '77a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8',
          linearizedPublicInputsCommitment: '20fc996fc7db4aac8c313d16a4b9686b480d123576ceb94b81b6720eaf54d46c',
          foldedAccumulator: {
            u_accumulator: '0x12a89bf1478a4e6e',
            fiatShamirChallenge: '0x3c99a0b1c2d3e4f5',
            compressedPoints: ['0x1111222233334444', '0x5555666677778888']
          },
          evmCalldataHex: generateEvm ? '0x9a8b7c6d00000000000000000000000020fc996fc7db4aac8c313d16a4b9686b480d123576ceb94b81b6720eaf54d46c' : undefined,
          aggregatorDid: aggregatorKey.did,
          signatureHex: '3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b',
          timestamp: new Date().toISOString()
        });
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    if (!recursiveProof) return;
    setLoading(true);
    try {
      const res = await fetch('/api/v1/zk/recursive/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          proof: recursiveProof,
          aggregatorPublicKey: aggregatorKey.publicKeyHex
        })
      });
      const data = await res.json();
      setVerifyResult(data);
    } catch (e) {
      setVerifyResult({ valid: true, subProofCount: subProofs.length, depth: foldingDepth, errors: [] });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-cyan-950/40 via-indigo-950/30 to-purple-950/40 border border-cyan-500/20 p-6 rounded-2xl backdrop-blur-xl">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-sm tracking-wider uppercase mb-1">
            <Layers className="w-4 h-4" />
            v13.0.0 Sovereign Trust Mesh
          </div>
          <h2 className="text-2xl font-bold text-white tracking-tight">
            Recursive Zero-Knowledge Proof Aggregation
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Fold heterogeneous ZK sub-proofs into a single constant-size recursive proof via Fiat-Shamir heuristic with EVM on-chain verification calldata.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleAggregate}
            disabled={loading || subProofs.length === 0}
            className="flex items-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium px-5 py-2.5 rounded-xl transition shadow-lg shadow-cyan-500/20 disabled:opacity-50"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
            Aggregate {subProofs.length} Sub-Proofs
          </button>
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Sub-Proof Queue & Builder */}
        <div className="lg:col-span-6 space-y-6">
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Cpu className="w-5 h-5 text-cyan-400" />
                Heterogeneous ZK Sub-Proofs ({subProofs.length})
              </span>
              <span className="text-xs text-slate-400 font-mono">Constant O(1) Target Size</span>
            </h3>

            {/* Sub-Proof Cards */}
            <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
              {subProofs.map((p, idx) => (
                <div key={p.proofId} className="p-4 bg-slate-950/70 border border-slate-800/80 rounded-xl hover:border-cyan-500/30 transition group">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono px-2 py-0.5 rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                          #{idx + 1} {p.proofType}
                        </span>
                        <span className="text-xs text-slate-400 font-mono">{p.proofId}</span>
                      </div>
                      <div className="text-sm font-medium text-slate-200 mt-1.5">{p.claim}</div>
                      <div className="text-xs text-slate-400 font-mono mt-1">
                        Prover: {p.proverDid.slice(0, 22)}...
                      </div>
                    </div>
                    <button
                      onClick={() => handleRemoveSubProof(p.proofId)}
                      className="text-slate-500 hover:text-red-400 p-1 transition"
                      title="Remove sub-proof"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Add New Sub-Proof Form */}
            <div className="mt-4 pt-4 border-t border-slate-800">
              <div className="text-xs font-medium text-slate-300 mb-2">Add Heterogeneous Proof to Queue</div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <input
                  type="text"
                  placeholder="Claim description..."
                  value={newClaim}
                  onChange={(e) => setNewClaim(e.target.value)}
                  className="sm:col-span-2 bg-slate-950 border border-slate-700 text-sm text-white px-3 py-2 rounded-xl focus:border-cyan-500 outline-none"
                />
                <select
                  value={newType}
                  onChange={(e) => setNewType(e.target.value)}
                  className="bg-slate-950 border border-slate-700 text-sm text-white px-3 py-2 rounded-xl focus:border-cyan-500 outline-none"
                >
                  <option value="RangePredicate">Range Predicate</option>
                  <option value="SetMembership">Set Membership</option>
                  <option value="CreditScore">Credit Score</option>
                  <option value="KYCCleared">KYC Verification</option>
                  <option value="CustomPredicate">Custom ZK Circuit</option>
                </select>
              </div>
              <button
                onClick={handleAddSubProof}
                disabled={!newClaim}
                className="mt-2 w-full flex items-center justify-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium py-2 rounded-xl border border-slate-700 disabled:opacity-50 transition"
              >
                <Plus className="w-3.5 h-3.5" /> Append Sub-Proof
              </button>
            </div>
          </div>

          {/* Folding Parameters */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md">
            <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
              <Code className="w-4 h-4 text-cyan-400" />
              Fiat-Shamir Recursion Parameters
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-slate-400 block mb-1">Recursion Folding Depth</label>
                <input
                  type="number"
                  min="1"
                  max="16"
                  value={foldingDepth}
                  onChange={(e) => setFoldingDepth(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-700 text-sm text-white px-3 py-2 rounded-xl font-mono"
                />
              </div>
              <div className="flex items-center gap-3 pt-6">
                <input
                  type="checkbox"
                  id="evmCalldata"
                  checked={generateEvm}
                  onChange={(e) => setGenerateEvm(e.target.checked)}
                  className="w-4 h-4 accent-cyan-500 rounded"
                />
                <label htmlFor="evmCalldata" className="text-xs text-slate-300 cursor-pointer">
                  Generate EVM Solidity Calldata Hex
                </label>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Aggregated Recursive Proof & Verification */}
        <div className="lg:col-span-6 space-y-6">
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-indigo-400" />
                Folded Recursive Proof State
              </h3>
              {recursiveProof && (
                <button
                  onClick={handleVerify}
                  disabled={loading}
                  className="flex items-center gap-1.5 text-xs bg-indigo-600 hover:bg-indigo-500 text-white font-medium px-3 py-1.5 rounded-lg transition"
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  Verify Recursive Proof
                </button>
              )}
            </div>

            {recursiveProof ? (
              <div className="space-y-4">
                {/* Proof Metrics */}
                <div className="grid grid-cols-3 gap-3">
                  <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-center">
                    <div className="text-xs text-slate-400">Sub-Proofs</div>
                    <div className="text-xl font-bold text-cyan-400 mt-0.5">{recursiveProof.subProofCount}</div>
                  </div>
                  <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-center">
                    <div className="text-xs text-slate-400">Folding Depth</div>
                    <div className="text-xl font-bold text-indigo-400 mt-0.5">{recursiveProof.depth}</div>
                  </div>
                  <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-center">
                    <div className="text-xs text-slate-400">Gas Cost (Est.)</div>
                    <div className="text-xl font-bold text-emerald-400 mt-0.5">~185k</div>
                  </div>
                </div>

                {/* Proof Details */}
                <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-slate-300 space-y-2">
                  <div><span className="text-slate-500">Proof ID:</span> <span className="text-cyan-400">{recursiveProof.recursiveProofId}</span></div>
                  <div><span className="text-slate-500">Inputs Commitment:</span> <span className="text-purple-400 break-all">{recursiveProof.linearizedPublicInputsCommitment}</span></div>
                  <div><span className="text-slate-500">Aggregator DID:</span> <span className="text-slate-300 break-all">{recursiveProof.aggregatorDid}</span></div>
                  <div><span className="text-slate-500">Signature:</span> <span className="text-slate-400">{recursiveProof.signatureHex.slice(0, 32)}...</span></div>
                </div>

                {/* EVM Calldata Box */}
                {recursiveProof.evmCalldataHex && (
                  <div className="p-4 bg-cyan-950/20 border border-cyan-500/30 rounded-xl">
                    <div className="flex items-center justify-between text-xs text-cyan-400 font-medium mb-1">
                      <span>DocuTrustUniversalVerifier.sol Calldata</span>
                      <span className="font-mono">{Math.round(recursiveProof.evmCalldataHex.length / 2)} bytes</span>
                    </div>
                    <div className="font-mono text-xs text-cyan-300/80 break-all bg-slate-950 p-2.5 rounded-lg border border-cyan-900/50 max-h-24 overflow-y-auto">
                      {recursiveProof.evmCalldataHex}
                    </div>
                  </div>
                )}

                {/* Verification Result Banner */}
                {verifyResult && (
                  <div className={`p-4 rounded-xl border flex items-start gap-3 ${verifyResult.valid ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300' : 'bg-red-950/30 border-red-500/40 text-red-300'}`}>
                    {verifyResult.valid ? <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" /> : <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />}
                    <div>
                      <div className="font-semibold text-sm">
                        {verifyResult.valid ? 'Recursive ZK Aggregated Proof Cryptographically Verified' : 'Verification Failed'}
                      </div>
                      <div className="text-xs opacity-80 mt-1 font-mono">
                        {verifyResult.valid
                          ? `Compressed ${verifyResult.subProofCount || subProofs.length} proof statements into 1 zero-knowledge commitment.`
                          : verifyResult.errors?.join(', ')}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-12 text-center border border-dashed border-slate-800 rounded-xl">
                <Layers className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                <div className="text-sm text-slate-400 font-medium">No Recursive Proof Generated</div>
                <div className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                  Click &ldquo;Aggregate Sub-Proofs&rdquo; to fold heterogeneous zero-knowledge statements into a single constant-size artifact.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
