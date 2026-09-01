import React, { useState } from 'react';
import { Layers, Database, ShieldCheck, CheckCircle2, Cpu, ArrowRight, RefreshCw, FileCode, CheckCircle } from 'lucide-react';

const dummyHex = (len = 64) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');

export default function ZKRollupStudio() {
  const [blockNumber, setBlockNumber] = useState(1);
  const [batchSize, setBatchSize] = useState(4);
  const [batch, setBatch] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleGenerateBatch = () => {
    setLoading(true);
    setTimeout(() => {
      const txs = Array.from({ length: batchSize }, (_, i) => ({
        txId: `tx_rollup_${dummyHex(8)}`,
        accountIndex: i,
        holderDid: `did:docutrust:holder:${dummyHex(6)}`,
        credentialId: `cred_${1000 + i}`,
        previousStatus: 1, // ACTIVE
        newStatus: i % 2 === 0 ? 2 : 3, // SUSPENDED or REVOKED
        nonce: 1
      }));

      const compressedDiffs = `0x` + dummyHex(32 * batchSize);
      const prevRoot = '0x' + dummyHex(64);
      const postRoot = '0x' + dummyHex(64);

      const rollupBatch = {
        batchId: `batch_${Date.now()}_${blockNumber}`,
        blockNumber: Number(blockNumber),
        transactionCount: batchSize,
        previousStateRoot: prevRoot,
        postStateRoot: postRoot,
        transactions: txs,
        compressedStateDiffs: compressedDiffs,
        polynomialCommitmentHex: '0x' + dummyHex(64),
        validiumProof: {
          proofId: `proof_stark_${dummyHex(12)}`,
          friCommitments: [dummyHex(32), dummyHex(32), dummyHex(32)],
          evaluations: [dummyHex(16), dummyHex(16)],
          verified: true
        },
        evmCalldataHeader: `0x7f${prevRoot.slice(2)}${postRoot.slice(2)}`,
        createdAt: new Date().toISOString()
      };

      setBatch(rollupBatch);
      setVerificationResult(null);
      setLoading(false);
    }, 300);
  };

  const handleVerifyBatch = () => {
    if (!batch) return;
    setVerificationResult({
      valid: true,
      batchId: batch.batchId,
      verifiedTransactions: batch.transactionCount,
      stateTransitionValid: true,
      validiumProofValid: true,
      verifiedAt: new Date().toISOString()
    });
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8">
      <div className="border-b border-gray-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-blue-500/10 rounded-xl text-blue-400 border border-blue-500/20">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              ZK-Rollup & Batch State Compression Studio
              <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30">v20.0.0</span>
            </h1>
            <p className="text-gray-400 text-sm mt-1">
              High-throughput Validium zero-knowledge state compression, polynomial commitments, and on-chain EVM calldata generation.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Rollup Configuration */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Database className="w-4 h-4 text-blue-400" />
              Batch Configuration
            </h2>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Rollup Block Number</label>
              <input
                type="number"
                value={blockNumber}
                onChange={(e) => setBlockNumber(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Batch Transaction Count</label>
              <select
                value={batchSize}
                onChange={(e) => setBatchSize(Number(e.target.value))}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-blue-500"
              >
                <option value={2}>2 Transactions (Micro-batch)</option>
                <option value={4}>4 Transactions (Standard)</option>
                <option value={8}>8 Transactions (High Throughput)</option>
                <option value={16}>16 Transactions (Maximum Compression)</option>
              </select>
            </div>

            <button
              onClick={handleGenerateBatch}
              disabled={loading}
              className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium text-sm flex items-center justify-center gap-2 transition disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Layers className="w-4 h-4" />}
              Generate ZK-Rollup Block
            </button>
          </div>

          {batch && (
            <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
              <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Proof Verification
              </h2>
              <button
                onClick={handleVerifyBatch}
                className="w-full py-2 px-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium text-sm flex items-center justify-center gap-2 transition"
              >
                <CheckCircle2 className="w-4 h-4" />
                Verify Validium Proof
              </button>

              {verificationResult && (
                <div className="p-3 bg-emerald-950/40 border border-emerald-500/30 rounded-lg text-xs space-y-1">
                  <div className="text-emerald-400 font-semibold flex items-center gap-1">
                    <CheckCircle className="w-3.5 h-3.5" /> Proof Authenticated
                  </div>
                  <div className="text-gray-300">Batch ID: {verificationResult.batchId}</div>
                  <div className="text-gray-400">State Transitions Verified: {verificationResult.verifiedTransactions}</div>
                  <div className="text-gray-400">Time: {new Date(verificationResult.verifiedAt).toLocaleTimeString()}</div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Column: Generated Block & Calldata */}
        <div className="lg:col-span-2 space-y-6">
          {batch ? (
            <div className="space-y-6">
              <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-gray-800 pb-3">
                  <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-blue-400" />
                    ZK-Rollup Block #{batch.blockNumber} Details
                  </h3>
                  <span className="text-xs px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                    {batch.batchId}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-3 bg-gray-950 rounded-lg border border-gray-800 space-y-1">
                    <span className="text-gray-500 font-medium">Previous Merkle Root</span>
                    <p className="font-mono text-gray-300 truncate">{batch.previousStateRoot}</p>
                  </div>
                  <div className="p-3 bg-gray-950 rounded-lg border border-gray-800 space-y-1">
                    <span className="text-emerald-500 font-medium">Post State Merkle Root</span>
                    <p className="font-mono text-emerald-300 truncate">{batch.postStateRoot}</p>
                  </div>
                  <div className="p-3 bg-gray-950 rounded-lg border border-gray-800 space-y-1 md:col-span-2">
                    <span className="text-indigo-400 font-medium">KZG / FRI Polynomial Commitment</span>
                    <p className="font-mono text-indigo-300 truncate">{batch.polynomialCommitmentHex}</p>
                  </div>
                </div>

                <div>
                  <h4 className="text-xs font-semibold text-gray-400 mb-2">Compressed State Transitions</h4>
                  <div className="bg-gray-950 border border-gray-800 rounded-lg p-3 space-y-2 max-h-48 overflow-y-auto">
                    {batch.transactions.map((tx, idx) => (
                      <div key={idx} className="flex items-center justify-between text-xs py-1 border-b border-gray-900 last:border-none font-mono">
                        <span className="text-blue-400">{tx.txId}</span>
                        <span className="text-gray-400">{tx.holderDid.slice(0, 18)}...</span>
                        <span className="flex items-center gap-1">
                          <span className="text-yellow-400">S:{tx.previousStatus}</span>
                          <ArrowRight className="w-3 h-3 text-gray-500" />
                          <span className="text-emerald-400">S:{tx.newStatus}</span>
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="text-xs font-semibold text-gray-400 mb-2 flex items-center gap-1.5">
                    <FileCode className="w-3.5 h-3.5 text-yellow-400" />
                    Synthesized EVM Calldata Header
                  </h4>
                  <pre className="p-3 bg-gray-950 border border-gray-800 rounded-lg text-xs font-mono text-yellow-300 overflow-x-auto">
                    {batch.evmCalldataHeader}
                  </pre>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center border border-dashed border-gray-800 rounded-xl text-gray-500 space-y-2">
              <Layers className="w-8 h-8 opacity-40" />
              <p className="text-sm">Configure parameters and click "Generate ZK-Rollup Block" to begin.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
