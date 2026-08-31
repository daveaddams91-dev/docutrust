import React, { useState } from 'react';
import { Cpu, Play, CheckCircle2, XCircle, Code2, Terminal, RefreshCw, Key, ShieldCheck, Layers } from 'lucide-react';

export default function VerifiableComputeStudio() {
  const [proverKey, setProverKey] = useState({
    publicKeyHex: 'b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9',
    privateKeyHex: '9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d',
    did: 'did:key:z6MkuProverVerifiableCompute2026MasterNode'
  });

  const [programJson, setProgramJson] = useState(() => JSON.stringify({
    programId: 'CreditRiskScoreCalculator',
    version: '1.2.0',
    instructions: [
      { op: 'WEIGHTED_SUM', args: [['$income', '$creditHistoryYears'], [0.6, 0.4]], outputVar: 'baseMetric' },
      { op: 'SUB', args: ['$baseMetric', '$debtObligations'], outputVar: 'netCreditBuffer' },
      { op: 'THRESHOLD_CHECK', args: ['$netCreditBuffer', 50000], outputVar: 'creditApproved' },
      { op: 'RANGE_CHECK', args: ['$netCreditBuffer', 50000, 500000], outputVar: 'isTierA' },
      { op: 'HASH_CHAIN', args: ['$netCreditBuffer', 2], outputVar: 'auditAnchor' }
    ]
  }, null, 2));

  const [inputsJson, setInputsJson] = useState(() => JSON.stringify({
    income: 120000,
    creditHistoryYears: 10,
    debtObligations: 25000
  }, null, 2));

  const [executionResult, setExecutionResult] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleExecute = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const program = JSON.parse(programJson);
      const inputs = JSON.parse(inputsJson);

      const res = await fetch('/api/v1/compute/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          program,
          inputs,
          proverKeyPair: proverKey
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Execution failed');
      setExecutionResult(data);
      setVerifyResult(null);
    } catch (e) {
      setErrorMsg(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    if (!executionResult?.receipt) return;
    try {
      const inputs = JSON.parse(inputsJson);
      const res = await fetch('/api/v1/compute/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          receipt: executionResult.receipt,
          proverPublicKey: proverKey.publicKeyHex,
          inputs
        })
      });
      const data = await res.json();
      setVerifyResult(data);
    } catch (e) {
      setErrorMsg(e.message);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-mono">
              v12.0.0 Verifiable VM
            </span>
            <span className="text-gray-400 text-xs font-mono">DocuTrustComputeReceipt2026</span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Cpu className="w-8 h-8 text-indigo-400" />
            Deterministic Verifiable Compute Engine
          </h1>
          <p className="text-gray-400 text-sm mt-1 max-w-3xl">
            Execute deterministic credential computation pipelines off-chain, generate step-by-step cryptographic execution traces, and produce verifiable compute receipts without smart contract gas limits.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left: Program & Inputs Editor */}
        <div className="lg:col-span-6 space-y-6">
          <div className="bg-gray-900/60 border border-gray-800/80 rounded-2xl p-6 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Code2 className="w-4 h-4 text-indigo-400" />
                Compute Program Definition (AST)
              </h3>
              <span className="text-[10px] font-mono text-gray-500">JSON AST</span>
            </div>
            <textarea
              rows={11}
              value={programJson}
              onChange={(e) => setProgramJson(e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded-xl p-3 text-xs font-mono text-gray-200 focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div className="bg-gray-900/60 border border-gray-800/80 rounded-2xl p-6 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-blue-400" />
                Input Variable Bindings
              </h3>
              <span className="text-[10px] font-mono text-gray-500">Context JSON</span>
            </div>
            <textarea
              rows={5}
              value={inputsJson}
              onChange={(e) => setInputsJson(e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded-xl p-3 text-xs font-mono text-gray-200 focus:outline-none focus:border-indigo-500"
            />

            <div className="mt-4 flex justify-end">
              <button
                onClick={handleExecute}
                disabled={loading}
                className="px-5 py-2.5 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white font-semibold text-xs rounded-xl shadow-lg shadow-indigo-500/20 transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
              >
                <Play className="w-4 h-4" />
                {loading ? 'Proving...' : 'Execute & Prove Program'}
              </button>
            </div>
          </div>

          {errorMsg && (
            <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-xs font-mono">
              Error: {errorMsg}
            </div>
          )}
        </div>

        {/* Right: Execution Trace & Verifiable Receipt */}
        <div className="lg:col-span-6 space-y-6">
          {executionResult ? (
            <>
              {/* Output Variables Card */}
              <div className="bg-gray-900/60 border border-gray-800/80 rounded-2xl p-6 backdrop-blur-sm">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    Final Computation State
                  </h3>
                  <span className="text-[10px] font-mono text-emerald-400 px-2 py-0.5 bg-emerald-500/10 rounded border border-emerald-500/20">
                    {executionResult.trace?.length || 0} Steps Executed
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 mb-4">
                  {Object.entries(executionResult.finalOutputs || {}).map(([k, v]) => (
                    <div key={k} className="p-3 bg-gray-950 rounded-xl border border-gray-800/80">
                      <span className="text-[10px] font-mono text-gray-400 block">{k}</span>
                      <span className="text-sm font-bold font-mono text-white break-all">
                        {typeof v === 'boolean' ? (v ? 'TRUE' : 'FALSE') : String(v)}
                      </span>
                    </div>
                  ))}
                </div>

                <div className="pt-3 border-t border-gray-800/60 text-[11px] font-mono text-gray-400 space-y-1">
                  <div><span className="text-gray-500">Trace Root:</span> <span className="text-indigo-300">{executionResult.receipt?.traceMerkleRoot}</span></div>
                  <div><span className="text-gray-500">Output Hash:</span> <span className="text-blue-300">{executionResult.receipt?.outputStateHash}</span></div>
                </div>
              </div>

              {/* Execution Step Trace List */}
              <div className="bg-gray-900/60 border border-gray-800/80 rounded-2xl p-6 backdrop-blur-sm">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
                  <Layers className="w-4 h-4 text-purple-400" />
                  Deterministic Execution Trace
                </h3>
                <div className="space-y-2 max-h-44 overflow-y-auto pr-1">
                  {executionResult.trace?.map((step, idx) => (
                    <div key={idx} className="p-2.5 bg-gray-950 rounded-lg border border-gray-800/80 text-xs font-mono flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-gray-500">#{step.step}</span>
                        <span className="px-1.5 py-0.5 bg-indigo-500/10 text-indigo-400 rounded text-[10px] font-semibold">{step.op}</span>
                        <span className="text-gray-300">→ {step.outputVar}</span>
                      </div>
                      <span className="text-gray-400 text-[11px] truncate max-w-[150px]">{JSON.stringify(step.result)}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Cryptographic Receipt & Verifier */}
              <div className="bg-gray-900/60 border border-gray-800/80 rounded-2xl p-6 backdrop-blur-sm">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-indigo-400" />
                    DocuTrustComputeReceipt2026
                  </h3>
                  <button
                    onClick={handleVerify}
                    className="px-3 py-1.5 bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    Verify Receipt
                  </button>
                </div>

                <pre className="bg-gray-950 p-3 rounded-xl text-[10px] font-mono text-gray-300 border border-gray-800/80 overflow-x-auto max-h-36">
                  {JSON.stringify(executionResult.receipt, null, 2)}
                </pre>

                {verifyResult && (
                  <div className={`mt-3 p-3 rounded-xl border flex items-center justify-between text-xs ${
                    verifyResult.valid ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-red-500/10 border-red-500/30 text-red-300'
                  }`}>
                    <div className="flex items-center gap-2">
                      {verifyResult.valid ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                      <span>{verifyResult.valid ? 'Execution trace root and prover signature verified successfully!' : 'Verification Failed'}</span>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="h-full min-h-[300px] flex flex-col items-center justify-center border border-dashed border-gray-800 rounded-2xl p-8 text-center bg-gray-900/20">
              <Cpu className="w-12 h-12 text-gray-600 mb-3 animate-pulse" />
              <h4 className="text-sm font-semibold text-gray-400">No Execution In Progress</h4>
              <p className="text-xs text-gray-500 max-w-sm mt-1">
                Configure your AST compute instructions and input variables on the left and click "Execute & Prove Program".
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
