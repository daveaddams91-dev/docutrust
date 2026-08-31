import React, { useState } from 'react';
import { Bot, GitFork, ShieldCheck, CheckCircle2, RefreshCw, Key, ArrowRight, Layers, FileCheck } from 'lucide-react';

export default function AgenticCapabilityStudio() {
  const [rootDid] = useState('did:key:z6MkpOrgRoot9941');
  const [orchestratorDid] = useState('did:key:z6MkuOrchestratorAgent12');
  const [workerDid] = useState('did:key:z6MkwWorkerLeafAgent88');

  const [rootCap, setRootCap] = useState(null);
  const [workerCap, setWorkerCap] = useState(null);
  const [executionReceipt, setExecutionReceipt] = useState(null);
  const [spendAmount, setSpendAmount] = useState(75);
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleIssueRootCapability = () => {
    setLoading(true);
    setTimeout(() => {
      const rootToken = {
        type: 'DocuTrustUCANToken2026',
        issuer: rootDid,
        audience: orchestratorDid,
        capabilities: [
          { resource: 'urn:docutrust:vault:*', action: '*' },
          { resource: 'urn:docutrust:compute:zk', action: 'EXECUTE' }
        ],
        caveats: [{ type: 'maxSpend', value: 1000 }],
        expiresAt: new Date(Date.now() + 3600 * 1000).toISOString(),
        parentProofHashes: [],
        signature: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')
      };
      setRootCap(rootToken);
      setWorkerCap(null);
      setExecutionReceipt(null);
      setVerificationResult(null);
      setLoading(false);
    }, 300);
  };

  const handleAttenuateToWorker = () => {
    if (!rootCap) return;
    const workerToken = {
      type: 'DocuTrustUCANToken2026',
      issuer: orchestratorDid,
      audience: workerDid,
      capabilities: [
        { resource: 'urn:docutrust:vault:documents', action: 'READ' }
      ],
      caveats: [{ type: 'maxSpend', value: 100 }],
      expiresAt: new Date(Date.now() + 1800 * 1000).toISOString(),
      parentProofHashes: ['0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')],
      signature: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')
    };
    setWorkerCap(workerToken);
  };

  const handleExecuteAgentTask = () => {
    if (!rootCap || !workerCap) return;
    const isSpendValid = spendAmount <= 100;
    if (!isSpendValid) {
      setVerificationResult({
        valid: false,
        error: `Caveat violation: requested spend ${spendAmount} exceeds maximum allowed 100`
      });
      return;
    }

    const receipt = {
      type: 'DocuTrustAgentExecutionReceipt2026',
      receiptId: `rec_agent_${Date.now()}`,
      agentDid: workerDid,
      capabilityExercised: { resource: 'urn:docutrust:vault:documents', action: 'READ' },
      delegationDepth: 2,
      executionPayload: {
        task: 'FETCH_CREDENTIAL_RECORD',
        recordId: 'REC-9941',
        spendAmount: spendAmount,
        status: 'SUCCESS'
      },
      status: 'EXECUTED_AUTHENTIC',
      agentSignature: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
      timestamp: new Date().toISOString()
    };
    setExecutionReceipt(receipt);
    setVerificationResult({ valid: true, error: null });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-rose-500 to-pink-600 rounded-xl shadow-lg shadow-rose-500/20">
            <Bot className="w-8 h-8 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-2xl font-bold text-white tracking-tight">Agentic Capability & Delegation Mesh Studio</h2>
              <span className="px-2.5 py-0.5 text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20 rounded-full">
                v16.0 UCAN / OCAP-LD
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Autonomous AI agent capability delegation tokens with monotonic caveat attenuation & cryptographically verifiable execution receipts.
            </p>
          </div>
        </div>
        <button
          onClick={handleIssueRootCapability}
          disabled={loading}
          className="flex items-center gap-2 px-5 py-2.5 bg-rose-600 hover:bg-rose-500 text-white text-sm font-semibold rounded-xl transition-all shadow-lg shadow-rose-600/25 active:scale-95 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Issue Root UCAN Token
        </button>
      </div>

      {/* Grid: Delegation Chain & Execution Verification */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Delegation Chain */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <GitFork className="w-5 h-5 text-rose-400" />
                <h3 className="text-lg font-semibold text-white">Delegation Hierarchy</h3>
              </div>
              <span className="text-xs bg-rose-500/10 text-rose-400 px-2 py-1 rounded-md border border-rose-500/20">
                Monotonic Attenuation
              </span>
            </div>

            <div className="space-y-3">
              {/* Root Organization */}
              <div className="p-3.5 bg-slate-950/80 rounded-xl border border-slate-800">
                <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                  <span className="font-semibold text-rose-400">1. Root Authority (Organization)</span>
                  <span className="font-mono">{rootDid.substring(0, 16)}...</span>
                </div>
                <div className="text-xs font-mono text-slate-300">
                  Caps: <code className="text-rose-300">vault:*, compute:zk:EXECUTE (maxSpend: $1000)</code>
                </div>
              </div>

              {/* Orchestrator Agent */}
              {rootCap && (
                <div className="p-3.5 bg-slate-950/80 rounded-xl border border-slate-800 ml-4 border-l-2 border-l-rose-500">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="font-semibold text-rose-400">2. Orchestrator Agent</span>
                    <span className="font-mono">{orchestratorDid.substring(0, 16)}...</span>
                  </div>
                  <button
                    onClick={handleAttenuateToWorker}
                    className="mt-2 text-xs px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-rose-300 rounded-lg border border-slate-700 transition-all font-semibold"
                  >
                    Attenuate Token to Worker Agent
                  </button>
                </div>
              )}

              {/* Leaf Worker Agent */}
              {workerCap && (
                <div className="p-3.5 bg-slate-950/80 rounded-xl border border-slate-800 ml-8 border-l-2 border-l-pink-500">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="font-semibold text-pink-400">3. Leaf Worker Agent</span>
                    <span className="font-mono">{workerDid.substring(0, 16)}...</span>
                  </div>
                  <div className="text-xs font-mono text-slate-300">
                    Caps: <code className="text-pink-300">vault:documents:READ (maxSpend: $100)</code>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Execution & Receipt Verification */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FileCheck className="w-5 h-5 text-rose-400" />
                <h3 className="text-lg font-semibold text-white">Agent Execution & Receipt</h3>
              </div>
              <span className="text-xs bg-pink-500/10 text-pink-400 px-2 py-1 rounded-md border border-pink-500/20">
                Verifiable Proof of Action
              </span>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Spend Budget for Action ($)</label>
                <input
                  type="number"
                  value={spendAmount}
                  onChange={(e) => setSpendAmount(parseInt(e.target.value, 10))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-white font-mono"
                />
                <span className="text-xs text-slate-500 mt-1 block">Worker token ceiling: $100 maxSpend caveat</span>
              </div>

              <button
                onClick={handleExecuteAgentTask}
                disabled={!workerCap}
                className="w-full py-2.5 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs font-semibold rounded-xl transition-all shadow-lg shadow-rose-600/25"
              >
                Execute Agent Vault Access & Sign Receipt
              </button>

              {verificationResult && (
                <div className={`p-3.5 rounded-xl border text-xs flex items-center gap-2 ${
                  verificationResult.valid
                    ? 'bg-rose-950/30 border-rose-500/30 text-rose-300'
                    : 'bg-red-950/30 border-red-500/30 text-red-400'
                }`}>
                  {verificationResult.valid ? (
                    <>
                      <CheckCircle2 className="w-4 h-4 text-rose-400 shrink-0" />
                      <span>Delegation Chain & Caveats 100% Authorized & Valid</span>
                    </>
                  ) : (
                    <span>✖ {verificationResult.error}</span>
                  )}
                </div>
              )}

              {executionReceipt && (
                <pre className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-rose-300 font-mono text-xs overflow-x-auto">
                  {JSON.stringify(executionReceipt, null, 2)}
                </pre>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
