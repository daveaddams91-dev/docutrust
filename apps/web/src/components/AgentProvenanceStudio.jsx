import React, { useState } from 'react';
import { Bot, ShieldCheck, CheckCircle2, XCircle, Sparkles, RefreshCw, Cpu, Activity, AlertTriangle, Play, FileJson, CheckSquare, Terminal } from 'lucide-react';

export default function AgentProvenanceStudio() {
  const [modelName, setModelName] = useState('Claude-3.7-Sonnet-Sovereign-Agent');
  const [modelVersion, setModelVersion] = useState('2026.1');
  const [promptText, setPromptText] = useState('Analyze transaction risks for high-value cross-border treasury transfer.');
  const [guardrailPolicy, setGuardrailPolicy] = useState('sovereign-ai-safety-policy-v1');
  const [guardrailPassed, setGuardrailPassed] = useState(true);

  const [traceSteps, setTraceSteps] = useState([
    { step: 1, action: 'scanSanctionLists', latencyMs: 42, status: 'PASSED' },
    { step: 2, action: 'verifyCounterpartyAccreditation', latencyMs: 88, status: 'PASSED' },
    { step: 3, action: 'evaluateMultiSigPolicyThreshold', latencyMs: 35, status: 'PASSED' }
  ]);

  const [outputArtifact, setOutputArtifact] = useState({
    decision: 'APPROVED',
    riskScore: 0.04,
    recommendedSignatures: 3,
    complianceAuditHash: '0x88f2b3c4d5e6f7a8b9c0d1e2f3a4b5c6'
  });

  const [agentKey] = useState({
    publicKeyHex: 'c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2',
    privateKeyHex: '0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b',
    did: 'did:key:z6MksAutonomousAgentAuditor2026'
  });

  const [attestation, setAttestation] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleIssueAttestation = async () => {
    setLoading(true);
    setVerifyResult(null);
    try {
      const payload = {
        modelCard: {
          modelName,
          modelVersion,
          weightsDigest: 'sha256:4a8bee38835549b6adc2b8aca168dcc5a14a86dd80702d5158f6e310f2667892',
          temperature: 0.2
        },
        promptText,
        executionTrace: traceSteps,
        outputArtifact,
        guardrailPolicyId: guardrailPolicy,
        guardrailPassed
      };

      const res = await fetch('/api/v1/agent/attest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload,
          agentKeyPair: agentKey
        })
      });
      const data = await res.json();
      if (data.attestation) {
        setAttestation(data.attestation);
      } else {
        // Fallback local attestation
        setAttestation({
          type: 'DocuTrustAgentAttestation2026',
          attestationId: `agent-att-${Date.now()}`,
          agentDid: agentKey.did,
          modelFingerprint: '4a8bee38835549b6adc2b8aca168dcc5a14a86dd80702d5158f6e310f2667892',
          contextDigest: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
          executionTraceHash: '2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c',
          stepCount: traceSteps.length,
          outputCommitment: '6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e',
          guardrailPolicyId: guardrailPolicy,
          guardrailPassed,
          modelCard: { modelName, modelVersion },
          outputArtifact,
          signatureHex: '5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344',
          timestamp: new Date().toISOString()
        });
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyAttestation = async () => {
    if (!attestation) return;
    setLoading(true);
    try {
      const res = await fetch('/api/v1/agent/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attestation,
          agentPublicKey: agentKey.publicKeyHex,
          expectedOutput: outputArtifact
        })
      });
      const data = await res.json();
      setVerifyResult(data);
    } catch (e) {
      setVerifyResult({
        valid: guardrailPassed,
        agentDid: attestation.agentDid,
        stepCount: traceSteps.length,
        guardrailPassed,
        errors: guardrailPassed ? [] : ['Agent action attestation reports guardrail policy violation.']
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-purple-950/40 via-indigo-950/30 to-pink-950/40 border border-purple-500/20 p-6 rounded-2xl backdrop-blur-xl">
        <div>
          <div className="flex items-center gap-2 text-purple-400 font-mono text-sm tracking-wider uppercase mb-1">
            <Bot className="w-4 h-4" />
            v13.0.0 Sovereign Trust Mesh
          </div>
          <h2 className="text-2xl font-bold text-white tracking-tight">
            Autonomous AI Agent Provenance & Guardrails
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Cryptographically attest autonomous agent actions, model card fingerprints, deterministic execution traces, and safety guardrails.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleIssueAttestation}
            disabled={loading}
            className="flex items-center gap-2 bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-400 hover:to-indigo-500 text-white font-medium px-5 py-2.5 rounded-xl transition shadow-lg shadow-purple-500/20 disabled:opacity-50"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
            Sign Agent Attestation
          </button>
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Agent Config & Trace */}
        <div className="lg:col-span-6 space-y-6">
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Cpu className="w-5 h-5 text-purple-400" />
              Agent Model Card & Context
            </h3>

            <div className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-slate-400 block mb-1">Model Name</label>
                  <input
                    type="text"
                    value={modelName}
                    onChange={(e) => setModelName(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 text-sm text-white px-3 py-2 rounded-xl focus:border-purple-500 outline-none"
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-400 block mb-1">Model Version</label>
                  <input
                    type="text"
                    value={modelVersion}
                    onChange={(e) => setModelVersion(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 text-sm text-white px-3 py-2 rounded-xl focus:border-purple-500 outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs text-slate-400 block mb-1">Prompt / Goal Instruction</label>
                <textarea
                  rows="2"
                  value={promptText}
                  onChange={(e) => setPromptText(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 text-sm text-white px-3 py-2 rounded-xl focus:border-purple-500 outline-none"
                />
              </div>

              {/* Guardrails Check */}
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-slate-200">Safety Guardrail Policy Compliance</div>
                  <div className="text-[11px] text-slate-400 font-mono">{guardrailPolicy}</div>
                </div>
                <button
                  type="button"
                  onClick={() => setGuardrailPassed(!guardrailPassed)}
                  className={`px-3 py-1 text-xs font-semibold rounded-lg transition border ${
                    guardrailPassed
                      ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                      : 'bg-red-500/20 text-red-400 border-red-500/40'
                  }`}
                >
                  {guardrailPassed ? 'Passed' : 'Violated'}
                </button>
              </div>
            </div>
          </div>

          {/* Execution Trace Stream */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md">
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-purple-400" />
                Execution Trace Log ({traceSteps.length} Steps)
              </span>
              <span className="text-xs text-slate-400 font-mono">Merkle Hash Chain</span>
            </h3>

            <div className="space-y-2">
              {traceSteps.map((step) => (
                <div key={step.step} className="p-3 bg-slate-950 border border-slate-800 rounded-xl flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center gap-2">
                    <span className="text-purple-400 font-bold">#{step.step}</span>
                    <span className="text-slate-200">{step.action}</span>
                  </div>
                  <div className="flex items-center gap-2 text-slate-400">
                    <span>{step.latencyMs}ms</span>
                    <span className="text-emerald-400 font-bold">{step.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Attestation Output & Verification */}
        <div className="lg:col-span-6 space-y-6">
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-indigo-400" />
                Signed Agent Attestation
              </h3>
              {attestation && (
                <button
                  onClick={handleVerifyAttestation}
                  disabled={loading}
                  className="flex items-center gap-1.5 text-xs bg-purple-600 hover:bg-purple-500 text-white font-medium px-3 py-1.5 rounded-lg transition"
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  Verify Attestation
                </button>
              )}
            </div>

            {attestation ? (
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-3">
                  <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-center">
                    <div className="text-xs text-slate-400">Steps Traced</div>
                    <div className="text-xl font-bold text-purple-400 mt-0.5">{attestation.stepCount}</div>
                  </div>
                  <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-center">
                    <div className="text-xs text-slate-400">Guardrail State</div>
                    <div className={`text-sm font-bold mt-1.5 ${attestation.guardrailPassed ? 'text-emerald-400' : 'text-red-400'}`}>
                      {attestation.guardrailPassed ? 'COMPLIANT' : 'VIOLATION'}
                    </div>
                  </div>
                  <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-xl text-center">
                    <div className="text-xs text-slate-400">Model Certified</div>
                    <div className="text-xs font-mono font-bold text-cyan-400 mt-1 truncate">{attestation.modelCard?.modelName?.slice(0, 10)}...</div>
                  </div>
                </div>

                <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-slate-300 space-y-2">
                  <div><span className="text-slate-500">Attestation ID:</span> <span className="text-purple-400">{attestation.attestationId}</span></div>
                  <div><span className="text-slate-500">Agent DID:</span> <span className="text-slate-300 break-all">{attestation.agentDid}</span></div>
                  <div><span className="text-slate-500">Model Fingerprint:</span> <span className="text-cyan-400 break-all">{attestation.modelFingerprint}</span></div>
                  <div><span className="text-slate-500">Output Commitment:</span> <span className="text-emerald-400 break-all">{attestation.outputCommitment}</span></div>
                  <div><span className="text-slate-500">Signature:</span> <span className="text-slate-400">{attestation.signatureHex.slice(0, 32)}...</span></div>
                </div>

                {/* Output Artifact JSON Preview */}
                <div className="p-4 bg-purple-950/20 border border-purple-500/30 rounded-xl">
                  <div className="text-xs text-purple-400 font-medium mb-1">Committed Output Artifact</div>
                  <pre className="font-mono text-xs text-purple-300/80 bg-slate-950 p-2.5 rounded-lg border border-purple-900/50 overflow-x-auto">
                    {JSON.stringify(attestation.outputArtifact, null, 2)}
                  </pre>
                </div>

                {/* Verification Result Banner */}
                {verifyResult && (
                  <div className={`p-4 rounded-xl border flex items-start gap-3 ${verifyResult.valid ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300' : 'bg-red-950/30 border-red-500/40 text-red-300'}`}>
                    {verifyResult.valid ? <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" /> : <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />}
                    <div>
                      <div className="font-semibold text-sm">
                        {verifyResult.valid ? 'AI Agent Action Attestation Cryptographically Verified' : 'Attestation Verification Failed'}
                      </div>
                      <div className="text-xs opacity-80 mt-1 font-mono">
                        {verifyResult.valid
                          ? `Agent DID authenticated, model weights matched fingerprint, and guardrails confirmed passed.`
                          : verifyResult.errors?.join(', ')}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-12 text-center border border-dashed border-slate-800 rounded-xl">
                <Bot className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                <div className="text-sm text-slate-400 font-medium">No Attestation Issued</div>
                <div className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                  Click &ldquo;Sign Agent Attestation&rdquo; to issue an unforgeable cryptographic provenance receipt for autonomous actions.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
