import React, { useState } from 'react';
import { Users, Shield, Key, Network, CheckCircle2, ArrowRight, Activity, Zap, RefreshCw, Cpu, Award } from 'lucide-react';

const dummyHex = (len = 64) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');

export default function AgentFederationStudio() {
  const [authorityType, setAuthorityType] = useState('root_authority');
  const [capabilities, setCapabilities] = useState('inference:execute,state:update,oracle:feed');
  const [epistemicScore, setEpistemicScore] = useState(95);
  const [agentIdentity, setAgentIdentity] = useState(null);
  const [delegationToken, setDelegationToken] = useState(null);
  const [handshakeSession, setHandshakeSession] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleCreateAgent = () => {
    setLoading(true);
    setTimeout(() => {
      const caps = capabilities.split(',').map(c => c.trim()).filter(Boolean);
      const did = `did:docutrust:agent:${dummyHex(16)}`;
      const pubKey = dummyHex(64);
      const identity = {
        agentId: `agent_${dummyHex(8)}`,
        did,
        authorityType,
        capabilities: caps,
        epistemicScore: Number(epistemicScore),
        publicKeyHex: pubKey,
        epistemicVector: [0.92, 0.88, 0.95, 0.99],
        reputationWeight: (epistemicScore / 100).toFixed(2),
        signature: dummyHex(128),
        createdAt: new Date().toISOString()
      };
      setAgentIdentity(identity);
      setDelegationToken(null);
      setHandshakeSession(null);
      setVerificationResult(null);
      setLoading(false);
    }, 250);
  };

  const handleDelegateCapabilities = () => {
    if (!agentIdentity) return;
    const workerDid = `did:docutrust:agent:worker_${dummyHex(8)}`;
    const token = {
      tokenId: `del_${dummyHex(12)}`,
      issuerDid: agentIdentity.did,
      subjectDid: workerDid,
      delegatedCapabilities: ['inference:execute'],
      maxDelegationDepth: 3,
      currentDepth: 1,
      attenuationRules: {
        maxExecutionCalls: 500,
        disallowSubDelegation: false
      },
      notAfter: new Date(Date.now() + 86400000).toISOString(),
      issuerSignature: dummyHex(128)
    };
    setDelegationToken(token);
  };

  const handleZKHandshake = () => {
    if (!agentIdentity) return;
    const responderDid = `did:docutrust:agent:peer_${dummyHex(8)}`;
    const session = {
      sessionId: `hs_${dummyHex(16)}`,
      protocol: 'DocuTrustAgentHandshake2026',
      initiatorDid: agentIdentity.did,
      responderDid,
      sharedSecretHash: dummyHex(64),
      initiatorChallengeProof: dummyHex(64),
      responderChallengeProof: dummyHex(64),
      status: 'ESTABLISHED',
      authenticatedAt: new Date().toISOString()
    };
    setHandshakeSession(session);
  };

  const handleVerifyFederation = () => {
    if (!agentIdentity || !delegationToken) return;
    setVerificationResult({
      valid: true,
      transitiveTrustPassed: true,
      attenuationVerified: true,
      epistemicScoreCompliant: true,
      effectiveCapabilities: delegationToken.delegatedCapabilities,
      verifiedAt: new Date().toISOString()
    });
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8">
      <div className="border-b border-gray-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-violet-500/10 rounded-xl text-violet-400 border border-violet-500/20">
            <Users className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              Autonomous Agent Federation Studio
              <span className="text-xs px-2 py-0.5 rounded-full bg-violet-500/20 text-violet-400 border border-violet-500/30">v21.0.0</span>
            </h1>
            <p className="text-gray-400 text-sm mt-1">
              Multi-agent identity establishment, transitive capability attenuation delegation, epistemic credibility scoring, and mutual zero-knowledge handshakes.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Configuration */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Shield className="w-4 h-4 text-violet-400" />
              Agent Configuration
            </h2>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Authority Classification</label>
              <select
                value={authorityType}
                onChange={(e) => setAuthorityType(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-violet-500"
              >
                <option value="root_authority">Root Sovereign Authority</option>
                <option value="intermediate_delegator">Intermediate Delegator</option>
                <option value="autonomous_worker">Autonomous Execution Worker</option>
                <option value="oracle_agent">Oracle / Validator Agent</option>
              </select>
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Capabilities (comma-separated)</label>
              <input
                type="text"
                value={capabilities}
                onChange={(e) => setCapabilities(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-violet-500 font-mono text-xs"
              />
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">
                Epistemic Credibility Score: <span className="text-violet-400 font-bold">{epistemicScore}/100</span>
              </label>
              <input
                type="range"
                min="1"
                max="100"
                value={epistemicScore}
                onChange={(e) => setEpistemicScore(e.target.value)}
                className="w-full accent-violet-500"
              />
            </div>

            <button
              onClick={handleCreateAgent}
              disabled={loading}
              className="w-full py-2.5 bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white font-medium rounded-lg text-sm flex items-center justify-center gap-2 shadow-lg shadow-violet-600/20"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
              Generate Agent Identity
            </button>
          </div>

          {agentIdentity && (
            <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-3">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Federation Actions</h3>
              <button
                onClick={handleDelegateCapabilities}
                className="w-full py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-white font-medium rounded-lg text-xs flex items-center justify-center gap-2"
              >
                <Network className="w-3.5 h-3.5 text-violet-400" />
                Issue Attenuated Delegation Token
              </button>
              <button
                onClick={handleZKHandshake}
                className="w-full py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-white font-medium rounded-lg text-xs flex items-center justify-center gap-2"
              >
                <Zap className="w-3.5 h-3.5 text-amber-400" />
                Execute Mutual ZK Handshake
              </button>
              {delegationToken && (
                <button
                  onClick={handleVerifyFederation}
                  className="w-full py-2 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-300 font-medium rounded-lg text-xs flex items-center justify-center gap-2"
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Verify Delegation Trust Chain
                </button>
              )}
            </div>
          )}
        </div>

        {/* Right: Results Display */}
        <div className="lg:col-span-2 space-y-6">
          {agentIdentity ? (
            <div className="space-y-6">
              {/* Agent Identity Card */}
              <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-violet-400 bg-violet-500/10 px-2 py-0.5 rounded border border-violet-500/20">
                    {agentIdentity.did}
                  </span>
                  <span className="text-xs bg-emerald-500/10 text-emerald-400 px-2.5 py-0.5 rounded-full border border-emerald-500/20 flex items-center gap-1">
                    <Award className="w-3 h-3" /> Epistemic Score {agentIdentity.epistemicScore}/100
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-gray-950/60 p-3 rounded-lg border border-gray-800/80">
                    <div className="text-[11px] text-gray-400">Authority Type</div>
                    <div className="text-sm font-semibold text-white mt-0.5">{agentIdentity.authorityType}</div>
                  </div>
                  <div className="bg-gray-950/60 p-3 rounded-lg border border-gray-800/80">
                    <div className="text-[11px] text-gray-400">Reputation Weight</div>
                    <div className="text-sm font-semibold text-violet-400 mt-0.5">{agentIdentity.reputationWeight}</div>
                  </div>
                </div>

                <div>
                  <div className="text-xs text-gray-400 mb-1.5">Authorized Capability Grants</div>
                  <div className="flex flex-wrap gap-1.5">
                    {agentIdentity.capabilities.map((cap, i) => (
                      <span key={i} className="text-xs px-2 py-0.5 bg-gray-800 border border-gray-700 text-gray-300 rounded font-mono">
                        {cap}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Delegation Token */}
              {delegationToken && (
                <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-3">
                  <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                    <Network className="w-4 h-4 text-violet-400" />
                    Attenuated Multi-Hop Delegation Token
                  </h3>
                  <div className="bg-gray-950/80 p-3.5 rounded-lg border border-gray-800 text-xs font-mono space-y-1.5 text-gray-300">
                    <div><span className="text-gray-500">Token ID:</span> {delegationToken.tokenId}</div>
                    <div><span className="text-gray-500">Subject DID:</span> {delegationToken.subjectDid}</div>
                    <div><span className="text-gray-500">Delegated Caps:</span> {delegationToken.delegatedCapabilities.join(', ')}</div>
                    <div><span className="text-gray-500">Depth / Max:</span> {delegationToken.currentDepth} / {delegationToken.maxDelegationDepth}</div>
                    <div><span className="text-gray-500">Execution Limit:</span> {delegationToken.attenuationRules.maxExecutionCalls} calls</div>
                  </div>
                </div>
              )}

              {/* ZK Handshake Session */}
              {handshakeSession && (
                <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                      <Zap className="w-4 h-4 text-amber-400" />
                      Mutual Zero-Knowledge Agent Handshake
                    </h3>
                    <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      {handshakeSession.status}
                    </span>
                  </div>
                  <div className="bg-gray-950/80 p-3.5 rounded-lg border border-gray-800 text-xs font-mono space-y-1.5 text-gray-300">
                    <div><span className="text-gray-500">Protocol:</span> {handshakeSession.protocol}</div>
                    <div><span className="text-gray-500">Shared Key Digest:</span> {handshakeSession.sharedSecretHash.slice(0, 24)}...</div>
                    <div><span className="text-gray-500">Responder Peer:</span> {handshakeSession.responderDid}</div>
                  </div>
                </div>
              )}

              {/* Verification Output */}
              {verificationResult && (
                <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-xl p-5 space-y-3">
                  <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
                    <CheckCircle2 className="w-5 h-5" />
                    Transitive Trust Chain & Capability Attenuation Validated
                  </div>
                  <div className="text-xs text-gray-300 grid grid-cols-2 gap-2">
                    <div>Transitive Chain: <span className="text-emerald-400 font-bold">Passed</span></div>
                    <div>Epistemic Bounds: <span className="text-emerald-400 font-bold">Compliant</span></div>
                    <div>Attenuated Actions: <span className="text-emerald-400 font-mono font-bold">{verificationResult.effectiveCapabilities.join(', ')}</span></div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-gray-900/40 border border-gray-800 border-dashed rounded-xl p-12 text-center text-gray-500 flex flex-col items-center justify-center space-y-3">
              <Users className="w-10 h-10 text-gray-600" />
              <p className="text-sm">Configure agent authority properties and click "Generate Agent Identity" to start.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
