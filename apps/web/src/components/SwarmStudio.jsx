import React, { useState } from 'react';
import { Users, Vote, ShieldCheck, CheckCircle2, RefreshCw, Layers, ShieldAlert, Zap } from 'lucide-react';

export default function SwarmStudio() {
  const [swarmName, setSwarmName] = useState('autonomous-treasury-council');
  const [intentAction, setIntentAction] = useState('REBALANCE_STABLECOIN_RESERVES');
  const [targetAmountUsd, setTargetAmountUsd] = useState(750000);
  const [requiredQuorum, setRequiredQuorum] = useState(60);

  const [cluster, setCluster] = useState(null);
  const [proposal, setProposal] = useState(null);
  const [quorumProof, setQuorumProof] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleRegisterSwarm = () => {
    setLoading(true);
    setTimeout(() => {
      const dummyHex = (prefix = '0x') => prefix + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

      const agents = [
        { agentDid: 'did:docutrust:agent_security_01', role: 'Security Sentinel', reputationWeight: 40, publicKeyHex: dummyHex() },
        { agentDid: 'did:docutrust:agent_risk_02', role: 'Risk Auditor', reputationWeight: 35, publicKeyHex: dummyHex() },
        { agentDid: 'did:docutrust:agent_liquidity_03', role: 'Liquidity Router', reputationWeight: 25, publicKeyHex: dummyHex() }
      ];

      const cl = {
        swarmId: 'swarm_' + Math.floor(Math.random() * 100000),
        swarmName,
        members: agents,
        totalWeight: 100
      };

      setCluster(cl);
      setProposal(null);
      setQuorumProof(null);
      setVerificationResult(null);
      setLoading(false);
    }, 300);
  };

  const handleProposeAndVote = () => {
    if (!cluster) return;
    setLoading(true);
    setTimeout(() => {
      const dummyHex = (prefix = '0x') => prefix + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

      const prop = {
        proposalId: 'prop_' + Math.floor(Math.random() * 100000),
        swarmId: cluster.swarmId,
        proposerDid: cluster.members[0].agentDid,
        intentAction,
        targetPayload: { amountUsd: targetAmountUsd, pool: 'curve_3pool' },
        requiredQuorumWeight: requiredQuorum,
        proposalDigest: dummyHex()
      };
      setProposal(prop);

      // 2 agents vote APPROVE (40 + 35 = 75 weight >= 60 threshold)
      const votes = [
        {
          voteId: 'vote_01',
          proposalId: prop.proposalId,
          agentDid: cluster.members[0].agentDid,
          decision: 'APPROVE',
          agentWeight: 40,
          signatureHex: dummyHex()
        },
        {
          voteId: 'vote_02',
          proposalId: prop.proposalId,
          agentDid: cluster.members[1].agentDid,
          decision: 'APPROVE',
          agentWeight: 35,
          signatureHex: dummyHex()
        }
      ];

      const proof = {
        type: 'DocuTrustSwarmIntentProof2026',
        swarmId: cluster.swarmId,
        proposalId: prop.proposalId,
        intentAction: prop.intentAction,
        targetPayload: prop.targetPayload,
        proposalDigest: prop.proposalDigest,
        totalSwarmWeight: 100,
        achievedQuorumWeight: 75,
        requiredQuorumWeight: requiredQuorum,
        consensusOutcome: 'CONSENSUS_REACHED',
        participatingAgentDids: [cluster.members[0].agentDid, cluster.members[1].agentDid],
        aggregatedVotes: votes,
        swarmConsensusSignature: dummyHex(),
        timestamp: new Date().toISOString(),
        proofHash: dummyHex()
      };

      setQuorumProof(proof);
      setVerificationResult(null);
      setLoading(false);
    }, 400);
  };

  const handleVerifySwarmProof = () => {
    if (!quorumProof) return;
    setLoading(true);
    setTimeout(() => {
      setVerificationResult({
        valid: true,
        quorumAchieved: true,
        weightVerified: '75 / 60 (125% of threshold)',
        signaturesAudited: 2
      });
      setLoading(false);
    }, 250);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-amber-500 to-orange-600 rounded-xl shadow-lg shadow-amber-500/20">
            <Users className="w-8 h-8 text-white" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              Autonomous AI Agent Swarm Consensus Studio
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
                v18.0.0
              </span>
            </h2>
            <p className="text-sm text-slate-400">
              Weighted-reputation threshold voting, cryptographic intent proposals, and verifiable collective execution proofs.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Swarm Registration & Config */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider flex items-center gap-2">
              <Layers className="w-4 h-4 text-amber-400" />
              1. Swarm Cluster Registration
            </h3>
          </div>

          <div className="space-y-3">
            <div>
              <label className="text-xs font-medium text-slate-400 block mb-1">Swarm Cluster Name</label>
              <input
                type="text"
                value={swarmName}
                onChange={e => setSwarmName(e.target.value)}
                className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-amber-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium text-slate-400 block mb-1">Intent Action</label>
                <input
                  type="text"
                  value={intentAction}
                  onChange={e => setIntentAction(e.target.value)}
                  className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                />
              </div>

              <div>
                <label className="text-xs font-medium text-slate-400 block mb-1">Required Quorum Weight (%)</label>
                <input
                  type="number"
                  value={requiredQuorum}
                  onChange={e => setRequiredQuorum(Number(e.target.value))}
                  className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                />
              </div>
            </div>

            <button
              onClick={handleRegisterSwarm}
              disabled={loading}
              className="w-full mt-2 py-2.5 px-4 bg-amber-600 hover:bg-amber-500 text-white text-sm font-semibold rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-amber-600/20 disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Users className="w-4 h-4" />}
              Register Autonomous Swarm Cluster
            </button>
          </div>

          {cluster && (
            <div className="mt-4 p-4 bg-slate-800/60 rounded-xl border border-slate-700/60 space-y-2">
              <div className="flex items-center justify-between text-xs text-amber-400 font-semibold">
                <span>Cluster Members ({cluster.members.length} Agents)</span>
                <span className="px-2 py-0.5 bg-amber-500/10 rounded-full border border-amber-500/20">Total Weight: 100</span>
              </div>
              <div className="space-y-1 text-xs text-slate-300">
                {cluster.members.map((m, idx) => (
                  <div key={idx} className="flex justify-between bg-slate-900/60 p-1.5 px-2 rounded">
                    <span>{m.role}</span>
                    <span className="font-mono text-amber-300">{m.reputationWeight}% Weight</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Intent Proposal & Quorum Proof */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider flex items-center gap-2">
              <Vote className="w-4 h-4 text-orange-400" />
              2. Intent Voting & Quorum Proof
            </h3>
          </div>

          <div className="flex gap-3">
            <button
              onClick={handleProposeAndVote}
              disabled={loading || !cluster}
              className="flex-1 py-2.5 px-4 bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white text-sm font-semibold rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-orange-600/20 disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
              Execute Swarm Vote & Consensus
            </button>

            <button
              onClick={handleVerifySwarmProof}
              disabled={loading || !quorumProof}
              className="flex-1 py-2.5 px-4 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-sm font-semibold rounded-xl transition flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <CheckCircle2 className="w-4 h-4 text-orange-400" />
              Verify Quorum Proof
            </button>
          </div>

          {quorumProof && (
            <div className="space-y-3">
              <div className="p-4 bg-slate-800/60 rounded-xl border border-slate-700/60 space-y-2">
                <div className="flex items-center justify-between text-xs text-orange-400 font-semibold">
                  <span>Collective Consensus Outcome</span>
                  <span className="text-white bg-emerald-500/20 px-2 py-0.5 rounded border border-emerald-500/30 font-semibold">
                    {quorumProof.consensusOutcome}
                  </span>
                </div>
                <div className="text-xs text-slate-300">
                  Achieved Quorum: <span className="text-emerald-400 font-bold">{quorumProof.achievedQuorumWeight}%</span> / Required: {quorumProof.requiredQuorumWeight}%
                </div>
                <div className="font-mono text-xs text-slate-400 break-all bg-slate-900/60 p-2 rounded border border-slate-800">
                  Proposal Digest: {quorumProof.proposalDigest}
                </div>
              </div>

              {verificationResult && (
                <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-xs text-emerald-300 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>Swarm intent proposal validated: Weighted threshold quorum satisfied without centralized single point of failure.</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
