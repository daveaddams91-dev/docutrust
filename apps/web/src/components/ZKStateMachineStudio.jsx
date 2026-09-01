import React, { useState } from 'react';
import { Cpu, ShieldCheck, CheckCircle2, AlertOctagon, DollarSign, RefreshCw, GitCommit, Play, Award } from 'lucide-react';

const dummyHex = (len = 64) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');

export default function ZKStateMachineStudio() {
  const [machineName, setMachineName] = useState('AutonomousEscrow2026');
  const [requiredBond, setRequiredBond] = useState(500);
  const [escrowBounty, setEscrowBounty] = useState(2500);
  const [stateMachineSpec, setStateMachineSpec] = useState(null);
  const [transitionRecord, setTransitionRecord] = useState(null);
  const [disputeReport, setDisputeReport] = useState(null);
  const [settlementResult, setSettlementResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleInitStateMachine = () => {
    setLoading(true);
    setTimeout(() => {
      const spec = {
        machineId: `sm_${dummyHex(8)}`,
        name: machineName,
        initialState: 'INITIALIZED',
        allowedStates: ['INITIALIZED', 'ACTIVE_ESCROW', 'DISPUTED', 'SETTLED'],
        requiredBond: Number(requiredBond),
        escrowBounty: Number(escrowBounty),
        stateRoot: dummyHex(64),
        creatorDid: `did:docutrust:creator:${dummyHex(8)}`,
        createdAt: new Date().toISOString()
      };
      setStateMachineSpec(spec);
      setTransitionRecord(null);
      setDisputeReport(null);
      setSettlementResult(null);
      setLoading(false);
    }, 250);
  };

  const handleExecuteTransition = () => {
    if (!stateMachineSpec) return;
    const proverDid = `did:docutrust:prover:${dummyHex(8)}`;
    const trans = {
      transitionId: `trans_${dummyHex(10)}`,
      machineId: stateMachineSpec.machineId,
      fromState: 'INITIALIZED',
      toState: 'ACTIVE_ESCROW',
      action: 'DEPOSIT_ESCROW_FUNDS',
      proverDid,
      fromStateRoot: stateMachineSpec.stateRoot,
      toStateRoot: dummyHex(64),
      zkProof: {
        proofId: `proof_sm_${dummyHex(8)}`,
        protocol: 'DocuTrustZKStateMachineProof2026',
        fiatShamirChallenge: dummyHex(32),
        traceCommitment: dummyHex(64),
        verified: true
      },
      proverSignature: dummyHex(128),
      timestamp: new Date().toISOString()
    };
    setTransitionRecord(trans);
    setDisputeReport(null);
    setSettlementResult(null);
  };

  const handleDisputeTransition = () => {
    if (!stateMachineSpec || !transitionRecord) return;
    const challengerDid = `did:docutrust:challenger:${dummyHex(8)}`;
    const report = {
      disputeId: `disp_${dummyHex(10)}`,
      transitionId: transitionRecord.transitionId,
      challengerDid,
      disputeReason: 'INVALID_STATE_PRECONDITION',
      arbitrationStatus: 'RESOLVED_REJECTED_TRANSITION_VALID',
      bondSlashingApplied: false,
      challengerReward: 0,
      timestamp: new Date().toISOString()
    };
    setDisputeReport(report);
  };

  const handleSettleStateMachine = () => {
    if (!stateMachineSpec || !transitionRecord) return;
    const settlement = {
      settlementId: `settle_${dummyHex(10)}`,
      machineId: stateMachineSpec.machineId,
      finalState: 'SETTLED',
      finalStateRoot: transitionRecord.toStateRoot,
      payoutRecipientDid: transitionRecord.proverDid,
      payoutAmount: stateMachineSpec.escrowBounty,
      isSettled: true,
      onChainCalldata: `0xa084${transitionRecord.toStateRoot.slice(0, 32)}`,
      settledAt: new Date().toISOString()
    };
    setSettlementResult(settlement);
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8">
      <div className="border-b border-gray-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-amber-500/10 rounded-xl text-amber-400 border border-amber-500/20">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              ZK Multi-Party State Machine & Verifiable Escrow Studio
              <span className="text-xs px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30">v21.0.0</span>
            </h1>
            <p className="text-gray-400 text-sm mt-1">
              Verifiable state transition execution, Fiat-Shamir execution trace zero-knowledge proofs, optimistic dispute arbitration, and automated bounty settlement.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Setup */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-amber-400" />
              State Machine Specification
            </h2>

            <div>
              <label className="text-xs text-gray-400 block mb-1">State Machine Name</label>
              <input
                type="text"
                value={machineName}
                onChange={(e) => setMachineName(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-amber-500 text-xs"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Required Bond ($)</label>
                <input
                  type="number"
                  value={requiredBond}
                  onChange={(e) => setRequiredBond(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-amber-500 text-xs"
                />
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1">Escrow Bounty ($)</label>
                <input
                  type="number"
                  value={escrowBounty}
                  onChange={(e) => setEscrowBounty(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-amber-500 text-xs"
                />
              </div>
            </div>

            <button
              onClick={handleInitStateMachine}
              disabled={loading}
              className="w-full py-2.5 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white font-medium rounded-lg text-sm flex items-center justify-center gap-2 shadow-lg shadow-amber-600/20"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Cpu className="w-4 h-4" />}
              Initialize ZK State Machine
            </button>
          </div>

          {stateMachineSpec && (
            <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-3">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Transition Actions</h3>
              <button
                onClick={handleExecuteTransition}
                className="w-full py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-white font-medium rounded-lg text-xs flex items-center justify-center gap-2"
              >
                <Play className="w-3.5 h-3.5 text-amber-400" />
                Execute Verifiable ZK Transition
              </button>
              {transitionRecord && (
                <>
                  <button
                    onClick={handleDisputeTransition}
                    className="w-full py-2 bg-rose-600/20 hover:bg-rose-600/30 border border-rose-500/30 text-rose-300 font-medium rounded-lg text-xs flex items-center justify-center gap-2"
                  >
                    <AlertOctagon className="w-3.5 h-3.5" />
                    Simulate Optimistic Dispute
                  </button>
                  <button
                    onClick={handleSettleStateMachine}
                    className="w-full py-2 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-300 font-medium rounded-lg text-xs flex items-center justify-center gap-2"
                  >
                    <DollarSign className="w-3.5 h-3.5" />
                    Settle Escrow & Release Bounty
                  </button>
                </>
              )}
            </div>
          )}
        </div>

        {/* Right: Output */}
        <div className="lg:col-span-2 space-y-6">
          {stateMachineSpec ? (
            <div className="space-y-6">
              {/* Spec Header */}
              <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                    {stateMachineSpec.name} ({stateMachineSpec.machineId})
                  </span>
                  <span className="text-xs text-gray-400">
                    Initial State: <span className="text-emerald-400 font-semibold">{stateMachineSpec.initialState}</span>
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="bg-gray-950/60 p-3 rounded-lg border border-gray-800">
                    <div className="text-gray-400">Required Prover Bond</div>
                    <div className="text-sm font-bold text-white mt-0.5">${stateMachineSpec.requiredBond}</div>
                  </div>
                  <div className="bg-gray-950/60 p-3 rounded-lg border border-gray-800">
                    <div className="text-gray-400">Escrow Bounty Pool</div>
                    <div className="text-sm font-bold text-amber-400 mt-0.5">${stateMachineSpec.escrowBounty}</div>
                  </div>
                </div>
              </div>

              {/* ZK Transition Record */}
              {transitionRecord && (
                <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                      <GitCommit className="w-4 h-4 text-amber-400" />
                      State Transition Record ({transitionRecord.fromState} &rarr; {transitionRecord.toState})
                    </h3>
                    <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                      ZK Verified
                    </span>
                  </div>
                  <div className="bg-gray-950/80 p-3.5 rounded-lg border border-gray-800 text-xs font-mono space-y-1 text-gray-300">
                    <div><span className="text-gray-500">Action:</span> {transitionRecord.action}</div>
                    <div><span className="text-gray-500">Prover DID:</span> {transitionRecord.proverDid}</div>
                    <div><span className="text-gray-500">To State Root:</span> {transitionRecord.toStateRoot.slice(0, 32)}...</div>
                    <div><span className="text-gray-500">ZK Trace Commitment:</span> {transitionRecord.zkProof.traceCommitment.slice(0, 32)}...</div>
                  </div>
                </div>
              )}

              {/* Dispute Output */}
              {disputeReport && (
                <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-2">
                  <h3 className="text-sm font-semibold text-rose-300 flex items-center gap-2">
                    <AlertOctagon className="w-4 h-4 text-rose-400" />
                    Dispute Arbitration Resolution
                  </h3>
                  <div className="bg-gray-950/80 p-3 rounded-lg border border-gray-800 text-xs font-mono space-y-1 text-gray-300">
                    <div><span className="text-gray-500">Arbitration Status:</span> <span className="text-emerald-400 font-semibold">{disputeReport.arbitrationStatus}</span></div>
                    <div><span className="text-gray-500">Challenger DID:</span> {disputeReport.challengerDid}</div>
                    <div><span className="text-gray-500">Bond Slashing:</span> None (Transition validly proven)</div>
                  </div>
                </div>
              )}

              {/* Settlement Output */}
              {settlementResult && (
                <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-xl p-5 space-y-3">
                  <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
                    <CheckCircle2 className="w-5 h-5" />
                    Escrow Settled & Bounty Distributed
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-xs text-gray-300">
                    <div className="bg-gray-950/60 p-2.5 rounded border border-gray-800">
                      <div className="text-gray-500 text-[10px]">Payout Beneficiary</div>
                      <div className="text-white font-mono truncate mt-0.5">{settlementResult.payoutRecipientDid}</div>
                    </div>
                    <div className="bg-gray-950/60 p-2.5 rounded border border-gray-800">
                      <div className="text-gray-500 text-[10px]">Settled Amount</div>
                      <div className="text-emerald-400 font-bold mt-0.5">${settlementResult.payoutAmount}</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-gray-900/40 border border-gray-800 border-dashed rounded-xl p-12 text-center text-gray-500 flex flex-col items-center justify-center space-y-3">
              <Cpu className="w-10 h-10 text-gray-600" />
              <p className="text-sm">Configure parameters and click "Initialize ZK State Machine" to start.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
