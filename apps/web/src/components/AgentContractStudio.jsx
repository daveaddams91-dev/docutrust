import React, { useState } from 'react';
import { Cpu, ShieldAlert, CheckCircle, ShieldCheck, Coins, AlertTriangle, ArrowRight, FileCode2, Play } from 'lucide-react';

const dummyHex = (len = 64) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');

export default function AgentContractStudio() {
  const [principalDid, setPrincipalDid] = useState('did:docutrust:enterprise:principal_01');
  const [agentDid, setAgentDid] = useState('did:docutrust:agent:deep_analyst_v4');
  const [bountyAmount, setBountyAmount] = useState(2500);
  const [agentStakeAmount, setAgentStakeAmount] = useState(1000);
  const [contract, setContract] = useState(null);
  const [executionReceipt, setExecutionReceipt] = useState(null);
  const [disputeResult, setDisputeResult] = useState(null);
  const [settlementResult, setSettlementResult] = useState(null);

  const handleCreateContract = () => {
    try {
      const c = {
        contractId: 'act_' + Math.floor(Math.random() * 100000),
        principalDid,
        agentDid,
        specification: {
          taskType: 'FINANCIAL_AUDIT_SYNTHESIS',
          description: 'Synthesize verifiable quarterly proof ledger and verify solvency',
          inputParameters: { datasetCid: 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi' }
        },
        escrow: {
          bountyAmount: Number(bountyAmount),
          agentStake: Number(agentStakeAmount),
          currency: 'USDC',
          lockedAt: new Date().toISOString()
        },
        challengeWindowSeconds: 3600,
        status: 'INITIALIZED',
        createdAt: new Date().toISOString()
      };
      setContract(c);
      setExecutionReceipt(null);
      setDisputeResult(null);
      setSettlementResult(null);
    } catch (e) {
      alert('Contract creation failed: ' + e.message);
    }
  };

  const handleExecuteValidTrace = () => {
    if (!contract) return;
    try {
      const steps = [
        { action: 'FETCH_LEDGER', stateHash: '0x1111' },
        { action: 'ZK_VERIFY_SOLVENCY', stateHash: '0x2222' },
        { action: 'COMMIT_MERKLE_ROOT', stateHash: '0x3333' }
      ];
      const receipt = {
        receiptId: 'rcpt_' + Math.floor(Math.random() * 100000),
        contractId: contract.contractId,
        outputResult: { solvencyRatio: 1.45, auditedAssetsUsd: 150000000 },
        executionSteps: steps,
        traceRoot: '0x' + dummyHex(64),
        submittedAt: new Date().toISOString()
      };
      setContract({ ...contract, status: 'SUBMITTED' });
      setExecutionReceipt(receipt);
      setDisputeResult(null);
      setSettlementResult(null);
    } catch (e) {
      alert('Execution submission failed: ' + e.message);
    }
  };

  const handleSimulateDispute = () => {
    if (!contract || !executionReceipt) return;
    try {
      const dispute = {
        disputeId: 'dsp_' + Math.floor(Math.random() * 100000),
        contractId: contract.contractId,
        challengerDid: 'did:docutrust:challenger:watchdog_09',
        disputeReason: 'State transition fraud detected at step 1',
        invalidStepIndex: 1,
        actualStepHash: '0x2222',
        slashedStakeAmount: contract.escrow.agentStake,
        bountyAwarded: contract.escrow.bountyAmount,
        slashingProofHex: dummyHex(64),
        resolvedAt: new Date().toISOString()
      };
      setContract({ ...contract, status: 'SLASHED' });
      setDisputeResult({ valid: true, dispute, updatedContract: { ...contract, status: 'SLASHED' } });
      setSettlementResult(null);
    } catch (e) {
      alert('Dispute failed: ' + e.message);
    }
  };

  const handleSettle = () => {
    if (!contract || !executionReceipt) return;
    try {
      const res = {
        settlementId: 'stl_' + Math.floor(Math.random() * 100000),
        contractId: contract.contractId,
        agentPayout: contract.escrow.bountyAmount + contract.escrow.agentStake,
        settledAt: new Date().toISOString()
      };
      setContract({ ...contract, status: 'SETTLED' });
      setSettlementResult({ valid: true, settlement: res, updatedContract: { ...contract, status: 'SETTLED' } });
      setDisputeResult(null);
    } catch (e) {
      alert('Settlement failed: ' + e.message);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-amber-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 bg-amber-500/10 border border-amber-500/20 text-amber-400 rounded-full text-xs font-semibold uppercase tracking-wider mb-2">
              <Cpu className="w-3.5 h-3.5" /> DocuTrust v19.0.0
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
              Autonomous AI Agent Smart Contract & Slashing Studio
            </h2>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl">
              Verifiable agent task escrows, stateful execution trace commitments, fraud-proof challenge windows, and automated cryptographic slashing.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Step 1: Create Escrow Contract */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <Coins className="w-4 h-4 text-amber-400" /> 1. Task Escrow Contract
          </h3>
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Principal DID</label>
              <input
                type="text"
                value={principalDid}
                onChange={(e) => setPrincipalDid(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 text-xs font-mono focus:border-amber-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Assigned Agent DID</label>
              <input
                type="text"
                value={agentDid}
                onChange={(e) => setAgentDid(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 text-xs font-mono focus:border-amber-500 focus:outline-none"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Bounty ($TRUST)</label>
                <input
                  type="number"
                  value={bountyAmount}
                  onChange={(e) => setBountyAmount(parseInt(e.target.value, 10))}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 text-xs font-mono focus:border-amber-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Agent Stake ($TRUST)</label>
                <input
                  type="number"
                  value={agentStakeAmount}
                  onChange={(e) => setAgentStakeAmount(parseInt(e.target.value, 10))}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 text-xs font-mono focus:border-amber-500 focus:outline-none"
                />
              </div>
            </div>
            <button
              onClick={handleCreateContract}
              className="w-full py-2.5 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold transition flex items-center justify-center gap-2 shadow-lg shadow-amber-600/30"
            >
              <FileCode2 className="w-4 h-4" /> Instantiate Verifiable Escrow
            </button>
          </div>
        </div>

        {/* Step 2: Agent Execution Trace */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <Play className="w-4 h-4 text-cyan-400" /> 2. Agent Execution Trace
          </h3>
          <p className="text-xs text-slate-400">
            The autonomous AI agent executes sub-tasks and computes cryptographic state root commitments for every action.
          </p>
          <button
            onClick={handleExecuteValidTrace}
            disabled={!contract || contract.status !== 'ACTIVE'}
            className="w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold transition flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/30 disabled:opacity-40"
          >
            <Play className="w-4 h-4" /> Submit Verifiable Execution Trace
          </button>

          {executionReceipt && (
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs space-y-2 font-mono">
              <div className="flex justify-between text-slate-300">
                <span>Receipt:</span> <span className="text-cyan-300 font-bold">{executionReceipt.receiptId}</span>
              </div>
              <div className="text-[10px] text-slate-400">
                Trace Root: <span className="text-slate-200">{executionReceipt.traceCommitmentHash.substring(0, 20)}...</span>
              </div>
              <div className="text-[10px] text-emerald-400">Status: CHALLENGE_WINDOW_OPEN</div>
            </div>
          )}
        </div>

        {/* Step 3: Challenge, Slashing or Settlement */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" /> 3. Dispute or Settle
          </h3>
          <p className="text-xs text-slate-400">
            During the challenge window, challengers can submit fraud proofs. If valid, the agent's collateral is slashed. Otherwise, bounty is settled.
          </p>
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={handleSimulateDispute}
              disabled={!executionReceipt || contract?.status !== 'PENDING_CHALLENGE'}
              className="py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold transition disabled:opacity-40 flex items-center justify-center gap-1"
            >
              <ShieldAlert className="w-3.5 h-3.5" /> Challenge & Slash
            </button>
            <button
              onClick={handleSettle}
              disabled={!executionReceipt || contract?.status !== 'PENDING_CHALLENGE'}
              className="py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold transition disabled:opacity-40 flex items-center justify-center gap-1"
            >
              <CheckCircle className="w-3.5 h-3.5" /> Settle Escrow
            </button>
          </div>

          {disputeResult && (
            <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-3 text-xs space-y-1 text-rose-300">
              <div className="font-bold flex items-center gap-1.5 text-rose-400">
                <AlertTriangle className="w-4 h-4" /> Agent Slashed: {disputeResult.slashed ? 'YES' : 'NO'}
              </div>
              <div className="font-mono text-[10px] text-slate-300">
                Slashed Collateral: {disputeResult.slashingReceipt?.slashedAmount} $TRUST distributed to challenger
              </div>
            </div>
          )}

          {settlementResult && (
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-3 text-xs space-y-1 text-emerald-300">
              <div className="font-bold flex items-center gap-1.5 text-emerald-400">
                <CheckCircle className="w-4 h-4" /> Escrow Successfully Settled
              </div>
              <div className="font-mono text-[10px] text-slate-300">
                Bounty of {settlementResult.settledAmount} $TRUST released to Agent DID
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
