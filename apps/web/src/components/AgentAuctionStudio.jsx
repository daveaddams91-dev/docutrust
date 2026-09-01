import React, { useState } from 'react';
import { Gavel, CheckCircle2, AlertTriangle, ShieldCheck, DollarSign, ArrowRight, FileCode, CheckCircle, RefreshCw } from 'lucide-react';

const dummyHex = (len = 64) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');

export default function AgentAuctionStudio() {
  const [auctioneerDid, setAuctioneerDid] = useState('did:docutrust:auctioneer:coordinator_01');
  const [taskType, setTaskType] = useState('VERIFIABLE_ML_TRAINING');
  const [maxBudget, setMaxBudget] = useState(5000);
  const [auction, setAuction] = useState(null);

  const [bids, setBids] = useState([
    { agentDid: 'did:docutrust:agent:alpha_prover', bidAmount: 1800, stakeAmount: 600, salt: 'salt_alpha_99', status: 'UNCOMMITTED', commitmentId: null },
    { agentDid: 'did:docutrust:agent:beta_compute', bidAmount: 2200, stakeAmount: 600, salt: 'salt_beta_88', status: 'UNCOMMITTED', commitmentId: null },
    { agentDid: 'did:docutrust:agent:gamma_solver', bidAmount: 2900, stakeAmount: 600, salt: 'salt_gamma_77', status: 'UNCOMMITTED', commitmentId: null }
  ]);

  const [clearingResult, setClearingResult] = useState(null);
  const [settlementReceipt, setSettlementReceipt] = useState(null);

  const handleCreateAuction = () => {
    const auc = {
      auctionId: `auc_${Math.floor(Math.random() * 100000)}`,
      auctioneerDid,
      taskSpec: {
        taskType,
        description: 'Decentralized verifiable task procurement auction',
        maxBudget: Number(maxBudget),
        deadlineEpoch: Math.floor(Date.now() / 1000) + 7200,
        requiredCapabilities: ['GROTH16', 'GPU_ACCELERATED']
      },
      status: 'BIDDING',
      commitments: [],
      revealedBids: [],
      createdAt: new Date().toISOString()
    };
    setAuction(auc);
    setClearingResult(null);
    setSettlementReceipt(null);
  };

  const handleCommitBids = () => {
    if (!auction) return;
    const updatedBids = bids.map(b => {
      const commitmentId = `comm_${dummyHex(8)}`;
      return {
        ...b,
        status: 'COMMITTED',
        commitmentId
      };
    });
    setBids(updatedBids);
    setAuction({
      ...auction,
      status: 'REVEALING',
      commitments: updatedBids.map(b => ({ commitmentId: b.commitmentId, agentDid: b.agentDid, commitmentHash: '0x' + dummyHex(64) }))
    });
  };

  const handleRevealBids = () => {
    if (!auction) return;
    const updatedBids = bids.map(b => ({ ...b, status: 'REVEALED' }));
    setBids(updatedBids);
    setAuction({
      ...auction,
      revealedBids: updatedBids.map(b => ({
        commitmentId: b.commitmentId,
        agentDid: b.agentDid,
        bidAmount: b.bidAmount,
        stakeAmount: b.stakeAmount,
        revealedAt: new Date().toISOString()
      }))
    });
  };

  const handleClearAuction = () => {
    if (!auction || auction.revealedBids.length === 0) return;
    // Sort ascending for procurement (lowest bid wins, clearing price is second lowest)
    const sorted = [...auction.revealedBids].sort((a, b) => a.bidAmount - b.bidAmount);
    const winner = sorted[0];
    const secondPrice = sorted.length > 1 ? sorted[1].bidAmount : winner.bidAmount;

    const result = {
      auctionId: auction.auctionId,
      winnerAgentDid: winner.agentDid,
      winningBid: winner.bidAmount,
      clearingPrice: secondPrice, // Vickrey second-price
      totalEscrowLocked: secondPrice + winner.stakeAmount,
      clearedAt: new Date().toISOString()
    };

    setClearingResult(result);
    setAuction({ ...auction, status: 'CLEARED' });
  };

  const handleSettle = () => {
    if (!clearingResult) return;
    const receipt = {
      settlementId: `settle_auc_${dummyHex(8)}`,
      auctionId: clearingResult.auctionId,
      winnerAgentDid: clearingResult.winnerAgentDid,
      payoutAmount: clearingResult.clearingPrice,
      returnedStake: 600,
      settlementTimestamp: new Date().toISOString(),
      status: 'SETTLED'
    };
    setSettlementReceipt(receipt);
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8">
      <div className="border-b border-gray-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-emerald-500/10 rounded-xl text-emerald-400 border border-emerald-500/20">
            <Gavel className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              Decentralized AI Agent Capability Auction Studio
              <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">v20.0.0</span>
            </h1>
            <p className="text-gray-400 text-sm mt-1">
              Verifiable commit-reveal Vickrey second-price capability procurement auction protocol with automated escrow settlement and slashing.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Auction Parameters */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Gavel className="w-4 h-4 text-emerald-400" />
              Procurement Auction Spec
            </h2>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Auctioneer DID</label>
              <input
                type="text"
                value={auctioneerDid}
                onChange={(e) => setAuctioneerDid(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Task Type</label>
              <select
                value={taskType}
                onChange={(e) => setTaskType(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-emerald-500"
              >
                <option value="VERIFIABLE_ML_TRAINING">Verifiable ML Model Training</option>
                <option value="ZK_SNARK_PROVER">ZK-SNARK Distributed Prover</option>
                <option value="ORACLE_CROSSCHAIN_RELAY">Cross-Chain Oracle Relay</option>
              </select>
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Maximum Budget (USDC)</label>
              <input
                type="number"
                value={maxBudget}
                onChange={(e) => setMaxBudget(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <button
              onClick={handleCreateAuction}
              className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium text-xs flex items-center justify-center gap-2 transition"
            >
              <Gavel className="w-4 h-4" />
              Create Procurement Auction
            </button>
          </div>

          {auction && (
            <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-3">
              <h3 className="text-xs font-semibold text-gray-400">Auction Lifecycle Controls</h3>
              <button
                onClick={handleCommitBids}
                disabled={auction.status !== 'BIDDING'}
                className="w-full py-2 px-3 bg-gray-800 hover:bg-gray-700 text-xs text-gray-200 rounded-lg disabled:opacity-50"
              >
                1. Commit Sealed Bids
              </button>
              <button
                onClick={handleRevealBids}
                disabled={auction.status !== 'REVEALING'}
                className="w-full py-2 px-3 bg-blue-600 hover:bg-blue-500 text-xs text-white rounded-lg disabled:opacity-50"
              >
                2. Reveal Sealed Bids
              </button>
              <button
                onClick={handleClearAuction}
                disabled={auction.revealedBids.length === 0 || clearingResult !== null}
                className="w-full py-2 px-3 bg-purple-600 hover:bg-purple-500 text-xs text-white rounded-lg disabled:opacity-50"
              >
                3. Clear Vickrey Second-Price
              </button>
              {clearingResult && (
                <button
                  onClick={handleSettle}
                  disabled={settlementReceipt !== null}
                  className="w-full py-2 px-3 bg-emerald-600 hover:bg-emerald-500 text-xs text-white rounded-lg disabled:opacity-50"
                >
                  4. Settle Escrow Payout
                </button>
              )}
            </div>
          )}
        </div>

        {/* Bids & Clearing Visualizer */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center justify-between">
              <span>Sealed Autonomous Agent Bids</span>
              <span className="text-xs text-gray-400">Protocol: Vickrey Reverse Auction</span>
            </h3>

            <div className="space-y-3">
              {bids.map((b, idx) => (
                <div key={idx} className="p-4 bg-gray-950 border border-gray-800 rounded-xl flex items-center justify-between">
                  <div>
                    <div className="font-mono text-xs font-semibold text-emerald-300">{b.agentDid}</div>
                    <div className="text-xs text-gray-400 mt-1">
                      Bid Amount: <span className="text-gray-200 font-semibold">${b.bidAmount}</span> | Bond Stake: <span className="text-gray-200 font-semibold">${b.stakeAmount}</span>
                    </div>
                  </div>
                  <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${
                    b.status === 'REVEALED' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                    b.status === 'COMMITTED' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                    'bg-gray-800 text-gray-400'
                  }`}>
                    {b.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {clearingResult && (
            <div className="bg-purple-950/20 border border-purple-500/40 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold text-purple-300">Vickrey Auction Clearing Result</span>
                <span className="text-xs px-2 py-0.5 rounded bg-purple-500/20 text-purple-400 border border-purple-500/30 font-semibold">
                  AUCTION CLEARED
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                  <span className="text-gray-500 block">Winning Agent</span>
                  <span className="font-mono text-purple-300 font-semibold">{clearingResult.winnerAgentDid}</span>
                </div>
                <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                  <span className="text-gray-500 block">Winner's Bid</span>
                  <span className="text-gray-300 font-semibold">${clearingResult.winningBid}</span>
                </div>
                <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                  <span className="text-emerald-400 block">Second-Price Clearing Rate</span>
                  <span className="text-emerald-300 font-bold">${clearingResult.clearingPrice}</span>
                </div>
              </div>
            </div>
          )}

          {settlementReceipt && (
            <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-xl p-5 space-y-3">
              <div className="flex items-center gap-2 text-emerald-400 text-sm font-semibold">
                <CheckCircle className="w-4 h-4" />
                Escrow Settlement Completed
              </div>
              <pre className="p-3 bg-gray-950 border border-gray-800 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto">
                {JSON.stringify(settlementReceipt, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
