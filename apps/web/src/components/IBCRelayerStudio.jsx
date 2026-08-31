import React, { useState } from 'react';
import { GitCommit, ShieldCheck, CheckCircle2, ArrowRightLeft, RefreshCw, Send, Network, Layers, FileCheck } from 'lucide-react';

export default function IBCRelayerStudio() {
  const [packet, setPacket] = useState({
    sequence: 1,
    sourcePort: 'transfer',
    sourceChannel: 'channel-0',
    destinationPort: 'transfer',
    destinationChannel: 'channel-1',
    data: {
      recipient: 'cosmos1dt...',
      amount: '1000000',
      denom: 'uTRUST'
    },
    timeoutHeight: { revisionNumber: 1, revisionHeight: 120000 }
  });

  const [commitment, setCommitment] = useState(null);
  const [merkleProof, setMerkleProof] = useState(null);
  const [relayResult, setRelayResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleComputeCommitment = () => {
    setLoading(true);
    try {
      const commitmentBytes = '0x' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
      const pathStr = `commitments/ports/${packet.sourcePort}/channels/${packet.sourceChannel}/sequences/${packet.sequence}`;
      setCommitment({
        commitmentPath: pathStr,
        commitmentBytesHex: commitmentBytes,
        packetDataSha256: '0x' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('')
      });
      setMerkleProof(null);
      setRelayResult(null);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateMerkleProof = () => {
    if (!commitment) return;
    const rootHash = '0x' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
    setMerkleProof({
      rootAppHash: rootHash,
      proofType: 'ics23:iavl',
      key: commitment.commitmentPath,
      valueHex: commitment.commitmentBytesHex,
      leafPrefix: '0x00',
      innerOpCount: 3,
      verifiedAgainstAppHash: true
    });
  };

  const handleRelayPacket = () => {
    if (!merkleProof || !commitment) return;
    setRelayResult({
      success: true,
      relayedAt: new Date().toISOString(),
      sourceChainId: 'docutrust-hub-1',
      targetChainId: 'osmosis-1',
      sequence: packet.sequence,
      acknowledgement: 'AQ== (ICS-04 Success)',
      receiptProofValid: true
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-violet-500 to-indigo-600 rounded-xl shadow-lg shadow-violet-500/20">
            <Network className="w-8 h-8 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-2xl font-bold text-white tracking-tight">IBC Relayer & Interchain Studio</h2>
              <span className="px-2.5 py-0.5 text-xs font-semibold bg-violet-500/10 text-violet-400 border border-violet-500/20 rounded-full">
                v15.0 ICS-04 / ICS-23
              </span>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Cosmos Inter-Blockchain Communication (IBC) ICS-04 packet commitment engine, Merkle multi-store state proofs & cross-chain relayer.
            </p>
          </div>
        </div>
        <button
          onClick={handleComputeCommitment}
          disabled={loading}
          className="flex items-center gap-2 px-5 py-2.5 bg-violet-600 hover:bg-violet-500 text-white text-sm font-semibold rounded-xl transition-all shadow-lg shadow-violet-600/25 active:scale-95 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Compute ICS-04 Commitment
        </button>
      </div>

      {/* Grid: Packet Definition & Relay Execution */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Packet Configuration */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <GitCommit className="w-5 h-5 text-violet-400" />
            <h3 className="text-base font-semibold text-white">ICS-04 Packet Configuration</h3>
          </div>

          <div className="space-y-3 text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block font-semibold text-slate-400 uppercase tracking-wider mb-1">Source Port</label>
                <input
                  type="text"
                  value={packet.sourcePort}
                  onChange={(e) => setPacket({ ...packet, sourcePort: e.target.value })}
                  className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-2.5 text-slate-200 font-mono focus:outline-none focus:border-violet-500"
                />
              </div>
              <div>
                <label className="block font-semibold text-slate-400 uppercase tracking-wider mb-1">Source Channel</label>
                <input
                  type="text"
                  value={packet.sourceChannel}
                  onChange={(e) => setPacket({ ...packet, sourceChannel: e.target.value })}
                  className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-2.5 text-slate-200 font-mono focus:outline-none focus:border-violet-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block font-semibold text-slate-400 uppercase tracking-wider mb-1">Dest Port</label>
                <input
                  type="text"
                  value={packet.destinationPort}
                  onChange={(e) => setPacket({ ...packet, destinationPort: e.target.value })}
                  className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-2.5 text-slate-200 font-mono focus:outline-none focus:border-violet-500"
                />
              </div>
              <div>
                <label className="block font-semibold text-slate-400 uppercase tracking-wider mb-1">Dest Channel</label>
                <input
                  type="text"
                  value={packet.destinationChannel}
                  onChange={(e) => setPacket({ ...packet, destinationChannel: e.target.value })}
                  className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-2.5 text-slate-200 font-mono focus:outline-none focus:border-violet-500"
                />
              </div>
            </div>

            <div className="flex gap-3 pt-2">
              <button
                onClick={handleGenerateMerkleProof}
                disabled={!commitment}
                className="flex-1 py-2.5 bg-violet-600 hover:bg-violet-500 text-white font-semibold rounded-xl transition-all shadow-md shadow-violet-600/20 active:scale-95 disabled:opacity-40"
              >
                1. Generate Merkle Proof
              </button>
              <button
                onClick={handleRelayPacket}
                disabled={!merkleProof}
                className="flex-1 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-xl transition-all shadow-md shadow-indigo-600/20 active:scale-95 disabled:opacity-40"
              >
                2. Relay to Target Chain
              </button>
            </div>
          </div>
        </div>

        {/* Commitment & Relay Proof Details */}
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <h3 className="text-base font-semibold text-white">IBC State Proof Verification</h3>
            </div>
            {relayResult && (
              <span className="px-2.5 py-0.5 text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> RELAYED & ACKNOWLEDGED
              </span>
            )}
          </div>

          {commitment ? (
            <div className="space-y-2 text-xs font-mono">
              <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80 space-y-1">
                <div className="text-slate-400"><span className="text-slate-500">Commitment Path:</span> {commitment.commitmentPath}</div>
                <div className="text-slate-400 break-all text-[11px]"><span className="text-slate-500">Bytes Hex:</span> {commitment.commitmentBytesHex}</div>
              </div>

              {merkleProof && (
                <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80 space-y-1">
                  <div className="text-slate-400"><span className="text-slate-500">Proof Spec:</span> {merkleProof.proofType}</div>
                  <div className="text-slate-400 break-all text-[11px]"><span className="text-slate-500">Root AppHash:</span> {merkleProof.rootAppHash}</div>
                </div>
              )}

              {relayResult && (
                <div className="p-3 bg-emerald-950/20 rounded-xl border border-emerald-500/20 text-emerald-300 text-[11px]">
                  ✔ Packet #{relayResult.sequence} relayed from {relayResult.sourceChainId} to {relayResult.targetChainId}. Acknowledgement confirmed.
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
              Compute ICS-04 commitment and generate state proof to simulate cross-chain packet relay.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
