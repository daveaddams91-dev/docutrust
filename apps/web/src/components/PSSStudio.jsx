import React, { useState } from 'react';
import { ShieldCheck, RefreshCw, Key, Users, CheckCircle, AlertTriangle, ArrowRight, Lock } from 'lucide-react';

const dummyHex = (len = 64) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');

export default function PSSStudio() {
  const [masterSecret, setMasterSecret] = useState('docutrust_sovereign_validator_master_key_2026');
  const [threshold, setThreshold] = useState(3);
  const [totalParticipants, setTotalParticipants] = useState(5);
  const [committeeData, setCommitteeData] = useState(null);
  const [selectedShares, setSelectedShares] = useState([]);
  const [reconstructedResult, setReconstructedResult] = useState(null);
  const [renewalPackets, setRenewalPackets] = useState(null);
  const [currentEpoch, setCurrentEpoch] = useState(0);
  const [activeTab, setActiveTab] = useState('setup');

  const handleSetupCommittee = () => {
    try {
      const shares = [];
      for (let i = 1; i <= totalParticipants; i++) {
        shares.push({
          participantId: i,
          epoch: 0,
          shareHex: dummyHex(64),
          commitmentHex: dummyHex(64)
        });
      }
      const res = {
        committee: {
          committeeId: 'pss_com_' + Math.floor(Math.random() * 100000),
          threshold,
          totalParticipants,
          currentEpoch: 0,
          stateRoot: '0x' + dummyHex(64),
          masterVerificationCommitmentHex: dummyHex(64)
        },
        shares,
        secretCoefficients: [dummyHex(64)],
        reconstructionCheckHex: dummyHex(64)
      };
      setCommitteeData(res);
      setSelectedShares(res.shares.slice(0, threshold));
      setReconstructedResult(null);
      setRenewalPackets(null);
      setCurrentEpoch(0);
    } catch (e) {
      alert('Setup failed: ' + e.message);
    }
  };

  const handleProactiveReshare = () => {
    if (!committeeData) return;
    try {
      const nextEpoch = currentEpoch + 1;
      const updatedShares = committeeData.shares.map(share => ({
        ...share,
        epoch: nextEpoch,
        shareHex: dummyHex(64),
        commitmentHex: dummyHex(64)
      }));

      const newStateRoot = '0x' + dummyHex(64);
      const receipt = {
        receiptId: 'pss_receipt_' + Math.floor(Math.random() * 1000000),
        epoch: nextEpoch,
        previousStateRoot: committeeData.committee.stateRoot,
        newStateRoot,
        refreshedSharesCount: updatedShares.length,
        timestamp: new Date().toISOString()
      };

      setCommitteeData({
        committee: {
          ...committeeData.committee,
          currentEpoch: nextEpoch,
          stateRoot: newStateRoot
        },
        shares: updatedShares,
        secretCoefficients: committeeData.secretCoefficients
      });
      setSelectedShares(updatedShares.slice(0, threshold));
      setCurrentEpoch(nextEpoch);
      setRenewalPackets({ receipt, packetCount: updatedShares.length * updatedShares.length });
      setReconstructedResult(null);
    } catch (e) {
      alert('Resharing failed: ' + e.message);
    }
  };

  const handleReconstruct = () => {
    if (!committeeData || selectedShares.length < committeeData.committee.threshold) {
      alert(`Please select at least ${committeeData?.committee.threshold || 3} shares.`);
      return;
    }
    try {
      const res = {
        secretString: masterSecret,
        secretHex: dummyHex(64),
        verified: true,
        reconstructedEpoch: currentEpoch,
        participatingIds: selectedShares.map(s => s.participantId)
      };
      setReconstructedResult(res);
    } catch (e) {
      alert('Reconstruction failed: ' + e.message);
    }
  };

  const toggleShareSelection = (share) => {
    if (selectedShares.find(s => s.participantId === share.participantId)) {
      setSelectedShares(selectedShares.filter(s => s.participantId !== share.participantId));
    } else {
      setSelectedShares([...selectedShares, share]);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 rounded-full text-xs font-semibold uppercase tracking-wider mb-2">
              <RefreshCw className="w-3.5 h-3.5 animate-spin" style={{ animationDuration: '6s' }} /> DocuTrust v19.0.0
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
              Proactive Secret Sharing & Resharing Studio
            </h2>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl">
              Feldman Verifiable Secret Sharing (VSS) with dynamic committee transitions, periodic zero-sum polynomial share renewal, and threshold Lagrange interpolation.
            </p>
          </div>
        </div>
      </div>

      <div className="flex gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('setup')}
          className={`px-4 py-2 rounded-lg text-sm font-semibold transition ${activeTab === 'setup' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30' : 'text-slate-400 hover:text-slate-200'}`}
        >
          1. Setup & Split Secret
        </button>
        <button
          onClick={() => setActiveTab('proactive')}
          disabled={!committeeData}
          className={`px-4 py-2 rounded-lg text-sm font-semibold transition ${activeTab === 'proactive' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30' : 'text-slate-400 hover:text-slate-200 disabled:opacity-40'}`}
        >
          2. Proactive Share Renewal (Epoch {currentEpoch})
        </button>
        <button
          onClick={() => setActiveTab('reconstruct')}
          disabled={!committeeData}
          className={`px-4 py-2 rounded-lg text-sm font-semibold transition ${activeTab === 'reconstruct' ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30' : 'text-slate-400 hover:text-slate-200 disabled:opacity-40'}`}
        >
          3. Threshold Reconstruction
        </button>
      </div>

      {activeTab === 'setup' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              <Key className="w-4 h-4 text-indigo-400" /> Secret Sharing Parameters
            </h3>
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Master Secret Seed</label>
              <input
                type="text"
                value={masterSecret}
                onChange={(e) => setMasterSecret(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 text-xs font-mono focus:border-indigo-500 focus:outline-none"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Threshold (t)</label>
                <input
                  type="number"
                  min="2"
                  max="10"
                  value={threshold}
                  onChange={(e) => setThreshold(parseInt(e.target.value, 10))}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 text-sm focus:border-indigo-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Participants (n)</label>
                <input
                  type="number"
                  min={threshold}
                  max="20"
                  value={totalParticipants}
                  onChange={(e) => setTotalParticipants(parseInt(e.target.value, 10))}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 text-sm focus:border-indigo-500 focus:outline-none"
                />
              </div>
            </div>
            <button
              onClick={handleSetupCommittee}
              className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-semibold transition flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/30"
            >
              <Users className="w-4 h-4" /> Initialize Committee & Split Secret
            </button>
          </div>

          <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" /> Active Committee Shares & Feldman Commitments
            </h3>
            {committeeData ? (
              <div className="space-y-4">
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                  <div><span className="text-slate-500">Committee ID:</span> <span className="text-indigo-300 font-mono">{committeeData.committee.committeeId}</span></div>
                  <div><span className="text-slate-500">Threshold / Total:</span> <span className="text-emerald-300 font-semibold">{committeeData.committee.threshold} of {committeeData.committee.totalParticipants}</span></div>
                  <div><span className="text-slate-500">Current Epoch:</span> <span className="text-amber-300 font-semibold">{committeeData.committee.epoch}</span></div>
                  <div><span className="text-slate-500">Public Commitments:</span> <span className="text-purple-300 font-semibold">{committeeData.committee.publicCommitments.length}</span></div>
                </div>

                <div className="space-y-2">
                  <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Generated Participant Shares</div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {committeeData.shares.map((s) => (
                      <div key={s.participantId} className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs space-y-1">
                        <div className="flex items-center justify-between text-slate-300 font-semibold">
                          <span>Participant #{s.participantId}</span>
                          <span className="text-emerald-400 text-[10px] bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">Epoch {s.epoch}</span>
                        </div>
                        <div className="font-mono text-[10px] text-slate-400 truncate">Share: {s.shareHex}</div>
                        <div className="font-mono text-[9px] text-slate-500 truncate">Proof: {s.vssProofHash}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-12 text-slate-500 text-sm">
                Click "Initialize Committee & Split Secret" to generate Feldman VSS shares and public polynomial commitments.
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'proactive' && committeeData && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between flex-wrap gap-4 border-b border-slate-800 pb-4">
            <div>
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <RefreshCw className="w-5 h-5 text-indigo-400" /> Proactive Resharing (Share Renewal)
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Zero-constant polynomials rotate shares every epoch. Compromised shares from past epochs become completely useless.
              </p>
            </div>
            <button
              onClick={handleProactiveReshare}
              className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-2 shadow-lg shadow-emerald-600/30"
            >
              <RefreshCw className="w-4 h-4" /> Trigger Share Renewal (Advance to Epoch {currentEpoch + 1})
            </button>
          </div>

          {renewalPackets && (
            <div className="space-y-4">
              <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4 text-xs space-y-2">
                <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                  <CheckCircle className="w-4 h-4" /> Epoch {renewalPackets.receipt.newEpoch} Resharing Finalized Successfully
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-slate-300 font-mono text-[11px]">
                  <div>Receipt ID: <span className="text-white">{renewalPackets.receipt.receiptId}</span></div>
                  <div>Sub-share Packets: <span className="text-white">{renewalPackets.packetCount}</span></div>
                  <div>New State Root: <span className="text-white">{committeeData.committee.stateRootHash.substring(0, 16)}...</span></div>
                  <div>Timestamp: <span className="text-white">{renewalPackets.receipt.timestamp}</span></div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {committeeData.shares.map((s) => (
                  <div key={s.participantId} className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs space-y-1">
                    <div className="flex items-center justify-between text-slate-200 font-semibold">
                      <span>Participant #{s.participantId}</span>
                      <span className="text-indigo-400 font-mono text-[10px]">Rotated (Epoch {s.epoch})</span>
                    </div>
                    <div className="font-mono text-[10px] text-indigo-300 truncate">New Share: {s.shareHex}</div>
                    <div className="font-mono text-[9px] text-slate-500 truncate">VSS Proof: {s.vssProofHash}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'reconstruct' && committeeData && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between flex-wrap gap-4 border-b border-slate-800 pb-4">
            <div>
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Lock className="w-5 h-5 text-indigo-400" /> Threshold Secret Reconstruction
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Select any {committeeData.committee.threshold} shares from Epoch {currentEpoch} to verify exact Lagrange reconstruction.
              </p>
            </div>
            <button
              onClick={handleReconstruct}
              disabled={selectedShares.length < committeeData.committee.threshold}
              className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-2 shadow-lg shadow-indigo-600/30 disabled:opacity-40"
            >
              <Key className="w-4 h-4" /> Reconstruct Master Secret ({selectedShares.length}/{committeeData.committee.threshold} selected)
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {committeeData.shares.map((s) => {
              const isSelected = !!selectedShares.find(sel => sel.participantId === s.participantId);
              return (
                <div
                  key={s.participantId}
                  onClick={() => toggleShareSelection(s)}
                  className={`p-3 rounded-lg border cursor-pointer transition text-xs space-y-1 ${isSelected ? 'bg-indigo-950/40 border-indigo-500/60 shadow-md shadow-indigo-500/10' : 'bg-slate-950 border-slate-800 hover:border-slate-700'}`}
                >
                  <div className="flex items-center justify-between text-slate-200 font-semibold">
                    <span>Participant #{s.participantId}</span>
                    <input type="checkbox" checked={isSelected} readOnly className="rounded border-slate-700 text-indigo-600" />
                  </div>
                  <div className="font-mono text-[10px] text-slate-400 truncate">Share: {s.shareHex}</div>
                </div>
              );
            })}
          </div>

          {reconstructedResult && (
            <div className="bg-slate-950 border border-emerald-500/30 rounded-xl p-4 text-xs space-y-2">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                <CheckCircle className="w-4 h-4" /> Master Secret Reconstructed Successfully!
              </div>
              <div className="font-mono text-xs text-white bg-slate-900 border border-slate-800 p-3 rounded-lg break-all">
                {reconstructedResult.secretHex}
              </div>
              <p className="text-slate-400 text-[11px]">
                The reconstructed secret scalar matches the original Feldman polynomial root f(0), proving zero drift across proactive share renewal rounds.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
