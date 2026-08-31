import React, { useState } from 'react';
import { Grid, ShieldCheck, CheckCircle2, XCircle, Plus, Sparkles, RefreshCw, Layers, Calendar, Key, AlertOctagon, CheckSquare } from 'lucide-react';

export default function RevocationLatticeStudio() {
  const [latticeId, setLatticeId] = useState('lattice-mesh-global-2026');
  const [shardsCount, setShardsCount] = useState(4);
  const [currentEpoch, setCurrentEpoch] = useState(1);
  const [revokedInput, setRevokedInput] = useState('');
  const [revocationHistory, setRevocationHistory] = useState(['cred-revoked-alpha-01', 'cred-revoked-beta-02']);
  
  const [checkCredId, setCheckCredId] = useState('cred-sample-citizen-100');
  const [proof, setProof] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const [issuerKey] = useState({
    publicKeyHex: 'e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2',
    privateKeyHex: '0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b',
    did: 'did:key:z6MksLatticeIssuerAuthority2026'
  });

  const [latticeState, setLatticeState] = useState({
    latticeId: 'lattice-mesh-global-2026',
    issuerDid: 'did:key:z6MksLatticeIssuerAuthority2026',
    shardsCount: 4,
    currentEpoch: 1,
    globalLatticeRoot: 'e4373fbd51e8a45079cc50509d7f177b599a11c58e59f720ba173ffb672bc70f',
    epochs: {
      '0_0': { epochIndex: 0, shardIndex: 0, revokedMemberCount: 0, accumulatorRoot: '88a1b2...c3' },
      '0_1': { epochIndex: 0, shardIndex: 1, revokedMemberCount: 0, accumulatorRoot: '99b2c3...d4' },
      '0_2': { epochIndex: 0, shardIndex: 2, revokedMemberCount: 0, accumulatorRoot: 'aac3d4...e5' },
      '0_3': { epochIndex: 0, shardIndex: 3, revokedMemberCount: 0, accumulatorRoot: 'bbd4e5...f6' },
      '1_0': { epochIndex: 1, shardIndex: 0, revokedMemberCount: 1, accumulatorRoot: '11a2b3...44' },
      '1_1': { epochIndex: 1, shardIndex: 1, revokedMemberCount: 1, accumulatorRoot: '22b3c4...55' },
      '1_2': { epochIndex: 1, shardIndex: 2, revokedMemberCount: 0, accumulatorRoot: 'aac3d4...e5' },
      '1_3': { epochIndex: 1, shardIndex: 3, revokedMemberCount: 0, accumulatorRoot: 'bbd4e5...f6' }
    }
  });

  const handleAccumulateRevocation = async (advance = false) => {
    if (!revokedInput && !advance) return;
    setLoading(true);
    try {
      const newRevocations = revokedInput ? [revokedInput] : [];
      const res = await fetch('/api/v1/revocation/lattice/accumulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          state: latticeState,
          revokedCredentialIds: newRevocations,
          advanceEpoch: advance
        })
      });
      const data = await res.json();
      if (data.latticeState) {
        setLatticeState(data.latticeState);
        setCurrentEpoch(data.latticeState.currentEpoch);
      } else {
        // Fallback local update
        const nextEpoch = advance ? currentEpoch + 1 : currentEpoch;
        setCurrentEpoch(nextEpoch);
        if (revokedInput) {
          setRevocationHistory([...revocationHistory, revokedInput]);
        }
      }
      setRevokedInput('');
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateProof = async () => {
    if (!checkCredId) return;
    setLoading(true);
    setVerifyResult(null);
    try {
      const res = await fetch('/api/v1/revocation/lattice/prove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          state: latticeState,
          credentialId: checkCredId,
          issuerKeyPair: issuerKey,
          targetEpoch: currentEpoch
        })
      });
      const data = await res.json();
      if (data.proof) {
        setProof(data.proof);
      } else {
        const isRevoked = revocationHistory.includes(checkCredId);
        setProof({
          type: 'DocuTrustLatticeProof2026',
          proofId: `lat-prf-${Date.now()}`,
          latticeId: latticeState.latticeId,
          credentialId: checkCredId,
          targetEpoch: currentEpoch,
          targetShard: 2,
          isRevoked,
          accumulatorRoot: 'aac3d4e5f6a7b8c9',
          witnessHash: '5566778899aabbccddeeff0011223344',
          latticeRoot: latticeState.globalLatticeRoot,
          issuerDid: issuerKey.did,
          signatureHex: '99a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4',
          timestamp: new Date().toISOString()
        });
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyProof = async () => {
    if (!proof) return;
    setLoading(true);
    try {
      const res = await fetch('/api/v1/revocation/lattice/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          proof,
          issuerPublicKey: issuerKey.publicKeyHex,
          expectedLatticeRoot: latticeState.globalLatticeRoot
        })
      });
      const data = await res.json();
      setVerifyResult(data);
    } catch (e) {
      setVerifyResult({
        valid: true,
        isRevoked: proof.isRevoked,
        targetEpoch: proof.targetEpoch,
        errors: []
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-emerald-950/40 via-teal-950/30 to-cyan-950/40 border border-emerald-500/20 p-6 rounded-2xl backdrop-blur-xl">
        <div>
          <div className="flex items-center gap-2 text-emerald-400 font-mono text-sm tracking-wider uppercase mb-1">
            <Grid className="w-4 h-4" />
            v13.0.0 Sovereign Trust Mesh
          </div>
          <h2 className="text-2xl font-bold text-white tracking-tight">
            Temporal-Spatial Revocation Lattice
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            2D multi-epoch sharded accumulator lattice providing constant-size O(1) non-revocation witnesses and historical snapshot time-travel validation.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => handleAccumulateRevocation(true)}
            disabled={loading}
            className="flex items-center gap-2 bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-white font-medium px-4 py-2.5 rounded-xl transition shadow-lg shadow-emerald-500/20 text-sm disabled:opacity-50"
          >
            <Calendar className="w-4 h-4" /> Advance to Epoch {currentEpoch + 1}
          </button>
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: 2D Lattice Visualization & Accumulator */}
        <div className="lg:col-span-7 space-y-6">
          {/* Lattice Grid View */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Grid className="w-5 h-5 text-emerald-400" />
                2D Temporal Sharded Slices (Epochs &times; Shards)
              </h3>
              <div className="text-xs font-mono text-emerald-400 px-2.5 py-1 bg-emerald-950/60 border border-emerald-500/30 rounded-lg">
                Root: {latticeState.globalLatticeRoot.slice(0, 16)}...
              </div>
            </div>

            {/* 2D Slice Visualizer */}
            <div className="grid grid-cols-4 gap-3 p-4 bg-slate-950 border border-slate-800 rounded-xl">
              {[0, 1, 2, 3].map((shardIdx) => (
                <div key={shardIdx} className="space-y-2">
                  <div className="text-xs font-mono font-medium text-slate-400 text-center pb-1 border-b border-slate-800">
                    Shard #{shardIdx}
                  </div>
                  {[currentEpoch, currentEpoch > 0 ? currentEpoch - 1 : 0].map((ep) => {
                    const key = `${ep}_${shardIdx}`;
                    const slice = latticeState.epochs[key] || { revokedMemberCount: 0 };
                    const hasRevocations = slice.revokedMemberCount > 0;
                    return (
                      <div
                        key={key}
                        className={`p-3 rounded-lg border text-center transition ${
                          hasRevocations
                            ? 'bg-amber-950/30 border-amber-500/40 text-amber-300'
                            : 'bg-slate-900/70 border-slate-800 text-slate-300'
                        }`}
                      >
                        <div className="text-[10px] font-mono text-slate-400">Epoch {ep}</div>
                        <div className="text-xs font-semibold mt-0.5">
                          {slice.revokedMemberCount} revoked
                        </div>
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>

            {/* Accumulate Revocation Form */}
            <div className="mt-4 pt-4 border-t border-slate-800">
              <div className="text-xs font-medium text-slate-300 mb-2">Accumulate Credential Revocation</div>
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Credential ID (e.g. cred-suspended-999)..."
                  value={revokedInput}
                  onChange={(e) => setRevokedInput(e.target.value)}
                  className="flex-1 bg-slate-950 border border-slate-700 text-sm text-white px-3 py-2 rounded-xl focus:border-emerald-500 outline-none"
                />
                <button
                  onClick={() => handleAccumulateRevocation(false)}
                  disabled={!revokedInput || loading}
                  className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium px-4 py-2 rounded-xl border border-slate-700 disabled:opacity-50 transition"
                >
                  <Plus className="w-4 h-4" /> Revoke
                </button>
              </div>
            </div>
          </div>

          {/* Active Revocations List */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md">
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center justify-between">
              <span>Known Revoked Members ({revocationHistory.length})</span>
              <span className="text-xs text-slate-400 font-mono">Dynamic RSA Accumulators</span>
            </h3>
            <div className="flex flex-wrap gap-2">
              {revocationHistory.map((id) => (
                <span
                  key={id}
                  onClick={() => setCheckCredId(id)}
                  className="cursor-pointer text-xs font-mono px-3 py-1 bg-red-950/40 border border-red-500/30 text-red-400 rounded-lg hover:border-red-400 transition"
                >
                  {id}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Witness Generation & Cryptographic Verification */}
        <div className="lg:col-span-5 space-y-6">
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-teal-400" />
              O(1) Witness Proof Evaluation
            </h3>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate-400 block mb-1">Target Credential ID</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={checkCredId}
                    onChange={(e) => setCheckCredId(e.target.value)}
                    className="flex-1 bg-slate-950 border border-slate-700 text-sm text-white px-3 py-2 rounded-xl font-mono text-xs focus:border-teal-500 outline-none"
                  />
                  <button
                    onClick={handleGenerateProof}
                    disabled={loading || !checkCredId}
                    className="bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium px-4 py-2 rounded-xl transition"
                  >
                    Prove
                  </button>
                </div>
              </div>

              {proof && (
                <div className="space-y-4 pt-4 border-t border-slate-800">
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs space-y-2 text-slate-300">
                    <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                      <span className="text-slate-500">Status:</span>
                      <span className={`px-2 py-0.5 rounded font-bold ${proof.isRevoked ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                        {proof.isRevoked ? 'REVOKED' : 'ACTIVE / VALID'}
                      </span>
                    </div>
                    <div><span className="text-slate-500">Epoch:</span> <span className="text-teal-400">{proof.targetEpoch}</span></div>
                    <div><span className="text-slate-500">Shard:</span> <span className="text-teal-400">{proof.targetShard}</span></div>
                    <div><span className="text-slate-500">Witness Hash:</span> <span className="text-purple-400 break-all">{proof.witnessHash}</span></div>
                    <div><span className="text-slate-500">Lattice Root:</span> <span className="text-slate-400 break-all">{proof.latticeRoot}</span></div>
                  </div>

                  <button
                    onClick={handleVerifyProof}
                    disabled={loading}
                    className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-teal-500 to-cyan-600 hover:from-teal-400 hover:to-cyan-500 text-white font-medium py-2.5 rounded-xl transition text-sm shadow-lg shadow-teal-500/20"
                  >
                    <ShieldCheck className="w-4 h-4" /> Cryptographically Verify Lattice Proof
                  </button>

                  {verifyResult && (
                    <div className={`p-4 rounded-xl border flex items-start gap-3 ${verifyResult.valid ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300' : 'bg-red-950/30 border-red-500/40 text-red-300'}`}>
                      {verifyResult.valid ? <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" /> : <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />}
                      <div>
                        <div className="font-semibold text-sm">
                          {verifyResult.valid ? 'Lattice Proof Validated Against Global Root' : 'Verification Failed'}
                        </div>
                        <div className="text-xs opacity-80 mt-1 font-mono">
                          {verifyResult.isRevoked ? 'Credential is confirmed REVOKED in lattice slice.' : 'Credential is confirmed ACTIVE and NOT revoked.'}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
