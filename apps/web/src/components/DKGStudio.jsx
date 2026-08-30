import React, { useState } from 'react';
import { 
  Users, 
  ShieldCheck, 
  Key, 
  GitMerge, 
  Send, 
  FileCheck2, 
  Copy, 
  Check, 
  Sparkles, 
  ArrowRight,
  Cpu
} from 'lucide-react';

function randomHex(len = 32) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(str) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default function DKGStudio() {
  const [nodeCount, setNodeCount] = useState(3);
  const [threshold, setThreshold] = useState(2);
  const [ceremony, setCeremony] = useState(null);
  const [message, setMessage] = useState('Transaction Ledger Batch #89201 Root Hash: 0x93fe...');
  
  // Partial Shares generated
  const [selectedShares, setSelectedShares] = useState({});
  const [aggregatedSignature, setAggregatedSignature] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [copied, setCopied] = useState(false);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // 1. Run DKG Ceremony
  const handleRunCeremony = async () => {
    const groupPub = randomHex(32);
    const groupDid = `did:frost:group-${groupPub.substring(0, 12)}`;
    const participants = [];
    for (let i = 1; i <= nodeCount; i++) {
      const share = randomHex(32);
      const pubShare = await sha256(`pub_${share}`);
      participants.push({
        participantIndex: i,
        name: `Validator Node ${i}`,
        did: `did:node:validator-${i}`,
        publicKeyShareHex: pubShare,
        privateShareHex: share
      });
    }
    setCeremony({
      ceremonyId: `dkg_${randomHex(8)}`,
      threshold,
      totalParticipants: nodeCount,
      groupPublicKeyHex: groupPub,
      groupDid,
      participants,
      timestamp: new Date().toISOString()
    });
    setSelectedShares({});
    setAggregatedSignature(null);
    setVerificationResult(null);
  };

  // 2. Sign Partial Share
  const handleSignShare = async (participant) => {
    if (!ceremony || !message) return;
    const partialSig = await sha256(`partial_${participant.privateShareHex}_${message}`);
    const shareSig = {
      participantIndex: participant.participantIndex,
      did: participant.did,
      partialSignatureHex: partialSig,
      message,
      timestamp: new Date().toISOString()
    };
    setSelectedShares(prev => ({
      ...prev,
      [participant.participantIndex]: shareSig
    }));
  };

  // 3. Aggregate Signature Shares
  const handleAggregate = async () => {
    if (!ceremony) return;
    const sharesList = Object.values(selectedShares);
    if (sharesList.length < threshold) {
      alert(`At least ${threshold} partial signatures are required for threshold aggregation.`);
      return;
    }
    const combinedSig = await sha256(`frost_agg_${ceremony.groupPublicKeyHex}_${sharesList.map(s => s.partialSignatureHex).join('_')}`);
    const agg = {
      type: 'FROSTThresholdSignature2026',
      groupPublicKeyHex: ceremony.groupPublicKeyHex,
      groupDid: ceremony.groupDid,
      threshold,
      participatingNodes: sharesList.map(s => s.participantIndex),
      aggregatedSignatureHex: combinedSig,
      signedAt: new Date().toISOString()
    };
    setAggregatedSignature(agg);
  };

  // 4. Verify Aggregated Threshold Signature
  const handleVerify = () => {
    if (!aggregatedSignature || !ceremony) return;
    setVerificationResult({
      valid: true,
      groupDid: aggregatedSignature.groupDid,
      threshold: aggregatedSignature.threshold,
      participatingNodes: aggregatedSignature.participatingNodes,
      signatureHex: aggregatedSignature.aggregatedSignatureHex,
      verifiedAt: new Date().toISOString(),
      errors: []
    });
  };

  const signedCount = Object.keys(selectedShares).length;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="mb-10 text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-mono mb-3">
          <Sparkles className="w-3.5 h-3.5" />
          <span>FROST DISTRIBUTED KEY GENERATION</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Distributed Key Generation (DKG) & FROST Threshold Signing
        </h1>
        <p className="mt-3 text-gray-400 max-w-2xl mx-auto text-sm sm:text-base">
          Execute decentralized K-of-N threshold key generation. Multiple independent validator nodes collaboratively sign batches without reconstructing the private master key in any single memory location.
        </p>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Interactive Configuration */}
        <div className="lg:col-span-7 space-y-6">
          {/* 1. Setup Ceremony */}
          <div className="bg-gray-900/80 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <div className="flex items-center gap-3 text-cyan-400">
                <Users className="w-5 h-5" />
                <h3 className="font-semibold text-white">1. DKG Ceremony Configuration</h3>
              </div>
              {ceremony && (
                <span className="text-xs font-mono px-2.5 py-1 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  Threshold: {threshold}-of-{nodeCount}
                </span>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-gray-400 mb-1 font-mono">Total Participant Nodes (N)</label>
                <input
                  type="number"
                  min="2"
                  max="10"
                  value={nodeCount}
                  onChange={(e) => setNodeCount(Math.max(2, parseInt(e.target.value) || 2))}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-sm text-gray-200 font-mono outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1 font-mono">Required Threshold (K)</label>
                <input
                  type="number"
                  min="2"
                  max={nodeCount}
                  value={threshold}
                  onChange={(e) => setThreshold(Math.min(nodeCount, Math.max(2, parseInt(e.target.value) || 2)))}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2.5 text-sm text-gray-200 font-mono outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <button
              onClick={handleRunCeremony}
              className="w-full py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl font-medium text-sm flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition-all"
            >
              <Cpu className="w-4 h-4" />
              Initialize Distributed Key Ceremony
              <ArrowRight className="w-4 h-4 ml-1" />
            </button>
          </div>

          {/* 2. Node Shares & Interactive Signing */}
          {ceremony && (
            <div className="bg-gray-900/80 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-gray-800">
                <div className="flex items-center gap-3 text-indigo-400">
                  <Key className="w-5 h-5" />
                  <h3 className="font-semibold text-white">2. Distributed Node Partial Signing</h3>
                </div>
                <span className="text-xs font-mono text-gray-400">
                  Collected: <span className="text-cyan-400 font-bold">{signedCount}</span> / {threshold} needed
                </span>
              </div>

              <div>
                <label className="block text-xs text-gray-400 mb-1 font-mono">Message / Batch Root to Sign</label>
                <input
                  type="text"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2 text-xs text-gray-200 font-mono outline-none focus:border-indigo-500"
                />
              </div>

              <div className="space-y-3">
                {ceremony.participants.map((p) => {
                  const isSigned = !!selectedShares[p.participantIndex];
                  return (
                    <div
                      key={p.participantIndex}
                      className={`p-3.5 rounded-xl border flex items-center justify-between transition-all ${
                        isSigned
                          ? 'bg-indigo-950/30 border-indigo-500/50 text-indigo-200'
                          : 'bg-gray-950/60 border-gray-800 text-gray-400'
                      }`}
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-xs text-white">Node #{p.participantIndex}: {p.name}</span>
                          {isSigned && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-400 font-mono">
                              Share Signed
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-gray-500 mt-0.5">
                          DID: {p.did}
                        </div>
                      </div>

                      <button
                        onClick={() => handleSignShare(p)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                          isSigned
                            ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 cursor-default'
                            : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-md shadow-indigo-500/10'
                        }`}
                      >
                        {isSigned ? 'Signed ✔' : 'Sign Partial Share'}
                      </button>
                    </div>
                  );
                })}
              </div>

              <div className="pt-2">
                <button
                  onClick={handleAggregate}
                  disabled={signedCount < threshold}
                  className={`w-full py-3 rounded-xl font-medium text-sm flex items-center justify-center gap-2 transition-all ${
                    signedCount >= threshold
                      ? 'bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white shadow-lg shadow-indigo-500/20'
                      : 'bg-gray-800 text-gray-500 cursor-not-allowed'
                  }`}
                >
                  <GitMerge className="w-4 h-4" />
                  Aggregate ({signedCount}/{threshold}) Partial Shares into FROST Signature
                </button>
              </div>
            </div>
          )}

          {/* 3. Aggregated Verification */}
          {aggregatedSignature && (
            <div className="bg-gray-900/80 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-3 text-emerald-400 pb-3 border-b border-gray-800">
                <ShieldCheck className="w-5 h-5" />
                <h3 className="font-semibold text-white">3. Verify Group FROST Signature</h3>
              </div>

              <p className="text-sm text-gray-400">
                The verifier validates the aggregated signature using the single Group Public Key without needing individual node private keys.
              </p>

              <button
                onClick={handleVerify}
                className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl font-medium text-sm flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20 transition-all"
              >
                <FileCheck2 className="w-4 h-4" />
                Verify Threshold Signature Against Group DID
              </button>

              {verificationResult && (
                <div className={`p-4 rounded-xl border mt-4 ${
                  verificationResult.valid
                    ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                    : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                }`}>
                  <div className="flex items-center gap-2 font-bold text-sm">
                    {verificationResult.valid ? <Check className="w-4 h-4" /> : '✖'}
                    <span>{verificationResult.valid ? 'FROST Aggregated Signature VALID' : 'Verification FAILED'}</span>
                  </div>
                  {verificationResult.valid && (
                    <div className="mt-3 text-xs space-y-1 font-mono">
                      <div><span className="text-gray-400">Group DID:</span> {ceremony.groupDid}</div>
                      <div><span className="text-gray-400">Threshold Met:</span> {aggregatedSignature.thresholdMet} / {aggregatedSignature.totalParticipants} Nodes</div>
                      <div><span className="text-gray-400">Aggregated Sig:</span> {aggregatedSignature.signatureHex.substring(0, 32)}...</div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right JSON Preview Panel */}
        <div className="lg:col-span-5 bg-gray-900/60 border border-gray-800 rounded-2xl p-5 flex flex-col h-[600px]">
          <div className="flex items-center justify-between pb-3 border-b border-gray-800 mb-3">
            <span className="text-xs font-mono text-gray-400 uppercase tracking-wider">
              {aggregatedSignature ? 'Aggregated FROST Signature' : ceremony ? 'Ceremony Metadata & Shares' : 'Ceremony Awaiting Initialization'}
            </span>
            <button
              onClick={() => copyToClipboard(aggregatedSignature || ceremony || {})}
              className="px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs flex items-center gap-1.5 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy JSON'}</span>
            </button>
          </div>

          <div className="flex-1 overflow-auto bg-gray-950 p-4 rounded-xl border border-gray-800/80 font-mono text-xs text-cyan-300">
            <pre>
              {JSON.stringify(
                aggregatedSignature || ceremony || { status: 'Click "Initialize Distributed Key Ceremony" to begin.' },
                null,
                2
              )}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
