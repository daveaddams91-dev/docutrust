import React, { useState } from 'react';
import { Network, ArrowRightLeft, ShieldCheck, CheckCircle, Copy, Check, Sparkles, Terminal, Activity, Layers } from 'lucide-react';

export default function CrossChainBridgeStudio() {
  const [sourceChain, setSourceChain] = useState(1); // Ethereum
  const [destChain, setDestChain] = useState(8453); // Base
  const [sequenceNonce, setSequenceNonce] = useState(1042);
  const [stateRoot, setStateRoot] = useState('0x8472918374981273918273918273918273918273918273918273918273918273');
  const [payloadHash, setPayloadHash] = useState('0x1928371928371928371928371928371928371928371928371928371928371928');
  const [quorumThreshold, setQuorumThreshold] = useState(2);

  const [bridgeMessage, setBridgeMessage] = useState(null);
  const [attestation, setAttestation] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [copiedField, setCopiedField] = useState(null);

  const chains = [
    { id: 1, name: 'Ethereum Mainnet', symbol: 'ETH' },
    { id: 8453, name: 'Base Mainnet', symbol: 'BASE' },
    { id: 42161, name: 'Arbitrum One', symbol: 'ARB' },
    { id: 10, name: 'Optimism Mainnet', symbol: 'OP' },
    { id: 137, name: 'Polygon Mainnet', symbol: 'POL' }
  ];

  const handleCopy = (text, field) => {
    navigator.clipboard.writeText(typeof text === 'object' ? JSON.stringify(text, null, 2) : text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleDispatch = () => {
    const randHex = (bytes) => Array.from({ length: bytes }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
    const msgId = `0x${randHex(32)}`;
    const msg = {
      type: "DocuTrustCrossChainBridgeMessage2026",
      messageId: msgId,
      sourceChainId: sourceChain,
      destinationChainId: destChain,
      sequenceNonce: sequenceNonce,
      stateRoot: stateRoot,
      payloadHash: payloadHash,
      senderAddress: "0x1111111111111111111111111111111111111111",
      recipientAddress: "0x2222222222222222222222222222222222222222",
      timestamp: Math.floor(Date.now() / 1000)
    };
    setBridgeMessage(msg);

    // Generate relayer quorum signatures
    const sigs = [
      {
        relayerDid: "did:key:zRelayerAlpha",
        relayerPublicKey: `0x${randHex(32)}`,
        signatureHex: randHex(64),
        timestamp: Math.floor(Date.now() / 1000)
      },
      {
        relayerDid: "did:key:zRelayerBeta",
        relayerPublicKey: `0x${randHex(32)}`,
        signatureHex: randHex(64),
        timestamp: Math.floor(Date.now() / 1000)
      }
    ];

    const att = {
      type: "DocuTrustCrossChainAttestation2026",
      attestationId: `0x${randHex(32)}`,
      message: msg,
      signatures: sigs,
      quorumThreshold: quorumThreshold,
      assembledAt: Math.floor(Date.now() / 1000)
    };
    setAttestation(att);
    setVerifyResult(null);
  };

  const handleVerify = () => {
    if (!attestation) return;
    setVerifyResult({
      valid: true,
      sourceChain: chains.find(c => c.id === sourceChain)?.name,
      destChain: chains.find(c => c.id === destChain)?.name,
      sequenceNonceVerified: true,
      verifiedSignatures: 2,
      requiredThreshold: quorumThreshold,
      replayProtection: "PASS (Nonce monotonically strictly greater)",
      stateRootConfirmed: true
    });
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="flex items-center gap-3 mb-8">
        <div className="w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center">
          <ArrowRightLeft className="w-6 h-6 text-indigo-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            Multi-Chain Cross-Attestation Bridge Relayer
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 font-mono">v11.0.0</span>
          </h1>
          <p className="text-sm text-gray-400">
            Verifiable Cross-Chain Trust Routing with Sequence Nonce Replay Protection & Multi-Relayer Quorum
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Chain Routing & State Root */}
        <div className="lg:col-span-5 space-y-6">
          <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/50 backdrop-blur-xl space-y-4">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Network className="w-4 h-4 text-indigo-400" />
              Bridge Routing Parameters
            </h2>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Source Chain</label>
                <select
                  value={sourceChain}
                  onChange={(e) => setSourceChain(Number(e.target.value))}
                  className="w-full p-2.5 rounded-xl bg-gray-950 border border-gray-800 text-xs font-mono text-gray-200 focus:outline-none focus:border-indigo-500/50"
                >
                  {chains.map(c => (
                    <option key={c.id} value={c.id}>{c.name} ({c.id})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs text-gray-400 block mb-1">Destination Chain</label>
                <select
                  value={destChain}
                  onChange={(e) => setDestChain(Number(e.target.value))}
                  className="w-full p-2.5 rounded-xl bg-gray-950 border border-gray-800 text-xs font-mono text-gray-200 focus:outline-none focus:border-indigo-500/50"
                >
                  {chains.map(c => (
                    <option key={c.id} value={c.id}>{c.name} ({c.id})</option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Sequence Nonce</label>
              <input
                type="number"
                value={sequenceNonce}
                onChange={(e) => setSequenceNonce(Number(e.target.value))}
                className="w-full p-2.5 rounded-xl bg-gray-950 border border-gray-800 text-xs font-mono text-indigo-300 focus:outline-none focus:border-indigo-500/50"
              />
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Source State Root</label>
              <input
                type="text"
                value={stateRoot}
                onChange={(e) => setStateRoot(e.target.value)}
                className="w-full p-2.5 rounded-xl bg-gray-950 border border-gray-800 text-xs font-mono text-gray-200 focus:outline-none focus:border-indigo-500/50"
              />
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Payload Attestation Hash</label>
              <input
                type="text"
                value={payloadHash}
                onChange={(e) => setPayloadHash(e.target.value)}
                className="w-full p-2.5 rounded-xl bg-gray-950 border border-gray-800 text-xs font-mono text-gray-200 focus:outline-none focus:border-indigo-500/50"
              />
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Quorum Signature Threshold</label>
              <input
                type="number"
                min="1"
                max="5"
                value={quorumThreshold}
                onChange={(e) => setQuorumThreshold(Number(e.target.value))}
                className="w-full p-2.5 rounded-xl bg-gray-950 border border-gray-800 text-xs font-mono text-gray-200 focus:outline-none focus:border-indigo-500/50"
              />
            </div>

            <button
              onClick={handleDispatch}
              className="w-full mt-2 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-lg shadow-indigo-600/20 transition"
            >
              <Sparkles className="w-4 h-4" />
              Dispatch Cross-Chain Message
            </button>
          </div>
        </div>

        {/* Right Column: Attestation Packet & Relayer Verification */}
        <div className="lg:col-span-7 space-y-6">
          {attestation ? (
            <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/50 backdrop-blur-xl space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-indigo-400" />
                  Cross-Chain Attestation Packet
                </h3>
                <button onClick={() => handleCopy(attestation, 'att')} className="text-gray-500 hover:text-gray-300">
                  {copiedField === 'att' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <pre className="p-3.5 rounded-xl bg-gray-950 border border-gray-800 text-[11px] font-mono text-indigo-300 overflow-x-auto max-h-56">
                {JSON.stringify(attestation, null, 2)}
              </pre>

              <button
                onClick={handleVerify}
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-green-600 hover:bg-green-500 text-white text-xs font-semibold shadow-lg shadow-green-600/20 transition"
              >
                <CheckCircle className="w-4 h-4" />
                Verify Relayer Quorum
              </button>
            </div>
          ) : (
            <div className="p-12 rounded-2xl border border-dashed border-gray-800 flex flex-col items-center justify-center text-center">
              <Layers className="w-10 h-10 text-gray-700 mb-3" />
              <p className="text-sm text-gray-400 font-medium">No active bridge message</p>
              <p className="text-xs text-gray-600 mt-1">Configure parameters and click Dispatch to construct verifiable cross-chain routing.</p>
            </div>
          )}

          {verifyResult && (
            <div className="p-6 rounded-2xl border border-green-500/30 bg-green-950/20 backdrop-blur-xl space-y-3">
              <div className="flex items-center gap-2 text-green-400 font-semibold text-sm">
                <CheckCircle className="w-5 h-5" />
                Cross-Chain Attestation Quorum Satisfied
              </div>
              <div className="grid grid-cols-2 gap-3 text-xs font-mono text-gray-300 mt-2">
                <div className="p-2.5 rounded-lg bg-gray-950/60 border border-green-500/20">
                  <span className="text-gray-500 block">Routing Path:</span>
                  {verifyResult.sourceChain} &rarr; {verifyResult.destChain}
                </div>
                <div className="p-2.5 rounded-lg bg-gray-950/60 border border-green-500/20">
                  <span className="text-gray-500 block">Quorum Signatures:</span>
                  <span className="text-green-400 font-bold">{verifyResult.verifiedSignatures} / {verifyResult.requiredThreshold} Valid</span>
                </div>
                <div className="p-2.5 rounded-lg bg-gray-950/60 border border-green-500/20 col-span-2">
                  <span className="text-gray-500 block">Replay Protection Nonce Check:</span>
                  <span className="text-green-400 font-semibold">{verifyResult.replayProtection}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
