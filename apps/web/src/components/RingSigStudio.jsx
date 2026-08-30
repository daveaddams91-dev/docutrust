import React, { useState } from 'react';
import { 
  Shield, 
  Key, 
  FileCheck, 
  AlertCircle, 
  CheckCircle2, 
  Copy, 
  Check, 
  Fingerprint, 
  Users, 
  Sparkles, 
  Lock, 
  RotateCcw,
  Vote,
  ShieldCheck,
  ShieldAlert,
  Hash
} from 'lucide-react';

export default function RingSigStudio() {
  const [ringSize, setRingSize] = useState(3);
  const [participants, setParticipants] = useState([
    { id: 1, name: 'Alice (Finance VP)', pubKey: 'did:key:z6Mku7rV9p8nK7f3aB1cD2eE3fF4gG5hH6iI7jJ8kK9lL0m', privKey: '4a6f8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a', isSigner: true },
    { id: 2, name: 'Bob (Lead Auditor)', pubKey: 'did:key:z6Mkw1xY2z3aB4cD5eE6fF7gG8hH9iI0jJ1kK2lL3m4nN5o', privKey: '7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c', isSigner: false },
    { id: 3, name: 'Carol (Security Officer)', pubKey: 'did:key:z6Mkq4rS5t6uV7wX8yZ9aB0cD1eE2fF3gG4hH5iI6jJ7kK8l', privKey: '9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d', isSigner: false }
  ]);

  const [message, setMessage] = useState(JSON.stringify({
    action: "WHISTLEBLOWER_SECURITY_DISCLOSURE",
    incidentId: "INC-2026-0889",
    severity: "CRITICAL",
    disclosure: "Unbounded buffer access patched in sovereign cryptographic kernel."
  }, null, 2));

  const [signatureOutput, setSignatureOutput] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [usedKeyImages, setUsedKeyImages] = useState([]);
  const [copied, setCopied] = useState(false);
  const [isSigning, setIsSigning] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);

  const handleCopy = (text) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSelectSigner = (id) => {
    setParticipants(prev => prev.map(p => ({
      ...p,
      isSigner: p.id === id
    })));
  };

  const handleSign = async () => {
    setIsSigning(true);
    setVerificationResult(null);
    try {
      const signer = participants.find(p => p.isSigner);
      if (!signer) {
        alert('Please designate one participant as the active signer.');
        setIsSigning(false);
        return;
      }

      let parsedMessage;
      try {
        parsedMessage = JSON.parse(message);
      } catch (e) {
        parsedMessage = message;
      }

      // Call REST API
      const res = await fetch('/api/v1/ringsig/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: parsedMessage,
          ring: participants.map(p => p.pubKey),
          signerPrivateKeyHex: signer.privKey,
          signerPublicKeyHex: signer.pubKey
        })
      });

      if (!res.ok) {
        throw new Error(`Failed to sign: ${res.statusText}`);
      }

      const data = await res.json();
      setSignatureOutput(data);
    } catch (err) {
      console.error(err);
      alert('Error generating ring signature: ' + err.message);
    } finally {
      setIsSigning(false);
    }
  };

  const handleVerify = async () => {
    if (!signatureOutput) return;
    setIsVerifying(true);
    try {
      let parsedMessage;
      try {
        parsedMessage = JSON.parse(message);
      } catch (e) {
        parsedMessage = message;
      }

      const res = await fetch('/api/v1/ringsig/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: parsedMessage,
          signature: signatureOutput.signature,
          usedKeyImages: usedKeyImages
        })
      });

      const data = await res.json();
      setVerificationResult(data);
    } catch (err) {
      console.error(err);
      alert('Verification error: ' + err.message);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleRegisterKeyImage = () => {
    if (signatureOutput && signatureOutput.keyImage) {
      if (!usedKeyImages.includes(signatureOutput.keyImage)) {
        setUsedKeyImages(prev => [...prev, signatureOutput.keyImage]);
      }
    }
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="border-b border-gray-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-purple-500/10 border border-purple-500/20 rounded-xl text-purple-400">
            <Users className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              Linkable Ring Signature (LSAG) Studio
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30 font-mono">
                1-of-N Anonymous Attestation
              </span>
            </h1>
            <p className="text-sm text-gray-400 mt-1">
              Prove authorship or cast sovereign anonymous ballots from an N-member ring without revealing individual identity, while cryptographically preventing double-action via deterministic key images.
            </p>
          </div>
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Ring Setup & Message */}
        <div className="lg:col-span-6 space-y-6">
          {/* Ring Setup Card */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                <Users className="w-4 h-4 text-purple-400" />
                Anonymity Ring Participants ({participants.length}-of-{participants.length})
              </h2>
              <span className="text-xs text-gray-400 font-mono">1 Active Signer</span>
            </div>

            <div className="space-y-3">
              {participants.map((p, idx) => (
                <div 
                  key={p.id}
                  onClick={() => handleSelectSigner(p.id)}
                  className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                    p.isSigner 
                      ? 'bg-purple-950/30 border-purple-500/50 ring-1 ring-purple-500/30' 
                      : 'bg-gray-950/40 border-gray-800/80 hover:border-gray-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${p.isSigner ? 'bg-purple-400 animate-pulse' : 'bg-gray-600'}`} />
                      <span className="text-xs font-semibold text-white">{p.name}</span>
                    </div>
                    {p.isSigner ? (
                      <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-semibold border border-purple-500/30">
                        Designated Signer
                      </span>
                    ) : (
                      <span className="text-[10px] text-gray-500 hover:text-gray-300">Click to select</span>
                    )}
                  </div>
                  <div className="mt-2 text-[11px] font-mono text-gray-400 truncate">
                    <span className="text-gray-500">DID:</span> {p.pubKey}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Message Payload Card */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-blue-400" />
                Attestation Payload / Sovereign Ballot
              </h2>
            </div>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              rows={6}
              className="w-full font-mono text-xs bg-gray-950/80 border border-gray-800 rounded-lg p-3 text-gray-300 focus:outline-none focus:border-purple-500/60 focus:ring-1 focus:ring-purple-500/30 resize-none"
            />
            <button
              onClick={handleSign}
              disabled={isSigning}
              className="w-full py-2.5 px-4 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-medium rounded-lg text-xs flex items-center justify-center gap-2 transition-all shadow-lg shadow-purple-900/20 disabled:opacity-50"
            >
              <Fingerprint className="w-4 h-4" />
              {isSigning ? 'Computing LSAG Ring Signature...' : 'Generate 1-of-N Linkable Ring Signature'}
            </button>
          </div>
        </div>

        {/* Right Column: Signature & Audit Output */}
        <div className="lg:col-span-6 space-y-6">
          {/* Signature Result Card */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Cryptographic Ring Signature
              </h2>
              {signatureOutput && (
                <button
                  onClick={() => handleCopy(signatureOutput.signature)}
                  className="flex items-center gap-1 text-xs text-gray-400 hover:text-white transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
              )}
            </div>

            {signatureOutput ? (
              <div className="space-y-3">
                <div className="p-3 bg-gray-950/90 rounded-lg border border-gray-800 font-mono text-[11px] text-gray-300 max-h-64 overflow-y-auto">
                  <pre>{JSON.stringify(signatureOutput.signature, null, 2)}</pre>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="p-2.5 rounded bg-gray-950/60 border border-gray-800">
                    <span className="text-gray-500 block text-[10px]">Key Image (Linkability Tag):</span>
                    <span className="font-mono text-purple-400 truncate block mt-0.5">{signatureOutput.keyImage}</span>
                  </div>
                  <div className="p-2.5 rounded bg-gray-950/60 border border-gray-800">
                    <span className="text-gray-500 block text-[10px]">Anonymity Set:</span>
                    <span className="font-mono text-emerald-400 block mt-0.5">{signatureOutput.ringSize} Public Keys</span>
                  </div>
                </div>

                <div className="flex gap-2 pt-2">
                  <button
                    onClick={handleVerify}
                    disabled={isVerifying}
                    className="flex-1 py-2 px-3 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg text-xs flex items-center justify-center gap-1.5 transition-all shadow-md shadow-blue-900/20 disabled:opacity-50"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    {isVerifying ? 'Verifying...' : 'Verify Ring Signature'}
                  </button>
                  <button
                    onClick={handleRegisterKeyImage}
                    className="py-2 px-3 bg-gray-800 hover:bg-gray-700 text-gray-200 font-medium rounded-lg text-xs flex items-center gap-1.5 transition-all border border-gray-700"
                    title="Simulate recording key image in ledger to test double-voting prevention"
                  >
                    <ShieldAlert className="w-4 h-4 text-amber-400" />
                    Record in Double-Spend Ledger
                  </button>
                </div>
              </div>
            ) : (
              <div className="p-8 border border-dashed border-gray-800 rounded-lg text-center text-gray-500 text-xs">
                Configure participants and click Generate to produce a 1-of-N Linkable Ring Signature.
              </div>
            )}
          </div>

          {/* Verification Audit Result */}
          {verificationResult && (
            <div className={`p-4 rounded-xl border ${
              verificationResult.valid 
                ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300' 
                : 'bg-rose-950/20 border-rose-500/40 text-rose-300'
            }`}>
              <div className="flex items-center gap-2">
                {verificationResult.valid ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : (
                  <AlertCircle className="w-5 h-5 text-rose-400" />
                )}
                <span className="font-semibold text-sm">
                  {verificationResult.valid ? 'Ring Signature Authenticated & Valid' : 'Verification Rejected'}
                </span>
              </div>
              <p className="text-xs mt-2 opacity-90">
                {verificationResult.valid 
                  ? `Message mathematically proven signed by 1 member of the ${verificationResult.ringSize}-member ring without disclosing signer identity.`
                  : (verificationResult.error || 'Signature failed verification or key image was already consumed.')}
              </p>
              {verificationResult.isDoubleAction && (
                <div className="mt-2 text-xs font-mono font-semibold text-rose-400 flex items-center gap-1">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  Double-voting / double-action detected on key image: {verificationResult.keyImage?.slice(0, 16)}...
                </div>
              )}
            </div>
          )}

          {/* Ledger Tag State */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4 text-xs space-y-2">
            <div className="flex items-center justify-between text-gray-400">
              <span className="font-semibold text-gray-300 flex items-center gap-1.5">
                <Hash className="w-3.5 h-3.5 text-purple-400" />
                Consumed Key Images Ledger ({usedKeyImages.length})
              </span>
              {usedKeyImages.length > 0 && (
                <button 
                  onClick={() => setUsedKeyImages([])}
                  className="text-gray-500 hover:text-gray-300 flex items-center gap-1"
                >
                  <RotateCcw className="w-3 h-3" /> Clear
                </button>
              )}
            </div>
            {usedKeyImages.length === 0 ? (
              <span className="text-gray-500 italic block">No key images recorded yet.</span>
            ) : (
              <div className="space-y-1 max-h-24 overflow-y-auto">
                {usedKeyImages.map((img, idx) => (
                  <div key={idx} className="font-mono text-[11px] text-purple-300/80 bg-gray-950/60 p-1.5 rounded truncate">
                    {img}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
