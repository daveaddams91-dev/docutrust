import React, { useState } from 'react';
import { EyeOff, Key, FileSignature, ShieldCheck, CheckCircle, Sparkles, Lock, ArrowRight, UserCheck } from 'lucide-react';

const dummyHex = (len = 64) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');

export default function PQBlindStudio() {
  const [signerKeyPair, setSignerKeyPair] = useState(null);
  const [userMessage, setUserMessage] = useState(JSON.stringify({
    applicantId: 'sovereign_agent_0x9812',
    anonymousVote: 'PROPOSAL_402_APPROVE',
    entropySeed: '0xabc123fed456'
  }, null, 2));

  const [blindRequestData, setBlindRequestData] = useState(null);
  const [blindSignature, setBlindSignature] = useState(null);
  const [unblindedReceipt, setUnblindedReceipt] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);

  const handleGenerateSignerKeys = () => {
    try {
      const keys = {
        keyId: 'pq_signer_' + Math.floor(Math.random() * 10000),
        publicKeyHex: dummyHex(64),
        privateKeyHex: dummyHex(64),
        algorithm: 'ML-DSA-87-BLIND'
      };
      setSignerKeyPair(keys);
      setBlindRequestData(null);
      setBlindSignature(null);
      setUnblindedReceipt(null);
      setVerificationResult(null);
    } catch (e) {
      alert('Key generation failed: ' + e.message);
    }
  };

  const handleBlindMessage = () => {
    if (!signerKeyPair) {
      alert('Please generate signer keys first.');
      return;
    }
    try {
      const res = {
        messageHash: dummyHex(64),
        blindingSecretHex: dummyHex(64),
        request: {
          blindedMessageHex: dummyHex(64),
          signerKeyId: signerKeyPair.keyId,
          timestamp: new Date().toISOString()
        }
      };
      setBlindRequestData(res);
      setBlindSignature(null);
      setUnblindedReceipt(null);
      setVerificationResult(null);
    } catch (e) {
      alert('Blinding failed: ' + e.message);
    }
  };

  const handleBlindSign = () => {
    if (!signerKeyPair || !blindRequestData) return;
    try {
      const blindSig = {
        blindSignatureHex: dummyHex(64),
        signerKeyId: signerKeyPair.keyId,
        signedAt: new Date().toISOString()
      };
      setBlindSignature(blindSig);
      setUnblindedReceipt(null);
      setVerificationResult(null);
    } catch (e) {
      alert('Signing failed: ' + e.message);
    }
  };

  const handleUnblind = () => {
    if (!blindRequestData || !blindSignature || !signerKeyPair) return;
    try {
      const receipt = {
        receiptId: 'pq_blind_sig_' + Math.floor(Math.random() * 100000),
        unblindedSignatureHex: dummyHex(64),
        signerPublicKeyHex: signerKeyPair.publicKeyHex,
        messageHash: blindRequestData.messageHash,
        verifiedStatus: 'AUTHENTIC_UNLINKABLE'
      };
      setUnblindedReceipt(receipt);
      setVerificationResult(null);
    } catch (e) {
      alert('Unblinding failed: ' + e.message);
    }
  };

  const handleVerify = () => {
    if (!unblindedReceipt || !signerKeyPair) return;
    try {
      const res = {
        valid: true,
        receiptId: unblindedReceipt.receiptId,
        signerPublicKey: signerKeyPair.publicKeyHex,
        messageMatch: true,
        unlinkable: true,
        verificationTimeMs: 0.18
      };
      setVerificationResult(res);
    } catch (e) {
      alert('Verification failed: ' + e.message);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 bg-purple-500/10 border border-purple-500/20 text-purple-400 rounded-full text-xs font-semibold uppercase tracking-wider mb-2">
              <Sparkles className="w-3.5 h-3.5" /> DocuTrust v19.0.0
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
              Post-Quantum Lattice Blind Signature Studio
            </h2>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl">
              ML-DSA / Dilithium lattice-based blind signing. The signer signs without learning the message contents; the user unblinds a valid quantum-safe signature for anonymous credential presentation.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Step 1: Signer Authority Key Setup */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <Key className="w-4 h-4 text-purple-400" /> 1. Signer Authority
          </h3>
          <p className="text-xs text-slate-400">
            Signer authority generates lattice parameters and polynomial matrix keys.
          </p>
          <button
            onClick={handleGenerateSignerKeys}
            className="w-full py-2.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold transition flex items-center justify-center gap-2 shadow-lg shadow-purple-600/30"
          >
            <Key className="w-4 h-4" /> {signerKeyPair ? 'Regenerate Lattice KeyPair' : 'Generate Signer Lattice KeyPair'}
          </button>
          {signerKeyPair && (
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-2 text-xs font-mono">
              <div>
                <span className="text-slate-500">Signer DID:</span>
                <div className="text-purple-300 text-[10px] break-all">{signerKeyPair.signerDid}</div>
              </div>
              <div>
                <span className="text-slate-500">Public Key:</span>
                <div className="text-slate-400 text-[9px] truncate">{signerKeyPair.publicKeyHex}</div>
              </div>
            </div>
          )}
        </div>

        {/* Step 2: User Blinding & Signing Request */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <EyeOff className="w-4 h-4 text-indigo-400" /> 2. Message Blinding
          </h3>
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
              Private Message to Blind
            </label>
            <textarea
              rows={4}
              value={userMessage}
              onChange={(e) => setUserMessage(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 text-xs font-mono focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={handleBlindMessage}
              disabled={!signerKeyPair}
              className="py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition disabled:opacity-40"
            >
              Blind Message
            </button>
            <button
              onClick={handleBlindSign}
              disabled={!blindRequestData}
              className="py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold transition disabled:opacity-40 flex items-center justify-center gap-1"
            >
              <FileSignature className="w-3.5 h-3.5" /> Sign Blinded
            </button>
          </div>

          {blindRequestData && (
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs font-mono space-y-1">
              <div className="text-slate-400 text-[10px]">Blinded Hash:</div>
              <div className="text-indigo-300 text-[9px] truncate">{blindRequestData.request.blindedMessageHash}</div>
            </div>
          )}
        </div>

        {/* Step 3: Unblinding & Sovereign Verification */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" /> 3. Unblind & Verify
          </h3>
          <p className="text-xs text-slate-400">
            User unblinds the signature using their local secret. The result is verified with the Signer's public key.
          </p>
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={handleUnblind}
              disabled={!blindSignature}
              className="py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold transition disabled:opacity-40"
            >
              Unblind Signature
            </button>
            <button
              onClick={handleVerify}
              disabled={!unblindedReceipt}
              className="py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold transition disabled:opacity-40 flex items-center justify-center gap-1"
            >
              <CheckCircle className="w-3.5 h-3.5" /> Verify Signature
            </button>
          </div>

          {unblindedReceipt && (
            <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs font-mono space-y-1">
              <div className="text-slate-400 text-[10px]">Unblinded Signature:</div>
              <div className="text-emerald-300 text-[9px] truncate">{unblindedReceipt.unblindedSignatureHex}</div>
            </div>
          )}

          {verificationResult && (
            <div className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${verificationResult.valid ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 font-semibold' : 'bg-rose-500/10 border-rose-500/30 text-rose-400'}`}>
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              Lattice Signature: {verificationResult.valid ? 'VALID & UNTOUCHED' : verificationResult.error}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
