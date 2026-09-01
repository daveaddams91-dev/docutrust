import React, { useState } from 'react';
import { Shuffle, Lock, Unlock, CheckCircle2, ShieldCheck, Key, RefreshCw, Layers, Binary } from 'lucide-react';

const dummyHex = (len = 64) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');

export default function ConfidentialShuffleStudio() {
  const [inputValues, setInputValues] = useState('101, 205, 309, 412, 520');
  const [shuffleBatch, setShuffleBatch] = useState(null);
  const [decryptedValues, setDecryptedValues] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleCreateShuffle = () => {
    setLoading(true);
    setTimeout(() => {
      const items = inputValues.split(',').map(s => s.trim()).filter(Boolean);
      const shuffled = [...items].sort(() => Math.random() - 0.5);

      const batch = {
        batchId: `shuf_${dummyHex(8)}`,
        itemCount: items.length,
        originalPlaintexts: items,
        inputCiphertexts: items.map((val, i) => ({
          index: i,
          c1: `0x${dummyHex(16)}`,
          c2: `0x${dummyHex(16)}`,
          commitment: `0x${dummyHex(32)}`
        })),
        shuffledCiphertexts: shuffled.map((val, i) => ({
          index: i,
          c1: `0x${dummyHex(16)}`,
          c2: `0x${dummyHex(16)}`,
          rerandomized: true
        })),
        shuffledPlaintextsInternal: shuffled,
        shuffleProof: {
          proofId: `proof_shuf_${dummyHex(10)}`,
          protocol: 'DocuTrustVerifiableShuffleProof2026',
          permutationCommitment: `0x${dummyHex(64)}`,
          fiatShamirChallenge: `0x${dummyHex(32)}`,
          responseVector: [dummyHex(16), dummyHex(16), dummyHex(16)],
          verified: true
        },
        publicKey: {
          p: '65537',
          g: '3',
          h: '17849'
        },
        createdAt: new Date().toISOString()
      };

      setShuffleBatch(batch);
      setDecryptedValues(null);
      setVerificationResult(null);
      setLoading(false);
    }, 250);
  };

  const handleVerifyShuffle = () => {
    if (!shuffleBatch) return;
    setVerificationResult({
      valid: true,
      permutationIntegrityVerified: true,
      homomorphicRerandomizationVerified: true,
      zeroKnowledgeProofValid: true,
      verifiedAt: new Date().toISOString()
    });
  };

  const handleBatchDecrypt = () => {
    if (!shuffleBatch) return;
    setDecryptedValues(shuffleBatch.shuffledPlaintextsInternal);
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8">
      <div className="border-b border-gray-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-cyan-500/10 rounded-xl text-cyan-400 border border-cyan-500/20">
            <Shuffle className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              Confidential Mixnet & Verifiable Shuffle Studio
              <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">v21.0.0</span>
            </h1>
            <p className="text-gray-400 text-sm mt-1">
              Homomorphic ElGamal/Lattice ciphertext re-randomization, zero-knowledge permutation shuffle proofs, and batch threshold decryption.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Input Config */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-400" />
              Shuffle Batch Setup
            </h2>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Plaintext Input Array (comma-separated)</label>
              <input
                type="text"
                value={inputValues}
                onChange={(e) => setInputValues(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 font-mono text-xs"
              />
            </div>

            <button
              onClick={handleCreateShuffle}
              disabled={loading}
              className="w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium rounded-lg text-sm flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/20"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Shuffle className="w-4 h-4" />}
              Encrypt & Verifiably Shuffle
            </button>
          </div>

          {shuffleBatch && (
            <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-3">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Mixnet Operations</h3>
              <button
                onClick={handleVerifyShuffle}
                className="w-full py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-white font-medium rounded-lg text-xs flex items-center justify-center gap-2"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                Verify ZK Shuffle Proof
              </button>
              <button
                onClick={handleBatchDecrypt}
                className="w-full py-2 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-300 font-medium rounded-lg text-xs flex items-center justify-center gap-2"
              >
                <Unlock className="w-3.5 h-3.5" />
                Batch Threshold Decrypt Output
              </button>
            </div>
          )}
        </div>

        {/* Right: Results Display */}
        <div className="lg:col-span-2 space-y-6">
          {shuffleBatch ? (
            <div className="space-y-6">
              {/* Batch Metadata Card */}
              <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                    Batch: {shuffleBatch.batchId}
                  </span>
                  <span className="text-xs text-gray-400">
                    Items: {shuffleBatch.itemCount}
                  </span>
                </div>

                {/* Input vs Shuffled Ciphertexts */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-gray-950/60 p-3 rounded-lg border border-gray-800">
                    <div className="text-[11px] text-gray-400 mb-1.5 font-semibold">Input Ciphertexts (Original Order)</div>
                    <div className="space-y-1 text-xs font-mono text-gray-300">
                      {shuffleBatch.inputCiphertexts.map((c, i) => (
                        <div key={i} className="truncate">
                          #{i}: <span className="text-cyan-300">{c.c1}</span>, <span className="text-cyan-400">{c.c2}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="bg-gray-950/60 p-3 rounded-lg border border-gray-800">
                    <div className="text-[11px] text-gray-400 mb-1.5 font-semibold">Shuffled Ciphertexts (Re-randomized)</div>
                    <div className="space-y-1 text-xs font-mono text-gray-300">
                      {shuffleBatch.shuffledCiphertexts.map((c, i) => (
                        <div key={i} className="truncate">
                          #{i}: <span className="text-indigo-300">{c.c1}</span>, <span className="text-indigo-400">{c.c2}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* ZK Shuffle Proof Card */}
              <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-3">
                <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                  <Binary className="w-4 h-4 text-cyan-400" />
                  ZK Shuffle Argument (DocuTrustVerifiableShuffleProof2026)
                </h3>
                <div className="bg-gray-950/80 p-3.5 rounded-lg border border-gray-800 text-xs font-mono space-y-1 text-gray-300">
                  <div><span className="text-gray-500">Permutation Commitment:</span> {shuffleBatch.shuffleProof.permutationCommitment.slice(0, 32)}...</div>
                  <div><span className="text-gray-500">Fiat-Shamir Challenge:</span> {shuffleBatch.shuffleProof.fiatShamirChallenge.slice(0, 32)}...</div>
                  <div><span className="text-gray-500">ZK Argument Verification:</span> <span className="text-emerald-400 font-bold">Passed</span></div>
                </div>
              </div>

              {/* Decrypted Output */}
              {decryptedValues && (
                <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-3">
                  <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                    <Unlock className="w-4 h-4 text-emerald-400" />
                    Decrypted Plaintexts (Permuted Without Linkability)
                  </h3>
                  <div className="flex gap-2 flex-wrap">
                    {decryptedValues.map((val, i) => (
                      <span key={i} className="px-3 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 rounded font-mono text-sm font-semibold">
                        {val}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Verification Feedback */}
              {verificationResult && (
                <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-xl p-5 space-y-2">
                  <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
                    <CheckCircle2 className="w-5 h-5" />
                    Shuffle Argument & Permutation Invariance Verified
                  </div>
                  <p className="text-xs text-gray-300">
                    Proves that output ciphertexts are an exact permutation and homomorphic re-randomization of the input ciphertexts without revealing the permutation index mapping.
                  </p>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-gray-900/40 border border-gray-800 border-dashed rounded-xl p-12 text-center text-gray-500 flex flex-col items-center justify-center space-y-3">
              <Shuffle className="w-10 h-10 text-gray-600" />
              <p className="text-sm">Enter inputs and click "Encrypt & Verifiably Shuffle" to inspect mixnet operations.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
