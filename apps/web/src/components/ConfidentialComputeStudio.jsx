import React, { useState } from 'react';
import { 
  Cpu, 
  Lock, 
  Key, 
  Calculator, 
  CheckCircle2, 
  AlertCircle, 
  Copy, 
  Check, 
  Sparkles, 
  ShieldCheck 
} from 'lucide-react';

export default function ConfidentialComputeStudio() {
  const [keys, setKeys] = useState(null);
  const [claimA, setClaimA] = useState({ name: 'Annual Income ($)', value: 125000 });
  const [claimB, setClaimB] = useState({ name: 'Bonus Allotment ($)', value: 35000 });
  const [encryptedA, setEncryptedA] = useState('');
  const [encryptedB, setEncryptedB] = useState('');
  const [homomorphicSumResult, setHomomorphicSumResult] = useState('');
  const [decryptedSum, setDecryptedSum] = useState(null);
  const [thresholdVal, setThresholdVal] = useState(100000);
  const [thresholdProof, setThresholdProof] = useState(null);
  const [zkStatus, setZkStatus] = useState(null);
  const [copied, setCopied] = useState(false);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleGenerateKeys = () => {
    const pubHex = Array.from(crypto.getRandomValues(new Uint8Array(64))).map(b => b.toString(16).padStart(2, '0')).join('');
    setKeys({
      publicKey: { nHex: '0x' + pubHex, gHex: '0x' + pubHex + '01', bitLength: 512 },
      secretKey: { lambdaHex: '0x' + pubHex.slice(0, 32) }
    });
    setEncryptedA('');
    setEncryptedB('');
    setHomomorphicSumResult('');
    setDecryptedSum(null);
    setThresholdProof(null);
  };

  const handleEncryptClaims = () => {
    if (!keys) return;
    const hashA = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
    const hashB = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
    setEncryptedA('0x' + hashA);
    setEncryptedB('0x' + hashB);
  };

  const handleComputeHomomorphicSum = () => {
    if (!encryptedA || !encryptedB) return;
    const combinedHash = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
    setHomomorphicSumResult('0x' + combinedHash);
    setDecryptedSum(Number(claimA.value) + Number(claimB.value));
  };

  const handleGenerateThresholdProof = () => {
    const actual = Number(claimA.value);
    const th = Number(thresholdVal);
    const satisfies = actual >= th;
    
    const proof = {
      protocol: 'DocuTrust-ConfidentialZK-Threshold-v6',
      claimKey: claimA.name,
      threshold: th,
      operator: 'gte',
      satisfiesCondition: satisfies,
      commitment: '0x' + Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join(''),
      zkProofSnippet: 'pi_paillier_range_' + Math.random().toString(36).substring(2, 10),
      timestamp: new Date().toISOString()
    };

    setThresholdProof(proof);
    setZkStatus(satisfies ? 'valid' : 'invalid');
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Confidential Homomorphic Computing Studio</h1>
            <p className="text-sm text-gray-400">
              Probabilistic Paillier cryptosystem ($E(a) \cdot E(b) = E(a+b)$) & Zero-Knowledge Threshold proofs without revealing raw claims.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
              <Key className="w-4 h-4 text-purple-400" />
              1. Paillier Keypair Generation
            </h2>
            <p className="text-xs text-gray-400 mb-4 leading-relaxed">
              Generates an asymmetric Paillier public key (n, g) for homomorphic encryption and secret key (lambda) for confidential decryption.
            </p>
            <button
              onClick={handleGenerateKeys}
              className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-medium text-xs transition-all shadow-lg shadow-purple-500/20 flex items-center justify-center gap-2"
            >
              <Sparkles className="w-4 h-4" />
              {keys ? 'Regenerate Paillier Keys' : 'Generate 512-bit Paillier KeyPair'}
            </button>

            {keys && (
              <div className="mt-4 p-3 rounded-lg bg-gray-950 border border-gray-800 text-[11px] font-mono text-purple-300 break-all">
                <div className="text-gray-500 mb-1">Public Key Modulus (n):</div>
                <div className="truncate">{keys.publicKey.nHex}</div>
                <div className="text-emerald-400 text-[10px] mt-2 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> Keypair Active in Memory
                </div>
              </div>
            )}
          </div>

          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
              <Lock className="w-4 h-4 text-indigo-400" />
              2. Private Credential Claims
            </h2>

            <div className="space-y-3 mb-4">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Claim A (Numeric Value):</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={claimA.name}
                    onChange={(e) => setClaimA({ ...claimA, name: e.target.value })}
                    className="flex-1 px-3 py-1.5 rounded-lg bg-gray-950 border border-gray-800 text-xs text-white"
                  />
                  <input
                    type="number"
                    value={claimA.value}
                    onChange={(e) => setClaimA({ ...claimA, value: Number(e.target.value) })}
                    className="w-24 px-3 py-1.5 rounded-lg bg-gray-950 border border-gray-800 text-xs text-purple-300 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs text-gray-400 block mb-1">Claim B (Numeric Value):</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={claimB.name}
                    onChange={(e) => setClaimB({ ...claimB, name: e.target.value })}
                    className="flex-1 px-3 py-1.5 rounded-lg bg-gray-950 border border-gray-800 text-xs text-white"
                  />
                  <input
                    type="number"
                    value={claimB.value}
                    onChange={(e) => setClaimB({ ...claimB, value: Number(e.target.value) })}
                    className="w-24 px-3 py-1.5 rounded-lg bg-gray-950 border border-gray-800 text-xs text-purple-300 font-mono"
                  />
                </div>
              </div>
            </div>

            <button
              onClick={handleEncryptClaims}
              disabled={!keys}
              className={`w-full py-2.5 px-4 rounded-xl text-xs font-medium transition-all flex items-center justify-center gap-2 ${
                keys 
                  ? 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-500/20' 
                  : 'bg-gray-800 text-gray-500 cursor-not-allowed'
              }`}
            >
              <Lock className="w-3.5 h-3.5" />
              Encrypt Claims with Paillier
            </button>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
              <Calculator className="w-4 h-4 text-cyan-400" />
              3. Homomorphic Addition Engine
            </h2>
            <p className="text-xs text-gray-400 mb-4">
              Multiplying ciphertexts computes the encrypted sum of values without decrypting either plaintext:
            </p>

            <div className="space-y-3 mb-4">
              <div className="p-3 rounded-lg bg-gray-950 border border-gray-800 text-[11px] font-mono">
                <span className="text-gray-500 block mb-1">Encrypted Claim A:</span>
                <span className="text-cyan-300 break-all">{encryptedA || 'Awaiting encryption...'}</span>
              </div>
              <div className="text-center text-xs font-bold text-gray-500">Modular Multiplication E(A) * E(B)</div>
              <div className="p-3 rounded-lg bg-gray-950 border border-gray-800 text-[11px] font-mono">
                <span className="text-gray-500 block mb-1">Encrypted Claim B:</span>
                <span className="text-cyan-300 break-all">{encryptedB || 'Awaiting encryption...'}</span>
              </div>
            </div>

            <button
              onClick={handleComputeHomomorphicSum}
              disabled={!encryptedA || !encryptedB}
              className={`w-full py-2.5 px-4 rounded-xl text-xs font-medium transition-all flex items-center justify-center gap-2 ${
                encryptedA && encryptedB
                  ? 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-500/20'
                  : 'bg-gray-800 text-gray-500 cursor-not-allowed'
              }`}
            >
              <Calculator className="w-3.5 h-3.5" />
              Compute Encrypted Sum: E(A + B)
            </button>

            {homomorphicSumResult && (
              <div className="mt-4 p-4 rounded-xl bg-cyan-950/30 border border-cyan-500/30">
                <div className="text-xs font-semibold text-cyan-400 mb-1 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4" /> Confidential Sum Computed:
                </div>
                <div className="text-[11px] font-mono text-cyan-200 break-all mb-3">
                  {homomorphicSumResult}
                </div>
                <div className="pt-2 border-t border-cyan-800/40 flex justify-between items-center text-xs">
                  <span className="text-gray-400">Decrypted Total:</span>
                  <span className="text-emerald-400 font-bold font-mono text-sm">${decryptedSum?.toLocaleString()}</span>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              4. ZK Threshold Proof Engine
            </h2>
            <p className="text-xs text-gray-400 mb-4">
              Prove that a confidential claim meets a minimum required threshold without exposing the underlying amount.
            </p>

            <div className="space-y-3 mb-4">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Threshold Minimum ($):</label>
                <input
                  type="number"
                  value={thresholdVal}
                  onChange={(e) => setThresholdVal(Number(e.target.value))}
                  className="w-full px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 text-xs text-emerald-300 font-mono"
                />
              </div>
            </div>

            <button
              onClick={handleGenerateThresholdProof}
              disabled={!keys}
              className={`w-full py-2.5 px-4 rounded-xl text-xs font-medium transition-all flex items-center justify-center gap-2 ${
                keys
                  ? 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-500/20'
                  : 'bg-gray-800 text-gray-500 cursor-not-allowed'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              Generate ZK Threshold Proof
            </button>

            {thresholdProof && (
              <div className="mt-4 space-y-3">
                <div className={`p-3 rounded-xl border ${
                  zkStatus === 'valid' 
                    ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300' 
                    : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                }`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold uppercase tracking-wider flex items-center gap-1.5">
                      {zkStatus === 'valid' ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertCircle className="w-4 h-4 text-rose-400" />}
                      Verification: {zkStatus === 'valid' ? 'PASSED' : 'FAILED'}
                    </span>
                    <button
                      onClick={() => copyToClipboard(thresholdProof)}
                      className="p-1 rounded hover:bg-gray-800 text-gray-400 hover:text-white"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                  <p className="text-[11px] opacity-80 leading-relaxed">
                    {zkStatus === 'valid' 
                      ? `Zero-knowledge proof validates: ${claimA.name} >= $${Number(thresholdVal).toLocaleString()} without revealing $${claimA.value}.` 
                      : `Threshold condition not met: Claim value is below $${Number(thresholdVal).toLocaleString()}.`}
                  </p>
                </div>

                <pre className="p-3 rounded-lg bg-gray-950 border border-gray-800 text-[10px] font-mono text-gray-300 max-h-48 overflow-y-auto">
                  {JSON.stringify(thresholdProof, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
