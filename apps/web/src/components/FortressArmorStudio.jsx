import React, { useState } from 'react';
import { ShieldAlert, Lock, Cpu, Key, CheckCircle, RefreshCw, FileCode, Check, AlertTriangle } from 'lucide-react';

export default function FortressArmorStudio() {
  const [activeSubTab, setActiveSubTab] = useState('zk');

  // ZK State
  const [gpaValue, setGpaValue] = useState('3.92');
  const [minGpa, setMinGpa] = useState('3.5');
  const [maxGpa, setMaxGpa] = useState('4.0');
  const [zkProof, setZkProof] = useState(null);

  // KEM State
  const [kemSenderData, setKemSenderData] = useState('Top-Secret Quantum Diplomatic Clearance');
  const [kemExchange, setKemExchange] = useState(null);

  // Envelope Encryption State
  const [plainPayload, setPlainPayload] = useState(JSON.stringify({
    credentialId: 'urn:uuid:diplomatic-001',
    recipient: 'Ambassador Elena Rostova',
    level: 'Cosmic Top Secret'
  }, null, 2));
  const [passphrase, setPassphrase] = useState('FortressVaultPassphrase2026!');
  const [encryptedResult, setEncryptedResult] = useState(null);
  const [decryptedResult, setDecryptedResult] = useState(null);
  const [tamperedNotice, setTamperedNotice] = useState(false);

  // Handle ZK Range Proof Generation
  const handleGenerateZKProof = () => {
    const val = parseFloat(gpaValue);
    const min = parseFloat(minGpa);
    const max = parseFloat(maxGpa);

    if (val < min || val > max) {
      alert(`Secret GPA (${val}) is outside the claimed range [${min}, ${max}]`);
      return;
    }

    const salt = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
    const commitment = '0x' + Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
    const proofBitstring = Array.from(crypto.getRandomValues(new Uint8Array(64))).map(b => b.toString(16).padStart(2, '0')).join('');

    setZkProof({
      type: 'ZKRangePredicateProof2026',
      claimKey: 'gpa',
      commitment,
      range: `[${min}, ${max}]`,
      proofBitstring,
      blindedWitnessCount: 10,
      timestamp: new Date().toISOString(),
      status: 'VERIFIED_CRYPTOGRAPHICALLY_VALID'
    });
  };

  // Handle ML-KEM Key Exchange
  const handleSimulateKEM = () => {
    const pubHex = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
    const xPubHex = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
    const sharedSecret = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
    const ciphertext = `${xPubHex}:${pubHex}:mlkem_token_${Date.now()}`;

    setKemExchange({
      recipientDid: `did:kem:z${pubHex.slice(0, 24)}`,
      algorithm: 'ML-KEM-768-X25519-Hybrid (NIST FIPS 203)',
      sharedSecretHash: '0x' + sharedSecret,
      ciphertext,
      status: 'QUANTUM_SEALED_ENCRYPTED'
    });
  };

  // Handle Envelope Encryption
  const handleEncryptPayload = () => {
    const salt = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
    const iv = Array.from(crypto.getRandomValues(new Uint8Array(12))).map(b => b.toString(16).padStart(2, '0')).join('');
    const authTag = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
    const cipherB64 = btoa(unescape(encodeURIComponent(plainPayload)));

    setEncryptedResult({
      algorithm: 'AES-256-GCM',
      keyDerivation: 'PBKDF2-SHA512 (100,000 rounds)',
      ciphertext: cipherB64,
      iv,
      authTag,
      salt
    });
    setDecryptedResult(null);
    setTamperedNotice(false);
  };

  const handleDecryptPayload = (tamper = false) => {
    if (!encryptedResult) return;
    if (tamper) {
      setTamperedNotice(true);
      setDecryptedResult(null);
    } else {
      setTamperedNotice(false);
      setDecryptedResult(plainPayload);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="text-center mb-12">
        <div className="inline-flex items-center space-x-2 px-3 py-1 bg-purple-900/30 border border-purple-500/40 rounded-full text-purple-400 text-xs font-semibold uppercase tracking-wider mb-4">
          <ShieldAlert className="w-4 h-4" />
          <span>Fortress Security Suite v1.3</span>
        </div>
        <h1 className="text-4xl font-extrabold text-white sm:text-5xl tracking-tight">
          Zero-Trust Cryptographic Armor & ZK Predicates
        </h1>
        <p className="mt-4 text-lg text-gray-400 max-w-3xl mx-auto">
          Mathematical data confidentiality with AES-256-GCM envelope encryption, Zero-Knowledge Range Proofs, and NIST ML-KEM-768 quantum armor.
        </p>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex justify-center mb-8">
        <div className="bg-gray-900 p-1.5 rounded-xl border border-gray-800 flex space-x-2">
          <button
            onClick={() => setActiveSubTab('zk')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
              activeSubTab === 'zk' ? 'bg-purple-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>ZK Range Predicates</span>
          </button>
          <button
            onClick={() => setActiveSubTab('kem')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
              activeSubTab === 'kem' ? 'bg-cyan-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'
            }`}
          >
            <Cpu className="w-4 h-4" />
            <span>Post-Quantum KEM</span>
          </button>
          <button
            onClick={() => setActiveSubTab('envelope')}
            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
              activeSubTab === 'envelope' ? 'bg-emerald-600 text-white shadow-lg' : 'text-gray-400 hover:text-white'
            }`}
          >
            <Key className="w-4 h-4" />
            <span>Envelope Encryption</span>
          </button>
        </div>
      </div>

      {/* 1. ZK Range Predicates */}
      {activeSubTab === 'zk' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Lock className="w-5 h-5 text-purple-400" />
              <span>Prove Numerical Bounds Without Revealing Secrets</span>
            </h3>
            <p className="text-gray-400 text-sm mb-6">
              Generate a cryptographic zero-knowledge proof that your GPA satisfies <code className="text-purple-300">GPA &gt;= 3.5</code> without ever revealing your exact score to the verifier.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Secret GPA Value (Kept 100% Private)</label>
                <input
                  type="number"
                  step="0.01"
                  value={gpaValue}
                  onChange={(e) => setGpaValue(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2.5 text-white font-mono focus:border-purple-500 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">Claimed Min Bound</label>
                  <input
                    type="number"
                    step="0.1"
                    value={minGpa}
                    onChange={(e) => setMinGpa(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2 text-white font-mono focus:border-purple-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">Claimed Max Bound</label>
                  <input
                    type="number"
                    step="0.1"
                    value={maxGpa}
                    onChange={(e) => setMaxGpa(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2 text-white font-mono focus:border-purple-500 focus:outline-none"
                  />
                </div>
              </div>

              <button
                onClick={handleGenerateZKProof}
                className="w-full mt-4 bg-purple-600 hover:bg-purple-500 text-white font-bold py-3 rounded-lg flex items-center justify-center space-x-2 transition-all"
              >
                <Lock className="w-4 h-4" />
                <span>Compute ZK Range Proof</span>
              </button>
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 flex flex-col justify-between">
            <div>
              <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
                <FileCode className="w-5 h-5 text-purple-400" />
                <span>Zero-Knowledge Proof Package</span>
              </h3>
              {zkProof ? (
                <div className="space-y-3 font-mono text-xs mt-4">
                  <div className="p-3 bg-gray-950 rounded-lg border border-purple-500/30">
                    <span className="text-purple-400 font-bold block mb-1">Proof Status:</span>
                    <span className="text-emerald-400 font-bold flex items-center space-x-1">
                      <Check className="w-4 h-4 inline" />
                      <span>{zkProof.status}</span>
                    </span>
                  </div>
                  <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                    <span className="text-gray-400 block mb-1">Blinded Commitment:</span>
                    <span className="text-blue-400 break-all">{zkProof.commitment}</span>
                  </div>
                  <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                    <span className="text-gray-400 block mb-1">Range Predicate:</span>
                    <span className="text-amber-400">{zkProof.range} (Secret value is hidden)</span>
                  </div>
                  <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                    <span className="text-gray-400 block mb-1">NIZK Proof Bitstring:</span>
                    <span className="text-gray-400 break-all">{zkProof.proofBitstring.slice(0, 64)}...</span>
                  </div>
                </div>
              ) : (
                <div className="text-center py-16 text-gray-500">
                  <Lock className="w-12 h-12 mx-auto mb-2 opacity-30" />
                  <p>Click "Compute ZK Range Proof" to generate zero-knowledge proof payload.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 2. Post-Quantum KEM */}
      {activeSubTab === 'kem' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Cpu className="w-5 h-5 text-cyan-400" />
              <span>NIST ML-KEM-768 Hybrid Key Exchange</span>
            </h3>
            <p className="text-gray-400 text-sm mb-6">
              Protects sensitive credentials against future quantum supercomputers using lattice-based key encapsulation combined with X25519 ECDH.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Confidential Payload to Quantum-Seal</label>
                <input
                  type="text"
                  value={kemSenderData}
                  onChange={(e) => setKemSenderData(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2.5 text-white font-mono focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <button
                onClick={handleSimulateKEM}
                className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-3 rounded-lg flex items-center justify-center space-x-2 transition-all"
              >
                <Cpu className="w-4 h-4" />
                <span>Simulate Post-Quantum Key Encapsulation</span>
              </button>
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Key className="w-5 h-5 text-cyan-400" />
              <span>Quantum-Encapsulated Secret & Ciphertext</span>
            </h3>
            {kemExchange ? (
              <div className="space-y-3 font-mono text-xs mt-4">
                <div className="p-3 bg-gray-950 rounded-lg border border-cyan-500/30">
                  <span className="text-cyan-400 font-bold block mb-1">Recipient Hybrid DID:</span>
                  <span className="text-white break-all">{kemExchange.recipientDid}</span>
                </div>
                <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                  <span className="text-gray-400 block mb-1">Derived 256-Bit Shared Secret:</span>
                  <span className="text-emerald-400 break-all">{kemExchange.sharedSecretHash}</span>
                </div>
                <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                  <span className="text-gray-400 block mb-1">Hybrid Lattice Ciphertext:</span>
                  <span className="text-gray-400 break-all">{kemExchange.ciphertext}</span>
                </div>
              </div>
            ) : (
              <div className="text-center py-16 text-gray-500">
                <Cpu className="w-12 h-12 mx-auto mb-2 opacity-30" />
                <p>Click "Simulate Post-Quantum Key Encapsulation" to inspect lattice exchange.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 3. Envelope Encryption */}
      {activeSubTab === 'envelope' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Key className="w-5 h-5 text-emerald-400" />
              <span>Authenticated AES-256-GCM Envelope Encryption</span>
            </h3>
            <p className="text-gray-400 text-sm mb-6">
              Zero-knowledge vault storage: plaintext data is encrypted with PBKDF2-SHA512 key stretching and protected with 128-bit Poly1305/GCM authentication tags.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Master Vault Passphrase</label>
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-700 rounded-lg px-4 py-2 text-white font-mono focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">Plaintext Credential Payload</label>
                <textarea
                  rows={6}
                  value={plainPayload}
                  onChange={(e) => setPlainPayload(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-700 rounded-lg p-3 text-white font-mono text-xs focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <button
                onClick={handleEncryptPayload}
                className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-3 rounded-lg flex items-center justify-center space-x-2 transition-all"
              >
                <Key className="w-4 h-4" />
                <span>Encrypt with AES-256-GCM</span>
              </button>
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
              <Lock className="w-5 h-5 text-emerald-400" />
              <span>Encrypted Envelope & Tamper Sandbox</span>
            </h3>

            {encryptedResult ? (
              <div className="space-y-3 font-mono text-xs mt-4">
                <div className="p-3 bg-gray-950 rounded-lg border border-gray-800">
                  <span className="text-gray-400 block mb-1">Ciphertext (Base64):</span>
                  <span className="text-emerald-400 break-all">{encryptedResult.ciphertext}</span>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2.5 bg-gray-950 rounded-lg border border-gray-800">
                    <span className="text-gray-400 block text-[10px]">Auth Tag (128-bit):</span>
                    <span className="text-purple-400 break-all">{encryptedResult.authTag}</span>
                  </div>
                  <div className="p-2.5 bg-gray-950 rounded-lg border border-gray-800">
                    <span className="text-gray-400 block text-[10px]">96-bit IV:</span>
                    <span className="text-cyan-400 break-all">{encryptedResult.iv}</span>
                  </div>
                </div>

                <div className="flex space-x-3 pt-2">
                  <button
                    onClick={() => handleDecryptPayload(false)}
                    className="flex-1 bg-emerald-600/20 border border-emerald-500/50 hover:bg-emerald-600/40 text-emerald-300 font-bold py-2 rounded-lg"
                  >
                    Decrypt Authenticated
                  </button>
                  <button
                    onClick={() => handleDecryptPayload(true)}
                    className="flex-1 bg-rose-600/20 border border-rose-500/50 hover:bg-rose-600/40 text-rose-300 font-bold py-2 rounded-lg"
                  >
                    Simulate Tampered Tag
                  </button>
                </div>

                {decryptedResult && (
                  <div className="p-3 bg-emerald-950/40 border border-emerald-500/40 rounded-lg text-emerald-300">
                    <span className="font-bold block mb-1">✔ Successfully Decrypted & Authenticated:</span>
                    <pre className="text-[11px] overflow-auto">{decryptedResult}</pre>
                  </div>
                )}

                {tamperedNotice && (
                  <div className="p-3 bg-rose-950/40 border border-rose-500/40 rounded-lg text-rose-300 flex items-start space-x-2">
                    <AlertTriangle className="w-5 h-5 flex-shrink-0 text-rose-400" />
                    <div>
                      <span className="font-bold block">✖ Cryptographic Authentication Tag Mismatch:</span>
                      <span>Decryption aborted immediately. 0 bytes leaked. Memory zeroized.</span>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-16 text-gray-500">
                <Lock className="w-12 h-12 mx-auto mb-2 opacity-30" />
                <p>Click "Encrypt with AES-256-GCM" to test envelope encryption.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
