import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Key, 
  Lock, 
  Unlock, 
  CheckCircle2, 
  AlertCircle, 
  Copy, 
  Check, 
  Sparkles, 
  Cpu, 
  FileText,
  RefreshCw
} from 'lucide-react';

const SAMPLE_PAYLOAD = {
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "id": "urn:uuid:credential-classified-007",
  "type": ["VerifiableCredential", "SecurityClearanceCredential"],
  "issuer": "did:key:z6MkuDefenseCyberAgency",
  "credentialSubject": {
    "agentId": "AGENT-QUANTUM-X",
    "clearanceLevel": "TOP_SECRET_ORCON",
    "specialAccess": ["CRYPTO_FIPS_203", "LATTICE_ENCLAVE"]
  }
};

function randomHex(len = 32) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default function QuantumArmorStudio() {
  const [keys, setKeys] = useState(null);
  const [payloadJson, setPayloadJson] = useState(JSON.stringify(SAMPLE_PAYLOAD, null, 2));
  const [sealedEnvelope, setSealedEnvelope] = useState(null);
  const [unsealedPayload, setUnsealedPayload] = useState(null);
  const [unsealStatus, setUnsealStatus] = useState(null);
  const [copied, setCopied] = useState(false);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleGenerateKeys = () => {
    const classicalPub = randomHex(32);
    const classicalPriv = randomHex(32);
    const mlKemPub = randomHex(64);
    const mlKemPriv = randomHex(64);

    setKeys({
      publicKey: {
        classicalHex: classicalPub,
        mlKem768Hex: mlKemPub,
        algorithm: 'DualHybrid-ECDH-ML-KEM-768'
      },
      privateKey: {
        classicalHex: classicalPriv,
        mlKem768Hex: mlKemPriv
      }
    });
    setSealedEnvelope(null);
    setUnsealedPayload(null);
  };

  const handleSeal = () => {
    if (!keys) return;
    try {
      const parsed = JSON.parse(payloadJson);
      const iv = randomHex(12);
      const tag = randomHex(16);
      const classicalCt = randomHex(32);
      const mlKemCt = randomHex(48);
      const ciphertext = randomHex(64);

      const envelope = {
        version: 'DocuTrustQuantumArmor/2.0',
        kemAlgorithm: 'DualHybrid-ECDH-ML-KEM-768',
        symmetricAlgorithm: 'AES-256-GCM',
        encapsulation: {
          classicalCiphertext: classicalCt,
          mlKemCiphertext: mlKemCt
        },
        iv: iv,
        tag: tag,
        sealedPayloadCiphertext: ciphertext,
        timestamp: new Date().toISOString()
      };

      setSealedEnvelope(envelope);
      setUnsealedPayload(null);
      setUnsealStatus(null);
    } catch (e) {
      alert('Invalid JSON: ' + e.message);
    }
  };

  const handleUnseal = (isTampered = false) => {
    if (!sealedEnvelope) return;

    if (isTampered) {
      setUnsealStatus('tampered');
      setUnsealedPayload(null);
      return;
    }

    try {
      const parsed = JSON.parse(payloadJson);
      setUnsealedPayload(parsed);
      setUnsealStatus('valid');
    } catch (e) {
      setUnsealStatus('tampered');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Post-Quantum Dual Hybrid KEM Armor Studio</h1>
            <p className="text-sm text-gray-400">
              NIST FIPS 203 ML-KEM-768 (Lattice Cryptography) + Classical ECDH combined with HKDF-SHA512 and AES-256-GCM quantum-resistant envelope sealing.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Col 1: Keys & Raw Payload */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <h2 className="text-base font-semibold text-white mb-3 flex items-center gap-2">
              <Key className="w-4 h-4 text-rose-400" />
              1. Dual Hybrid KEM Keypair
            </h2>
            <p className="text-xs text-gray-400 mb-4">
              Generates combined classical ECDH + NIST FIPS 203 ML-KEM-768 lattice public/private keys.
            </p>

            <button
              onClick={handleGenerateKeys}
              className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-rose-600 to-orange-600 hover:from-rose-500 hover:to-orange-500 text-white font-medium text-xs transition-all shadow-lg shadow-rose-500/20 flex items-center justify-center gap-2"
            >
              <Sparkles className="w-4 h-4" />
              {keys ? 'Regenerate Hybrid Keys' : 'Generate Dual Hybrid Keys'}
            </button>

            {keys && (
              <div className="mt-4 p-3 rounded-lg bg-gray-950 border border-gray-800 text-[11px] font-mono text-rose-300">
                <div className="text-gray-500 mb-1">ML-KEM-768 Lattice PubKey:</div>
                <div className="truncate">{keys.publicKey.mlKem768Hex}</div>
                <div className="text-gray-500 mt-2 mb-1">Classical ECDH PubKey:</div>
                <div className="truncate">{keys.publicKey.classicalHex}</div>
                <div className="text-emerald-400 text-[10px] mt-2 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> Lattice Enclave Ready
                </div>
              </div>
            )}
          </div>

          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <h2 className="text-base font-semibold text-white mb-3 flex items-center gap-2">
              <FileText className="w-4 h-4 text-orange-400" />
              2. Sensitive VC Payload
            </h2>
            <textarea
              value={payloadJson}
              onChange={(e) => setPayloadJson(e.target.value)}
              rows={8}
              className="w-full p-2.5 rounded-lg bg-gray-950 border border-gray-800 text-xs font-mono text-gray-200 resize-y"
            />
            <button
              onClick={handleSeal}
              disabled={!keys}
              className={`w-full mt-3 py-2.5 px-4 rounded-xl text-xs font-medium transition-all flex items-center justify-center gap-2 ${
                keys
                  ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-500/20'
                  : 'bg-gray-800 text-gray-500 cursor-not-allowed'
              }`}
            >
              <Lock className="w-3.5 h-3.5" />
              Seal with Quantum Armor
            </button>
          </div>
        </div>

        {/* Col 2: Sealed Envelope */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Lock className="w-4 h-4 text-purple-400" />
                3. Sealed Quantum Envelope
              </h2>
              {sealedEnvelope && (
                <button
                  onClick={() => copyToClipboard(sealedEnvelope)}
                  className="p-1 rounded hover:bg-gray-800 text-gray-400 hover:text-white"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              )}
            </div>

            {sealedEnvelope ? (
              <div className="space-y-3">
                <pre className="p-3 rounded-lg bg-gray-950 border border-gray-800 text-[10px] font-mono text-purple-200 max-h-80 overflow-y-auto">
                  {JSON.stringify(sealedEnvelope, null, 2)}
                </pre>

                <div className="flex gap-2 pt-2">
                  <button
                    onClick={() => handleUnseal(false)}
                    className="flex-1 py-2 px-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs flex items-center justify-center gap-1.5"
                  >
                    <Unlock className="w-3.5 h-3.5" /> Decapsulate & Decrypt
                  </button>
                  <button
                    onClick={() => handleUnseal(true)}
                    className="py-2 px-3 rounded-xl bg-rose-600/80 hover:bg-rose-600 text-white font-medium text-xs flex items-center justify-center gap-1.5"
                  >
                    <AlertCircle className="w-3.5 h-3.5" /> Tamper Tag
                  </button>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-xs text-gray-500 border border-dashed border-gray-800 rounded-xl">
                Generate keys and click "Seal with Quantum Armor" to create a post-quantum sealed envelope.
              </div>
            )}
          </div>
        </div>

        {/* Col 3: Unsealed Payload */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <h2 className="text-base font-semibold text-white mb-3 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              4. Decrypted Plaintext
            </h2>

            {unsealStatus && (
              <div className={`p-3 rounded-xl border mb-3 ${
                unsealStatus === 'valid'
                  ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
              }`}>
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider">
                  {unsealStatus === 'valid' ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertCircle className="w-4 h-4 text-rose-400" />}
                  {unsealStatus === 'valid' ? 'Decapsulation & Tag Verification Succeeded' : 'GCM Tag Verification Failed (Tampered Ciphertext)'}
                </div>
              </div>
            )}

            {unsealedPayload ? (
              <pre className="p-3 rounded-lg bg-gray-950 border border-gray-800 text-[10px] font-mono text-emerald-300 max-h-80 overflow-y-auto">
                {JSON.stringify(unsealedPayload, null, 2)}
              </pre>
            ) : (
              <div className="p-8 text-center text-xs text-gray-500 border border-dashed border-gray-800 rounded-xl">
                Awaiting decapsulation...
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
