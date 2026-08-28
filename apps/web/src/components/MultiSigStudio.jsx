import React, { useState } from 'react';
import { 
  Users, 
  CheckCircle2, 
  XCircle, 
  Lock, 
  ShieldCheck, 
  Sparkles, 
  Key, 
  ArrowRight,
  AlertTriangle,
  Copy
} from 'lucide-react';

export default function MultiSigStudio() {
  const [requiredCount, setRequiredCount] = useState(2);
  const [signers, setSigners] = useState([
    { id: 1, name: 'Dr. Frank Doyle', role: 'Dean of Faculty', did: 'did:key:z6MkDean...', signed: false, sig: null },
    { id: 2, name: 'Dr. Lawrence Bacow', role: 'University Chancellor', did: 'did:key:z6MkChancellor...', signed: false, sig: null },
    { id: 3, name: 'Dr. Sarah Higgins', role: 'University Registrar', did: 'did:key:z6MkRegistrar...', signed: false, sig: null }
  ]);

  const [recipient, setRecipient] = useState('Elena Rostova');
  const [degree, setDegree] = useState('Ph.D. in Artificial Intelligence & Robotics');
  const [finalizedVC, setFinalizedVC] = useState(null);
  const [copied, setCopied] = useState(false);

  const toggleSign = (id) => {
    setSigners(prev => prev.map(s => {
      if (s.id === id) {
        const nextSigned = !s.signed;
        const fakeSig = nextSigned ? '0x' + Array.from({length: 32}, () => Math.floor(Math.random()*16).toString(16)).join('') : null;
        return { ...s, signed: nextSigned, sig: fakeSig };
      }
      return s;
    }));
  };

  const activeSignaturesCount = signers.filter(s => s.signed).length;
  const isThresholdMet = activeSignaturesCount >= requiredCount;

  const handleAssembleMultiSig = () => {
    if (!isThresholdMet) return;

    const vc = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ],
      id: `urn:uuid:multisig-${Date.now()}`,
      type: ['VerifiableCredential', 'MultiSigAccreditedCredential'],
      issuer: {
        id: 'did:web:harvard.edu',
        name: 'Harvard University Multi-Sig Governance Board'
      },
      validFrom: new Date().toISOString(),
      credentialSubject: {
        name: recipient,
        degree: degree,
        honors: 'With Highest Distinction'
      },
      proof: {
        type: 'MultiSigThresholdSignature2026',
        created: new Date().toISOString(),
        thresholdPolicy: {
          required: requiredCount,
          total: signers.length
        },
        collectedSignatures: signers.filter(s => s.signed).map(s => ({
          signerDid: s.did,
          role: s.role,
          signature: s.sig,
          signedAt: new Date().toISOString()
        }))
      }
    };

    setFinalizedVC(vc);
  };

  const copyJson = () => {
    if (finalizedVC) {
      navigator.clipboard.writeText(JSON.stringify(finalizedVC, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 text-left space-y-10">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 text-xs font-mono text-amber-400 mb-2 uppercase tracking-widest">
          <Users className="w-3.5 h-3.5" />
          <span>M-of-N Institutional Cryptographic Governance</span>
        </div>
        <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Threshold Multi-Signature Studio
        </h2>
        <p className="text-sm text-gray-400 mt-2">
          Eliminate single-point-of-failure vulnerabilities. High-stakes academic degrees and medical accreditations require 2-of-3 or 3-of-5 institutional key authorizations.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Multi-Sig Threshold Board */}
        <div className="lg:col-span-7 space-y-6">
          <div className="glass-card p-6 rounded-2xl border border-gray-800 space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <span className="text-xs font-mono text-gray-300 uppercase font-semibold">
                Threshold Policy Setting
              </span>
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="text-gray-400">Required:</span>
                <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-bold">
                  {requiredCount} of {signers.length} Signatures
                </span>
              </div>
            </div>

            {/* Signers List */}
            <div className="space-y-3">
              {signers.map(s => (
                <div
                  key={s.id}
                  onClick={() => toggleSign(s.id)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer flex items-center justify-between ${
                    s.signed
                      ? 'bg-amber-950/20 border-amber-500/50 shadow-md shadow-amber-500/10'
                      : 'bg-gray-950/60 border-gray-800/80 hover:border-gray-700'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${s.signed ? 'bg-amber-500/20 text-amber-400' : 'bg-gray-900 text-gray-500'}`}>
                      <Key className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="text-xs font-bold text-white">{s.name}</div>
                      <div className="text-[11px] text-gray-400 font-mono">{s.role} • {s.did}</div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {s.signed ? (
                      <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> Signed
                      </span>
                    ) : (
                      <span className="px-2.5 py-1 rounded-full text-[10px] font-mono text-gray-500 bg-gray-900 border border-gray-800">
                        Click to Sign
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {/* Threshold Status Bar */}
            <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-gray-400">Current Threshold State</span>
                <span className={isThresholdMet ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'}>
                  {activeSignaturesCount} / {requiredCount} Signatures Collected
                </span>
              </div>
              <div className="w-full h-2 bg-gray-900 rounded-full overflow-hidden">
                <div 
                  className={`h-full transition-all duration-500 ${isThresholdMet ? 'bg-emerald-500' : 'bg-amber-500'}`}
                  style={{ width: `${Math.min(100, (activeSignaturesCount / requiredCount) * 100)}%` }}
                />
              </div>
            </div>

            <button
              onClick={handleAssembleMultiSig}
              disabled={!isThresholdMet}
              className={`w-full py-3.5 rounded-xl text-xs font-bold uppercase tracking-wider shadow-lg flex items-center justify-center gap-2 transition-all ${
                isThresholdMet
                  ? 'bg-amber-500 hover:bg-amber-400 text-gray-950 shadow-amber-500/20 cursor-pointer'
                  : 'bg-gray-900 border border-gray-800 text-gray-500 cursor-not-allowed'
              }`}
            >
              <Sparkles className="w-4 h-4" />
              {isThresholdMet ? 'Assemble Multi-Signature Credential' : `Awaiting ${requiredCount - activeSignaturesCount} More Signature(s)`}
            </button>
          </div>
        </div>

        {/* Right Column: Output JSON */}
        <div className="lg:col-span-5 space-y-6">
          <div className="glass-card p-6 rounded-2xl border border-gray-800 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <span className="text-xs font-mono text-gray-300 uppercase font-semibold flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-amber-400" />
                Multi-Sig Credential Payload
              </span>
              {finalizedVC && (
                <button
                  onClick={copyJson}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-gray-900 border border-gray-800 text-[11px] font-mono text-gray-300 hover:text-white transition-colors"
                >
                  <Copy className="w-3 h-3" />
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              )}
            </div>

            {finalizedVC ? (
              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 font-mono text-xs space-y-1">
                  <div className="flex items-center gap-1.5 text-emerald-400 font-bold">
                    <CheckCircle2 className="w-4 h-4" /> M-of-N Cryptographic Proof Sealed
                  </div>
                  <p className="text-[11px] text-gray-300 font-sans">
                    Validated against {finalizedVC.proof.thresholdPolicy.required} independent signing keys ({finalizedVC.proof.collectedSignatures.map(s => s.role).join(' & ')}).
                  </p>
                </div>

                <pre className="p-4 bg-black rounded-xl border border-gray-800 text-[11px] font-mono text-amber-300 overflow-x-auto max-h-96">
                  {JSON.stringify(finalizedVC, null, 2)}
                </pre>
              </div>
            ) : (
              <div className="p-12 text-center text-gray-500 font-mono text-xs space-y-3">
                <Lock className="w-8 h-8 mx-auto text-gray-600 mb-2" />
                <div>Sign as at least 2 institutional authorities</div>
                <div>to assemble the Multi-Sig Verifiable Credential.</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
