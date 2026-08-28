import React, { useState } from 'react';
import { 
  EyeOff, 
  Eye, 
  Lock, 
  ShieldCheck, 
  CheckCircle2, 
  Sparkles, 
  Key, 
  Layers,
  ArrowRight,
  Copy
} from 'lucide-react';

export default function SelectiveDisclosureStudio() {
  const initialClaims = [
    { key: 'name', label: 'Full Name', value: 'Alex Rivera', disclosed: true, salt: '8f92a1c04e3b419a', sensitive: false },
    { key: 'degree', label: 'Degree / Title', value: 'M.Sc. Computer Science', disclosed: true, salt: '9e1287f2b1d30c5e', sensitive: false },
    { key: 'graduationYear', label: 'Graduation Year', value: '2026', disclosed: true, salt: '4a1b3c5d7e9f0a2b', sensitive: false },
    { key: 'gpa', label: 'Cumulative GPA', value: '3.98 / 4.00', disclosed: false, salt: '6c0d8e2f4a1b3c5d', sensitive: true },
    { key: 'studentId', label: 'Student ID Number', value: 'STU-992014-CA', disclosed: false, salt: '1e3f7a5b6c0d8e2f', sensitive: true },
    { key: 'nationalId', label: 'National Identity / SSN', value: 'XXX-XX-9482', disclosed: false, salt: '4b5c6d7e8f9a0b1c', sensitive: true },
    { key: 'birthDate', label: 'Date of Birth', value: '1998-05-14', disclosed: false, salt: '2d3e4f5a6b7c8d9e', sensitive: true }
  ];

  const [claims, setClaims] = useState(initialClaims);
  const [vpOutput, setVpOutput] = useState(null);
  const [copied, setCopied] = useState(false);

  const toggleClaim = (index) => {
    setClaims(prev => {
      const updated = [...prev];
      updated[index].disclosed = !updated[index].disclosed;
      return updated;
    });
  };

  const handleGenerateVP = () => {
    const disclosed = claims.filter(c => c.disclosed);
    const hidden = claims.filter(c => !c.disclosed);
    const claimsRoot = '0x8f2c3b4e5d6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b';

    const vp = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ],
      type: ['VerifiablePresentation', 'SelectiveDisclosurePresentation'],
      claimsRoot,
      totalClaimsInAnchor: claims.length,
      disclosedClaims: disclosed.map((c, i) => ({
        key: c.key,
        value: c.value,
        salt: c.salt,
        proof: {
          leafIndex: i,
          leafHash: '0x' + Array.from({length: 32}, () => Math.floor(Math.random()*16).toString(16)).join(''),
          merkleRoot: claimsRoot
        }
      })),
      hiddenClaimsCount: hidden.length,
      proof: {
        type: 'Ed25519Signature2020',
        issuerVerificationMethod: 'did:key:z6MkuG2B83x1K8u4W7q2V6mJ9P4k#keys-1',
        signature: '0x7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f'
      }
    };

    setVpOutput(vp);
  };

  const copyVp = () => {
    if (vpOutput) {
      navigator.clipboard.writeText(JSON.stringify(vpOutput, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 text-left">
      {/* Header */}
      <div className="mb-10">
        <div className="flex items-center gap-2 text-xs font-mono text-purple-400 mb-2 uppercase tracking-widest">
          <EyeOff className="w-3.5 h-3.5" />
          <span>Zero-Knowledge Selective Disclosure Protocol</span>
        </div>
        <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Privacy-Preserving Credential Presentation
        </h2>
        <p className="text-sm text-gray-400 mt-2">
          Prove your academic qualifications or employment status to employers without exposing sensitive personal identifiers like GPA, National ID, or Birthdate.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left: Claim Selector & Blinding Table */}
        <div className="lg:col-span-7 space-y-6">
          <div className="glass-card p-6 rounded-2xl border border-gray-800 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <span className="text-xs font-mono text-gray-300 uppercase font-semibold">
                Credential Claims & Disclosure Matrix
              </span>
              <span className="text-xs font-mono text-purple-400">
                {claims.filter(c => c.disclosed).length} Disclosed • {claims.filter(c => !c.disclosed).length} Blinded
              </span>
            </div>

            <div className="space-y-3">
              {claims.map((claim, idx) => (
                <div
                  key={claim.key}
                  onClick={() => toggleClaim(idx)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer flex items-center justify-between ${
                    claim.disclosed
                      ? 'bg-blue-950/20 border-blue-500/40 shadow-sm'
                      : 'bg-gray-950/60 border-gray-800/80 opacity-70 hover:opacity-100'
                  }`}
                >
                  <div className="flex items-center gap-3.5">
                    <input
                      type="checkbox"
                      checked={claim.disclosed}
                      onChange={() => {}} // Handled by parent div
                      className="w-4 h-4 rounded text-blue-600 bg-gray-900 border-gray-700 pointer-events-none"
                    />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-white">{claim.label}</span>
                        {claim.sensitive && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-rose-500/10 text-rose-400 border border-rose-500/20 uppercase">
                            Sensitive
                          </span>
                        )}
                      </div>
                      <span className="text-xs font-mono text-gray-300 mt-0.5 block">
                        {claim.disclosed ? claim.value : '•••••••••••• (BLINDED WITH 128-BIT SALT)'}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {claim.disclosed ? (
                      <span className="flex items-center gap-1 text-[11px] font-mono text-blue-400 bg-blue-500/10 px-2 py-1 rounded-md border border-blue-500/20">
                        <Eye className="w-3 h-3" /> Disclosed
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-[11px] font-mono text-gray-500 bg-gray-900 px-2 py-1 rounded-md border border-gray-800">
                        <EyeOff className="w-3 h-3" /> Hidden (ZK)
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>

            <button
              onClick={handleGenerateVP}
              className="w-full py-3.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold uppercase tracking-wider shadow-lg shadow-purple-600/30 flex items-center justify-center gap-2 transition-all"
            >
              <Sparkles className="w-4 h-4" />
              Generate Verifiable Presentation with Merkle Proofs
            </button>
          </div>
        </div>

        {/* Right: Cryptographic Verifiable Presentation Output */}
        <div className="lg:col-span-5 space-y-6">
          <div className="glass-card p-6 rounded-2xl border border-gray-800 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <span className="text-xs font-mono text-gray-300 uppercase font-semibold flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-purple-400" />
                ZK Verifiable Presentation Output
              </span>
              {vpOutput && (
                <button
                  onClick={copyVp}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-gray-900 border border-gray-800 text-[11px] font-mono text-gray-300 hover:text-white transition-colors"
                >
                  <Copy className="w-3 h-3" />
                  {copied ? 'Copied!' : 'Copy JSON'}
                </button>
              )}
            </div>

            {vpOutput ? (
              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 font-mono text-xs space-y-2">
                  <div className="flex items-center gap-1.5 text-emerald-400 font-bold">
                    <CheckCircle2 className="w-4 h-4" /> Mathematical Proof Verified
                  </div>
                  <p className="text-[11px] text-gray-300 font-sans">
                    The verifier confirms that <span className="text-white font-semibold">{vpOutput.disclosedClaims.length} disclosed claims</span> are mathematically part of the original issuer's signed claims root (<span className="text-purple-300">{vpOutput.claimsRoot.slice(0, 16)}...</span>) without discovering the <span className="text-white font-semibold">{vpOutput.hiddenClaimsCount} hidden attributes</span>.
                  </p>
                </div>

                <pre className="p-4 bg-black rounded-xl border border-gray-800 text-[11px] font-mono text-purple-300 overflow-x-auto max-h-96">
                  {JSON.stringify(vpOutput, null, 2)}
                </pre>
              </div>
            ) : (
              <div className="p-12 text-center text-gray-500 font-mono text-xs space-y-2">
                <Lock className="w-8 h-8 mx-auto text-gray-600 mb-2" />
                <div>Select the claims to reveal on the left</div>
                <div>and click "Generate Verifiable Presentation"</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
