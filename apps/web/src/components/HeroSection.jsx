import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Lock, 
  Zap, 
  Layers, 
  EyeOff, 
  CheckCircle2, 
  ArrowRight, 
  Sparkles, 
  FileCode, 
  Globe2,
  Terminal
} from 'lucide-react';

export default function HeroSection({ setActiveTab }) {
  const [selectedDemoType, setSelectedDemoType] = useState('degree');

  const demoCredentials = {
    degree: {
      title: 'Master of Science in Computer Science',
      recipient: 'Alex Rivera',
      issuer: 'Stanford University (did:key:z6Mku...x9)',
      date: 'June 14, 2026',
      hash: '0x9a8f2c3b4e5d6f7a8b9c0d1e2f3a4b5c6d7e8f9a',
      status: 'Anchored on Polygon Mainnet'
    },
    employment: {
      title: 'Principal Distributed Systems Architect',
      recipient: 'Sophia Chen',
      issuer: 'Anthropic AI Corp (did:web:anthropic.com)',
      date: 'August 10, 2026',
      hash: '0x1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c',
      status: 'Anchored on Ethereum Layer 2'
    },
    medical: {
      title: 'Board Certified Neurosurgeon License',
      recipient: 'Dr. Marcus Vance',
      issuer: 'American Medical Accreditation Board',
      date: 'May 02, 2026',
      hash: '0x7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f',
      status: 'Anchored on Immutable Audit Ledger'
    }
  };

  const current = demoCredentials[selectedDemoType];

  return (
    <div className="relative overflow-hidden">
      {/* Background Glows */}
      <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[800px] h-[450px] bg-gradient-to-b from-blue-600/20 via-indigo-600/10 to-transparent blur-3xl pointer-events-none -z-10" />
      <div className="absolute top-80 right-10 w-[350px] h-[350px] bg-cyan-500/10 blur-3xl pointer-events-none -z-10" />

      {/* Hero Header */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-16 pb-20 text-center">
        {/* Release Pill */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-mono mb-8 hover:bg-blue-500/15 transition-all">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Next-Gen Sovereign Trust Protocol • 100% Open Source</span>
        </div>

        {/* Main Headline */}
        <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-white max-w-5xl mx-auto leading-[1.1] mb-6">
          The Open-Source <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-indigo-300 to-cyan-300">Trust Stack</span> for Verifiable Credentials
        </h1>

        {/* Subtitle */}
        <p className="text-lg sm:text-xl text-gray-400 max-w-3xl mx-auto mb-10 leading-relaxed">
          Issue tamper-proof academic degrees, employment proofs, and licenses with W3C standards, 
          Ed25519 digital signatures, Merkle-tree batch ledger anchors, and Zero-Knowledge selective disclosure.
        </p>

        {/* Primary CTA Buttons */}
        <div className="flex flex-wrap items-center justify-center gap-4 mb-16">
          <button
            onClick={() => setActiveTab('issuer')}
            className="flex items-center gap-2 px-7 py-3.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold shadow-lg shadow-blue-600/30 transition-all hover:scale-[1.02]"
          >
            <ShieldCheck className="w-4 h-4" />
            Launch Issuer Studio
          </button>

          <button
            onClick={() => setActiveTab('verify')}
            className="flex items-center gap-2 px-7 py-3.5 rounded-xl border border-gray-700 bg-gray-900/70 hover:bg-gray-800 text-gray-200 text-sm font-semibold transition-all hover:border-gray-600"
          >
            <FileCode className="w-4 h-4" />
            Instant Verification Hub
          </button>

          <button
            onClick={() => setActiveTab('simulator')}
            className="flex items-center gap-2 px-6 py-3.5 rounded-xl border border-blue-500/20 bg-blue-950/30 hover:bg-blue-900/40 text-blue-300 text-sm font-medium transition-all"
          >
            <Terminal className="w-4 h-4" />
            Interactive Protocol Sandbox
          </button>
        </div>

        {/* Live Interactive Credential Previewer Card */}
        <div className="max-w-4xl mx-auto glass-card rounded-2xl p-6 sm:p-8 text-left glow-border relative overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-gray-800 pb-5 mb-6">
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-xs font-mono uppercase tracking-wider text-gray-400">
                Live Verifiable Credential State (W3C VC 2.0 / RFC 8785)
              </span>
            </div>

            {/* Credential Template Switcher */}
            <div className="flex items-center gap-1 bg-gray-900/80 p-1 rounded-lg border border-gray-800">
              {['degree', 'employment', 'medical'].map(type => (
                <button
                  key={type}
                  onClick={() => setSelectedDemoType(type)}
                  className={`px-3 py-1 text-xs font-medium rounded-md capitalize transition-all ${
                    selectedDemoType === type
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-gray-400 hover:text-gray-200'
                  }`}
                >
                  {type}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
            {/* Left: Visual Credential Badge */}
            <div className="lg:col-span-7 space-y-4">
              <div className="p-5 rounded-xl border border-amber-500/30 bg-gradient-to-br from-amber-500/10 via-gray-900/90 to-gray-950">
                <div className="flex items-center justify-between text-[11px] font-mono text-amber-400/90 mb-3">
                  <span>OFFICIAL ACCREDITED RECORD</span>
                  <span className="flex items-center gap-1 text-emerald-400">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Cryptographically Valid
                  </span>
                </div>
                <h3 className="text-xl sm:text-2xl font-serif text-white font-bold mb-1">
                  {current.title}
                </h3>
                <p className="text-sm text-gray-300 mb-4">Awarded to <span className="text-amber-300 font-semibold">{current.recipient}</span></p>

                <div className="grid grid-cols-2 gap-3 text-xs font-mono pt-3 border-t border-white/10 text-gray-400">
                  <div>
                    <span className="block text-[10px] text-gray-500 uppercase">Issuing Authority</span>
                    <span className="text-gray-300 truncate block">{current.issuer}</span>
                  </div>
                  <div>
                    <span className="block text-[10px] text-gray-500 uppercase">Issuance Date</span>
                    <span className="text-gray-300">{current.date}</span>
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-gray-400">
                <span className="px-2.5 py-1 rounded bg-gray-900 border border-gray-800">
                  Algorithm: Ed25519
                </span>
                <span className="px-2.5 py-1 rounded bg-gray-900 border border-gray-800">
                  Canonicalization: JCS (RFC 8785)
                </span>
                <span className="px-2.5 py-1 rounded bg-blue-900/30 border border-blue-800/50 text-blue-300">
                  {current.status}
                </span>
              </div>
            </div>

            {/* Right: Cryptographic Verification Audit Card */}
            <div className="lg:col-span-5 bg-gray-950/90 p-5 rounded-xl border border-gray-800 font-mono text-xs space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-gray-800 text-gray-400">
                <span>Cryptographic Audit</span>
                <span className="text-emerald-400">0.04ms</span>
              </div>

              <div>
                <span className="text-gray-500 block text-[10px]">DIGITAL SIGNATURE (ED25519)</span>
                <span className="text-blue-400 break-all text-[11px]">
                  0x7f3b89e1c2a049...83d2
                </span>
              </div>

              <div>
                <span className="text-gray-500 block text-[10px]">CANONICAL JCS HASH (SHA-256)</span>
                <span className="text-gray-300 break-all text-[11px]">{current.hash}</span>
              </div>

              <div>
                <span className="text-gray-500 block text-[10px]">MERKLE ROOT ANCHOR</span>
                <span className="text-purple-400 break-all text-[11px]">
                  0xe9c3140a82b17f54...9184
                </span>
              </div>

              <button 
                onClick={() => setActiveTab('verify')}
                className="w-full mt-2 py-2 rounded bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/30 text-blue-300 font-sans text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors"
              >
                Inspect Full Verification Stack <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

        {/* Feature Grid Highlights */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-6xl mx-auto mt-20 text-left">
          <div className="glass-card p-6 rounded-2xl border border-gray-800/80 hover:border-blue-500/40 transition-all">
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 mb-4">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Cryptographic Tamper-Proofing</h3>
            <p className="text-sm text-gray-400 leading-relaxed">
              Every document is signed with Ed25519 asymmetric keys over canonical JSON (RFC 8785). 
              A single modified character immediately renders the cryptographic signature invalid.
            </p>
          </div>

          <div className="glass-card p-6 rounded-2xl border border-gray-800/80 hover:border-indigo-500/40 transition-all">
            <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 mb-4">
              <EyeOff className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">ZK-Style Selective Disclosure</h3>
            <p className="text-sm text-gray-400 leading-relaxed">
              Holders can prove they possess a valid degree or qualification while selectively hiding 
              sensitive attributes like GPA, student ID, birthdate, or residential address.
            </p>
          </div>

          <div className="glass-card p-6 rounded-2xl border border-gray-800/80 hover:border-cyan-500/40 transition-all">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mb-4">
              <Layers className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">10,000+ Batch Merkle Anchoring</h3>
            <p className="text-sm text-gray-400 leading-relaxed">
              Batch thousands of diplomas or corporate badges into a single 32-byte Merkle root anchored 
              to public ledgers with individual logarithmic inclusion proofs.
            </p>
          </div>
        </div>

        {/* Benchmark vs Legacy Comparison Table */}
        <div className="max-w-5xl mx-auto mt-24 glass-card rounded-2xl p-8 text-left">
          <div className="text-center max-w-2xl mx-auto mb-8">
            <h2 className="text-2xl sm:text-3xl font-bold text-white mb-2">
              DocuTrust vs Legacy Verification Services
            </h2>
            <p className="text-sm text-gray-400">
              Why sovereign cryptographic verification is replacing manual institutional background checks.
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-xs font-mono text-gray-400 uppercase">
                  <th className="pb-3 px-4">Feature</th>
                  <th className="pb-3 px-4 text-blue-400 font-bold">DocuTrust (Open Source)</th>
                  <th className="pb-3 px-4 text-gray-500">Proprietary / Closed Vendors</th>
                  <th className="pb-3 px-4 text-gray-500">Legacy Manual Checks</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60 font-sans">
                <tr>
                  <td className="py-4 px-4 font-medium text-white">Verification Time</td>
                  <td className="py-4 px-4 text-emerald-400 font-semibold font-mono">&lt; 50 milliseconds</td>
                  <td className="py-4 px-4 text-gray-400 font-mono">1 - 5 seconds (API)</td>
                  <td className="py-4 px-4 text-rose-400 font-mono">2 - 3 weeks</td>
                </tr>
                <tr>
                  <td className="py-4 px-4 font-medium text-white">Vendor Lock-In</td>
                  <td className="py-4 px-4 text-emerald-400 font-semibold">Zero (Open Source & Self-Hostable)</td>
                  <td className="py-4 px-4 text-rose-400">High (Proprietary platform fees)</td>
                  <td className="py-4 px-4 text-gray-400">N/A</td>
                </tr>
                <tr>
                  <td className="py-4 px-4 font-medium text-white">Standards Compliance</td>
                  <td className="py-4 px-4 text-emerald-400 font-semibold font-mono">W3C VC 2.0 / DID / RFC 8785</td>
                  <td className="py-4 px-4 text-amber-400 font-mono">Partial / Custom schemas</td>
                  <td className="py-4 px-4 text-rose-400 font-mono">None (Paper / PDF emails)</td>
                </tr>
                <tr>
                  <td className="py-4 px-4 font-medium text-white">Privacy / Selective Disclosure</td>
                  <td className="py-4 px-4 text-emerald-400 font-semibold">Built-in Salted Merkle ZK Proofs</td>
                  <td className="py-4 px-4 text-rose-400">Exposes entire document</td>
                  <td className="py-4 px-4 text-rose-400">Complete data exposure</td>
                </tr>
                <tr>
                  <td className="py-4 px-4 font-medium text-white">Revocation Mechanism</td>
                  <td className="py-4 px-4 text-emerald-400 font-semibold font-mono">StatusList2021 Bitstrings</td>
                  <td className="py-4 px-4 text-amber-400 font-mono">Database lookup</td>
                  <td className="py-4 px-4 text-rose-400 font-mono">Manual telephone / email</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
