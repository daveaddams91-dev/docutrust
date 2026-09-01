import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Cpu, 
  Key, 
  FileCheck2, 
  EyeOff, 
  Terminal, 
  Github, 
  Dices,
  Palette, 
  Users, 
  ShieldAlert, 
  Network, 
  Sparkles, 
  GitMerge, 
  Layers, 
  Lock, 
  Code2, 
  Package, 
  FileCode,
  Binary,
  Award,
  Fingerprint,
  Database,
  ArrowRightLeft,
  Smartphone,
  Grid,
  Bot,
  Brain,
  Hourglass,
  Menu,
  X,
  Compass,
  RefreshCw
} from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { id: 'hero', label: 'Overview', icon: ShieldCheck, cat: 'Core' },
    { id: 'zk-rollup-studio', label: 'ZK-Rollup', icon: Layers, cat: 'v20' },
    { id: 'quarantine-studio', label: 'Memory Quarantine', icon: ShieldAlert, cat: 'v20' },
    { id: 'pqabe-studio', label: 'MA-PQ-ABE', icon: Key, cat: 'v20' },
    { id: 'agent-auction-studio', label: 'Capability Auction', icon: Award, cat: 'v20' },
    { id: 'pss-studio', label: 'Proactive Sharing', icon: RefreshCw, cat: 'v19' },
    { id: 'vector-studio', label: 'Vector Commitments', icon: Layers, cat: 'v19' },
    { id: 'pqblind-studio', label: 'PQ Blind Signatures', icon: EyeOff, cat: 'v19' },
    { id: 'agent-contract-studio', label: 'Agent Smart Contracts', icon: Cpu, cat: 'v19' },
    { id: 'zkml-studio', label: 'zkML Inference', icon: Brain, cat: 'v18' },
    { id: 'mpc-studio', label: 'Garbled Circuits', icon: Lock, cat: 'v18' },
    { id: 'swarm-studio', label: 'Swarm Consensus', icon: Users, cat: 'v18' },
    { id: 'timelock-studio', label: 'Timelock VDF', icon: Hourglass, cat: 'v18' },
    { id: 'stark-studio', label: 'Transparent STARKs', icon: Cpu, cat: 'v17' },
    { id: 'frost-consensus', label: 'aBFT FROST Mesh', icon: Network, cat: 'v17' },
    { id: 'agent-memory', label: 'Verifiable Memory', icon: Bot, cat: 'v17' },
    { id: 'psi-studio', label: 'Private Set Intersection', icon: EyeOff, cat: 'v17' },
    { id: 'fhe-query', label: 'FHE Queries', icon: Lock, cat: 'v16' },
    { id: 'frost-studio', label: 'FROST Signatures', icon: Users, cat: 'v16' },
    { id: 'plonk-studio', label: 'ZK-PlonK', icon: Cpu, cat: 'v16' },
    { id: 'capability-studio', label: 'Agentic Mesh', icon: Bot, cat: 'v16' },
    { id: 'pq-ratchet', label: 'PQ Ratchet', icon: ArrowRightLeft, cat: 'v15' },
    { id: 'poly-commit', label: 'Polynomial KZG', icon: Cpu, cat: 'v15' },
    { id: 'tee-attest', label: 'TEE Attestation', icon: ShieldAlert, cat: 'v15' },
    { id: 'ibc-relayer', label: 'IBC Relayer', icon: Network, cat: 'v15' },
    { id: 'vrf-oracle', label: 'VRF & Oracles', icon: Dices, cat: 'v14' },
    { id: 'zk-dsl', label: 'ZK-DSL Compiler', icon: Code2, cat: 'v14' },
    { id: 'ai-bom', label: 'AI-BOM Registry', icon: Cpu, cat: 'v14' },
    { id: 'zk-recursive', label: 'Recursive ZK', icon: Layers, cat: 'v13' },
    { id: 'lattice', label: 'Revocation Lattice', icon: Grid, cat: 'v13' },
    { id: 'agent-provenance', label: 'AI Agent Provenance', icon: Bot, cat: 'v13' },
    { id: 'trustscore', label: 'Trust Scores', icon: Award, cat: 'Assurance' },
    { id: 'compute', label: 'Verifiable Compute', icon: Cpu, cat: 'Compute' },
    { id: 'vanish', label: 'Vanish Creds', icon: Sparkles, cat: 'Privacy' },
    { id: 'universal', label: 'StateSync & Verifier', icon: Network, cat: 'Interoperability' },
    { id: 'slhdsa', label: 'SLH-DSA FIPS 205', icon: ShieldAlert, cat: 'PQC' },
    { id: 'webauthn', label: 'Passkeys', icon: Fingerprint, cat: 'Auth' },
    { id: 'crosschain', label: 'Cross-Chain Bridge', icon: ArrowRightLeft, cat: 'Interoperability' },
    { id: 'groth16', label: 'Groth16 SNARKs', icon: Cpu, cat: 'ZK' },
    { id: 'ringsig', label: 'Ring Signatures', icon: Fingerprint, cat: 'Privacy' },
    { id: 'smt', label: 'Key Transparency', icon: Database, cat: 'Auditing' },
    { id: 'policy', label: 'Policy Studio', icon: Sparkles, cat: 'Governance' },
    { id: 'badge', label: 'Badges', icon: Award, cat: 'Identity' },
    { id: 'confidential', label: 'Confidential ZK', icon: Binary, cat: 'ZK' },
    { id: 'jsonld', label: 'JSON-LD 2.0', icon: FileCode, cat: 'Standard' },
    { id: 'trustchain', label: 'Trust Chains', icon: GitMerge, cat: 'Delegation' },
    { id: 'quantum-armor', label: 'Quantum Armor', icon: ShieldAlert, cat: 'PQC' },
    { id: 'anoncreds', label: 'AnonCreds 2.0', icon: Lock, cat: 'Privacy' },
    { id: 'dkg', label: 'FROST DKG', icon: Users, cat: 'Crypto' },
    { id: 'solidity', label: 'Solidity', icon: Code2, cat: 'Smart Contract' },
    { id: 'bundle', label: 'Audit Bundles', icon: Package, cat: 'Compliance' },
    { id: 'mesh', label: 'Trust Mesh', icon: Network, cat: 'Federation' },
    { id: 'issuer', label: 'Issuer', icon: Key, cat: 'Identity' },
    { id: 'verify', label: 'Verify', icon: FileCheck2, cat: 'Verification' },
    { id: 'developers', label: 'APIs', icon: Terminal, cat: 'Developer' }
  ];

  return (
    <header className="sticky top-0 z-50 w-full border-b border-gray-800/80 bg-gray-950/80 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <div 
          onClick={() => { setActiveTab('hero'); setMobileMenuOpen(false); }}
          className="flex items-center gap-3 cursor-pointer group"
        >
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 via-indigo-500 to-purple-500 p-[1px] flex items-center justify-center shadow-lg shadow-cyan-500/20 group-hover:scale-105 transition-transform">
            <div className="w-full h-full bg-gray-950 rounded-[11px] flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-base bg-clip-text text-transparent bg-gradient-to-r from-white via-gray-100 to-gray-400 tracking-tight">DocuTrust</span>
              <span className="text-[10px] uppercase tracking-widest px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono font-semibold">v20.0.0</span>
            </div>
            <span className="text-[10px] text-gray-400 tracking-wide block font-mono">Autonomous Sovereign Trust Mesh</span>
          </div>
        </div>

        {/* Navigation Tabs (Large Viewports) */}
        <nav className="hidden 2xl:flex items-center gap-1 max-w-[900px] overflow-x-auto py-1">
          {navItems.slice(0, 12).map(item => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all shrink-0 ${
                  isActive
                    ? 'bg-cyan-600/15 text-cyan-400 border border-cyan-500/30 shadow-sm font-semibold'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900/60'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-gray-500'}`} />
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Action Buttons & Menu Toggle */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-cyan-500/30 bg-cyan-950/30 hover:bg-cyan-900/40 text-cyan-300 transition-colors"
            title="Explore All Studios"
          >
            {mobileMenuOpen ? <X className="w-4 h-4" /> : <Compass className="w-4 h-4" />}
            <span className="hidden sm:inline">All Studios</span>
          </button>

          <a
            href="https://github.com/Raj123-0/docutrust"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg border border-gray-800 bg-gray-900/60 hover:bg-gray-800 text-gray-300 hover:text-white transition-colors"
          >
            <Github className="w-3.5 h-3.5" />
            <span className="hidden md:inline">GitHub</span>
          </a>
          <button
            onClick={() => { setActiveTab('issuer'); setMobileMenuOpen(false); }}
            className="inline-flex items-center gap-2 px-4 py-1.5 text-xs font-semibold rounded-lg bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white shadow-md shadow-cyan-500/25 transition-all"
          >
            Issue Credential
          </button>
        </div>
      </div>

      {/* Mobile / All Studios Drawer Overlay */}
      {mobileMenuOpen && (
        <div className="border-t border-gray-800 bg-gray-950/95 backdrop-blur-2xl px-4 py-6 max-h-[80vh] overflow-y-auto shadow-2xl">
          <div className="max-w-7xl mx-auto">
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-gray-800/80">
              <div className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
                <Compass className="w-4 h-4" /> DocuTrust v13.0.0 Sovereign Trust Mesh Modules
              </div>
              <span className="text-xs text-gray-500 font-mono">{navItems.length} Interactive Studios</span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2">
              {navItems.map(item => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      setActiveTab(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`flex items-center gap-2 p-2.5 rounded-xl text-left text-xs transition-all border ${
                      isActive
                        ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-300 font-semibold shadow-sm'
                        : 'bg-gray-900/40 border-gray-800/60 text-gray-300 hover:bg-gray-800/60 hover:text-white hover:border-gray-700'
                    }`}
                  >
                    <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-gray-400'}`} />
                    <span className="truncate">{item.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </header>
  );
}

