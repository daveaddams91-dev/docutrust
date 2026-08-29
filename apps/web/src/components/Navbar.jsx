import React from 'react';
import { 
  ShieldCheck, 
  Cpu, 
  Key, 
  FileCheck2, 
  EyeOff, 
  Terminal, 
  BookOpen, 
  Github, 
  Palette, 
  Scan, 
  Building2,
  Users,
  ShieldAlert,
  Network,
  Sparkles,
  GitMerge
} from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab }) {
  const navItems = [
    { id: 'hero', label: 'Overview', icon: ShieldCheck },
    { id: 'armor', label: 'Fortress Armor', icon: ShieldAlert },
    { id: 'trustmesh', label: 'Trust Mesh', icon: Network },
    { id: 'bbs', label: 'BBS+ & Oracles', icon: Sparkles },
    { id: 'didcomm', label: 'DIDComm & MMR', icon: GitMerge },
    { id: 'issuer', label: 'Issuer Studio', icon: Key },
    { id: 'designer', label: 'Visual Designer', icon: Palette },
    { id: 'multisig', label: 'Multi-Sig (M-of-N)', icon: Users },
    { id: 'scanner', label: 'Live Camera / PDF', icon: Scan },
    { id: 'dashboard', label: 'Enterprise Hub', icon: Building2 },
    { id: 'verify', label: 'Verification Hub', icon: FileCheck2 },
    { id: 'privacy', label: 'ZK Disclosure', icon: EyeOff },
    { id: 'simulator', label: 'Sandbox', icon: Cpu },
    { id: 'developers', label: 'APIs', icon: Terminal }
  ];

  return (
    <header className="sticky top-0 z-50 w-full border-b border-gray-800/80 bg-gray-950/80 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <div 
          onClick={() => setActiveTab('hero')}
          className="flex items-center gap-3 cursor-pointer group"
        >
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 via-indigo-500 to-cyan-400 p-[1px] flex items-center justify-center shadow-lg shadow-blue-500/20 group-hover:scale-105 transition-transform">
            <div className="w-full h-full bg-gray-950 rounded-[11px] flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-blue-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-lg tracking-tight text-white font-sans">DocuTrust</span>
              <span className="text-[10px] uppercase tracking-widest px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">v2.0</span>
            </div>
            <span className="text-[10px] text-gray-400 tracking-wide block font-mono">Sovereign Trust Stack</span>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="hidden xl:flex items-center gap-1">
          {navItems.map(item => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center gap-1.5 px-2.5 py-2 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30 shadow-sm font-semibold'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900/60'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-blue-400' : 'text-gray-500'}`} />
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Action Buttons */}
        <div className="flex items-center gap-3">
          <a
            href="https://github.com/Raj123-0/docutrust"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg border border-gray-800 bg-gray-900/60 hover:bg-gray-800 text-gray-300 hover:text-white transition-colors"
          >
            <Github className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">GitHub</span>
          </a>
          <button
            onClick={() => setActiveTab('issuer')}
            className="inline-flex items-center gap-2 px-4 py-1.5 text-xs font-semibold rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-md shadow-blue-600/25 transition-all"
          >
            Issue Credential
          </button>
        </div>
      </div>
    </header>
  );
}
