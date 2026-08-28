import React from 'react';
import { ShieldCheck, Github, Heart } from 'lucide-react';

export default function Footer({ setActiveTab }) {
  return (
    <footer className="border-t border-gray-900 bg-gray-950/80 text-gray-400 text-xs py-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-6">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <span className="font-bold text-white text-sm">DocuTrust</span>
            <span className="block text-[11px] text-gray-500">Open-Source Sovereign Trust Stack</span>
          </div>
        </div>

        <div className="flex items-center gap-6 text-xs text-gray-400">
          <button onClick={() => setActiveTab('hero')} className="hover:text-white transition-colors">Overview</button>
          <button onClick={() => setActiveTab('issuer')} className="hover:text-white transition-colors">Issuer Studio</button>
          <button onClick={() => setActiveTab('verify')} className="hover:text-white transition-colors">Verification Hub</button>
          <button onClick={() => setActiveTab('developers')} className="hover:text-white transition-colors">API Docs</button>
          <button onClick={() => setActiveTab('architecture')} className="hover:text-white transition-colors">Architecture</button>
        </div>

        <div className="flex items-center gap-4">
          <a
            href="https://github.com/Raj123-0/docutrust"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-gray-300 hover:text-white transition-colors"
          >
            <Github className="w-3.5 h-3.5" />
            <span>Apache-2.0 License</span>
          </a>
        </div>
      </div>
    </footer>
  );
}
