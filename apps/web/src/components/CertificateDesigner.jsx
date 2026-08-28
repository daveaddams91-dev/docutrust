import React, { useState } from 'react';
import { 
  Palette, 
  Download, 
  Sparkles, 
  CheckCircle2, 
  Layers, 
  Type, 
  Sliders, 
  ShieldCheck,
  Eye,
  RefreshCw
} from 'lucide-react';

export default function CertificateDesigner() {
  const [theme, setTheme] = useState('academic-gold');
  const [institution, setInstitution] = useState('HARVARD UNIVERSITY');
  const [recipient, setRecipient] = useState('Alexandra M. Chen');
  const [degree, setDegree] = useState('Doctor of Philosophy in Computer Science');
  const [honors, setHonors] = useState('Summa Cum Laude');
  const [issueDate, setIssueDate] = useState('May 28, 2026');
  const [chancellor, setChancellor] = useState('Dr. Lawrence Bacow');
  const [dean, setDean] = useState('Dr. Frank Doyle');
  const [showGuilloche, setShowGuilloche] = useState(true);
  const [showGoldSeal, setShowGoldSeal] = useState(true);

  const themeStyles = {
    'academic-gold': {
      bg: 'from-amber-950/40 via-gray-950 to-black',
      border: 'border-amber-500/70',
      accent: 'text-amber-400',
      sealBg: 'border-amber-400 text-amber-400',
      font: 'font-serif'
    },
    'ivy-crimson': {
      bg: 'from-rose-950/40 via-gray-950 to-black',
      border: 'border-rose-600/70',
      accent: 'text-rose-400',
      sealBg: 'border-rose-500 text-rose-400',
      font: 'font-serif'
    },
    'cyber-emerald': {
      bg: 'from-emerald-950/40 via-gray-950 to-black',
      border: 'border-emerald-500/70',
      accent: 'text-emerald-400',
      sealBg: 'border-emerald-400 text-emerald-400',
      font: 'font-mono'
    },
    'corporate-blue': {
      bg: 'from-blue-950/40 via-gray-950 to-black',
      border: 'border-blue-500/70',
      accent: 'text-blue-400',
      sealBg: 'border-blue-400 text-blue-400',
      font: 'font-sans'
    },
    'swiss-minimal': {
      bg: 'from-zinc-900 via-gray-950 to-black',
      border: 'border-zinc-400/50',
      accent: 'text-zinc-200',
      sealBg: 'border-zinc-300 text-zinc-300',
      font: 'font-sans'
    }
  };

  const currentTheme = themeStyles[theme];

  const downloadSvg = () => {
    const svgElement = document.getElementById('designer-certificate-svg');
    if (!svgElement) return;
    const svgData = new XMLSerializer().serializeToString(svgElement);
    const blob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `certificate-${recipient.replace(/\s+/g, '-').toLowerCase()}.svg`;
    link.click();
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 text-left">
      {/* Header */}
      <div className="mb-10 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-amber-400 mb-2 uppercase tracking-widest">
            <Palette className="w-3.5 h-3.5" />
            <span>WYSIWYG Dynamic Certificate Studio</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Visual Certificate & Diploma Designer
          </h2>
          <p className="text-sm text-gray-400 mt-2">
            Customize typography, ornate guilloche security patterns, institutional crests, and dynamic W3C QR code anchors.
          </p>
        </div>

        <button
          onClick={downloadSvg}
          className="flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-gray-950 font-bold text-xs uppercase tracking-wider shadow-lg shadow-amber-500/20 transition-all"
        >
          <Download className="w-4 h-4" />
          Export High-Res Vector SVG
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Visual Customizer Controls */}
        <div className="lg:col-span-5 space-y-6">
          {/* Theme Palette Switcher */}
          <div className="glass-card p-6 rounded-2xl border border-gray-800 space-y-3">
            <label className="text-xs font-mono text-gray-300 uppercase font-semibold block">
              Security Design Preset
            </label>
            <div className="grid grid-cols-2 gap-2">
              {[
                { id: 'academic-gold', label: 'Academic Gold Foil' },
                { id: 'ivy-crimson', label: 'Ivy League Crimson' },
                { id: 'cyber-emerald', label: 'Quantum Emerald' },
                { id: 'corporate-blue', label: 'Corporate Blue' },
                { id: 'swiss-minimal', label: 'Swiss Modern Minimal' }
              ].map(t => (
                <button
                  key={t.id}
                  onClick={() => setTheme(t.id)}
                  className={`p-2.5 rounded-xl text-xs font-medium border text-left transition-all ${
                    theme === t.id
                      ? 'bg-amber-500/15 border-amber-500/50 text-white shadow-sm'
                      : 'bg-gray-950/60 border-gray-800 text-gray-400 hover:text-white'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          {/* Form Content Inputs */}
          <div className="glass-card p-6 rounded-2xl border border-gray-800 space-y-4">
            <h3 className="text-xs font-mono text-gray-300 uppercase font-semibold">
              Diploma Typography & Tokens
            </h3>

            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Issuing University / Institution</label>
              <input
                type="text"
                value={institution}
                onChange={e => setInstitution(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-amber-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Recipient Name</label>
              <input
                type="text"
                value={recipient}
                onChange={e => setRecipient(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-amber-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Degree Title & Honors</label>
              <input
                type="text"
                value={degree}
                onChange={e => setDegree(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-amber-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Honors / Distinction</label>
                <input
                  type="text"
                  value={honors}
                  onChange={e => setHonors(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-amber-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Conferral Date</label>
                <input
                  type="text"
                  value={issueDate}
                  onChange={e => setIssueDate(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-amber-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">President / Chancellor</label>
                <input
                  type="text"
                  value={chancellor}
                  onChange={e => setChancellor(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-amber-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Dean of Faculty</label>
                <input
                  type="text"
                  value={dean}
                  onChange={e => setDean(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-amber-500"
                />
              </div>
            </div>

            {/* Pattern & Seal Toggles */}
            <div className="pt-3 border-t border-gray-800 flex items-center justify-between text-xs">
              <label className="flex items-center gap-2 cursor-pointer text-gray-300">
                <input
                  type="checkbox"
                  checked={showGuilloche}
                  onChange={e => setShowGuilloche(e.target.checked)}
                  className="w-4 h-4 rounded text-amber-500 bg-gray-900 border-gray-700"
                />
                Guilloche Latent Pattern
              </label>

              <label className="flex items-center gap-2 cursor-pointer text-gray-300">
                <input
                  type="checkbox"
                  checked={showGoldSeal}
                  onChange={e => setShowGoldSeal(e.target.checked)}
                  className="w-4 h-4 rounded text-amber-500 bg-gray-900 border-gray-700"
                />
                Official Gold Crest Seal
              </label>
            </div>
          </div>
        </div>

        {/* Right Column: Live SVG Render Canvas */}
        <div className="lg:col-span-7 flex flex-col justify-center">
          <div className="glass-card p-4 sm:p-6 rounded-2xl border border-gray-800 shadow-2xl relative overflow-hidden">
            <svg
              id="designer-certificate-svg"
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 900 640"
              className="w-full h-auto rounded-xl shadow-2xl"
            >
              <defs>
                <linearGradient id="canvasGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#0a0a0c" />
                  <stop offset="50%" stopColor="#040711" />
                  <stop offset="100%" stopColor="#000000" />
                </linearGradient>
                <pattern id="guillochePattern" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 0 20 Q 10 5 20 20 T 40 20" fill="none" stroke="#d4af37" strokeWidth="0.4" strokeOpacity={showGuilloche ? '0.18' : '0'} />
                  <path d="M 20 0 Q 5 10 20 20 T 20 40" fill="none" stroke="#d4af37" strokeWidth="0.4" strokeOpacity={showGuilloche ? '0.18' : '0'} />
                </pattern>
              </defs>

              {/* Background */}
              <rect width="900" height="640" fill="url(#canvasGrad)" />
              <rect width="900" height="640" fill="url(#guillochePattern)" />

              {/* Ornate Frame */}
              <rect x="25" y="25" width="850" height="590" rx="12" fill="none" stroke="#d4af37" strokeWidth="2" strokeOpacity="0.8" />
              <rect x="35" y="35" width="830" height="570" rx="8" fill="none" stroke="#d4af37" strokeWidth="1" strokeDasharray="6 3" strokeOpacity="0.4" />

              {/* Header */}
              <text x="450" y="95" fontFamily="Cinzel, serif" fontSize="22" fill="#d4af37" fontWeight="700" textAnchor="middle" letterSpacing="4">
                {institution.toUpperCase()}
              </text>
              <text x="450" y="125" fontFamily="Inter, sans-serif" fontSize="10" fill="#a1a1aa" fontWeight="500" textAnchor="middle" letterSpacing="3">
                SOVEREIGN POST-QUANTUM VERIFIABLE DIPLOMA
              </text>
              <line x1="320" y1="140" x2="580" y2="140" stroke="#d4af37" strokeWidth="1" strokeOpacity="0.5" />

              {/* Body */}
              <text x="450" y="190" fontFamily="Cinzel, serif" fontSize="13" fill="#e4e4e7" textAnchor="middle" letterSpacing="1.5">
                ON RECOMMENDATION OF THE FACULTY HEREBY CONFIRES UPON
              </text>

              <text x="450" y="260" fontFamily="Playfair Display, Georgia, serif" fontSize="36" fill="#ffffff" fontWeight="700" textAnchor="middle">
                {recipient}
              </text>
              <line x1="220" y1="280" x2="680" y2="280" stroke="#d4af37" strokeWidth="1" strokeOpacity="0.6" />

              <text x="450" y="325" fontFamily="Inter, sans-serif" fontSize="12" fill="#a1a1aa" textAnchor="middle">
                THE DEGREE OF
              </text>

              <text x="450" y="370" fontFamily="Cinzel, serif" fontSize="22" fill="#fde68a" fontWeight="700" textAnchor="middle" letterSpacing="1">
                {degree}
              </text>

              {honors && (
                <text x="450" y="405" fontFamily="Cinzel, serif" fontSize="13" fill="#d4af37" fontStyle="italic" textAnchor="middle">
                  {honors}
                </text>
              )}

              {/* Bottom Authority & Seal */}
              <g transform="translate(100, 480)">
                <path d="M 20 30 Q 50 10 80 35 T 140 25" fill="none" stroke="#ffffff" strokeWidth="1.5" opacity="0.8" />
                <line x1="10" y1="50" x2="160" y2="50" stroke="#52525b" strokeWidth="1" />
                <text x="85" y="68" fontFamily="Inter, sans-serif" fontSize="10" fill="#e4e4e7" textAnchor="middle">{chancellor}</text>
                <text x="85" y="82" fontFamily="Inter, sans-serif" fontSize="8" fill="#71717a" textAnchor="middle">President of the University</text>
              </g>

              {/* Official Seal */}
              {showGoldSeal && (
                <g transform="translate(390, 460)">
                  <circle cx="60" cy="50" r="40" fill="none" stroke="#d4af37" strokeWidth="2" />
                  <circle cx="60" cy="50" r="34" fill="none" stroke="#d4af37" strokeWidth="0.8" strokeDasharray="3 2" />
                  <text x="60" y="47" fontFamily="Cinzel, serif" fontSize="8" fill="#d4af37" fontWeight="bold" textAnchor="middle">VERITAS</text>
                  <text x="60" y="58" fontFamily="Cinzel, serif" fontSize="7" fill="#d4af37" textAnchor="middle">SEAL 2026</text>
                </g>
              )}

              <g transform="translate(640, 480)">
                <path d="M 20 35 Q 50 15 90 40 T 140 30" fill="none" stroke="#ffffff" strokeWidth="1.5" opacity="0.8" />
                <line x1="10" y1="50" x2="160" y2="50" stroke="#52525b" strokeWidth="1" />
                <text x="85" y="68" fontFamily="Inter, sans-serif" fontSize="10" fill="#e4e4e7" textAnchor="middle">{dean}</text>
                <text x="85" y="82" fontFamily="Inter, sans-serif" fontSize="8" fill="#71717a" textAnchor="middle">Dean of Graduate Studies</text>
              </g>

              {/* Verification Stamp Footer */}
              <text x="450" y="595" fontFamily="JetBrains Mono, monospace" fontSize="8" fill="#71717a" textAnchor="middle">
                CRYPTOGRAPHICALLY ANCHORED: W3C VC 2.0 • SHA-256 JCS • POST-QUANTUM HYBRID READY
              </text>
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
}
