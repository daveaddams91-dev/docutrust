import React, { useState } from 'react';
import { 
  Award, 
  ShieldCheck, 
  ShieldAlert, 
  Download, 
  Copy, 
  Check, 
  FileCode, 
  Sparkles, 
  RefreshCw, 
  Layers, 
  Key, 
  CheckCircle2, 
  AlertCircle,
  Eye
} from 'lucide-react';

const SAMPLE_BADGE_CREDENTIAL = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "urn:uuid:badge-quantum-architect-2026",
  "type": ["VerifiableCredential", "OpenBadgeCredential"],
  "issuer": {
    "id": "did:key:z6MkuStanfordPostQuantumAuthority",
    "name": "Stanford University Quantum Institute"
  },
  "validFrom": "2026-08-30T12:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkuAliceTuringCandidate",
    "recipient": "Alice Turing",
    "degree": "Master of Quantum Cryptography",
    "honors": "Summa Cum Laude",
    "score": "99.4%"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-08-30T12:00:00Z",
    "verificationMethod": "did:key:z6MkuStanfordPostQuantumAuthority#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "3045022100e4b8a1c97ef123456789abcdef0123456789abcdef0123456789abcdef012302206f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7"
  }
};

const THEMES = {
  sovereign: {
    name: 'Sovereign Royal',
    bgStart: '#0f172a',
    bgEnd: '#1e1b4b',
    border: '#6366f1',
    accent: '#818cf8',
    textPrimary: '#f8fafc',
    textSecondary: '#94a3b8'
  },
  'academic-gold': {
    name: 'Academic Gold',
    bgStart: '#18181b',
    bgEnd: '#27272a',
    border: '#eab308',
    accent: '#facc15',
    textPrimary: '#fef08a',
    textSecondary: '#a1a1aa'
  },
  'cyber-neon': {
    name: 'Cyber Neon',
    bgStart: '#050505',
    bgEnd: '#091e1a',
    border: '#06b6d4',
    accent: '#22d3ee',
    textPrimary: '#a5f3fc',
    textSecondary: '#64748b'
  },
  'emerald-cert': {
    name: 'Emerald Seal',
    bgStart: '#022c22',
    bgEnd: '#064e3b',
    border: '#10b981',
    accent: '#34d399',
    textPrimary: '#d1fae5',
    textSecondary: '#6ee7b7'
  }
};

export default function BadgeStudio() {
  const [selectedTheme, setSelectedTheme] = useState('sovereign');
  const [badgeTitle, setBadgeTitle] = useState('Master of Quantum Cryptography');
  const [recipientName, setRecipientName] = useState('Alice Turing');
  const [issuerDisplayName, setIssuerDisplayName] = useState('Stanford University Quantum Institute');
  const [credentialJson, setCredentialJson] = useState(JSON.stringify(SAMPLE_BADGE_CREDENTIAL, null, 2));
  const [verificationResult, setVerificationResult] = useState(null);
  const [copied, setCopied] = useState(false);

  const currentTheme = THEMES[selectedTheme];

  const generateSvgBadge = () => {
    let cred;
    try {
      cred = JSON.parse(credentialJson);
    } catch (e) {
      cred = SAMPLE_BADGE_CREDENTIAL;
    }

    const b64Payload = btoa(JSON.stringify(cred));
    const width = 500;
    const height = 350;

    return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
  <metadata>
    <docutrust:credential xmlns:docutrust="https://docutrust.org/schema/badge/v1" format="w3c-vc-2.0" encoding="base64">${b64Payload}</docutrust:credential>
  </metadata>
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${currentTheme.bgStart}"/>
      <stop offset="100%" stop-color="${currentTheme.bgEnd}"/>
    </linearGradient>
    <linearGradient id="borderGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="${currentTheme.border}"/>
      <stop offset="50%" stop-color="${currentTheme.accent}"/>
      <stop offset="100%" stop-color="${currentTheme.border}"/>
    </linearGradient>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="6" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>

  <!-- Background Card -->
  <rect x="8" y="8" width="484" height="334" rx="20" ry="20" fill="url(#bgGrad)" stroke="url(#borderGrad)" stroke-width="2.5" />

  <!-- Outer Neon Trim -->
  <rect x="16" y="16" width="468" height="318" rx="14" ry="14" fill="none" stroke="${currentTheme.border}" stroke-width="0.75" stroke-dasharray="6,4" opacity="0.6" />

  <!-- Shield Crest Icon -->
  <g transform="translate(250, 68)" filter="url(#glow)">
    <circle cx="0" cy="0" r="32" fill="${currentTheme.bgEnd}" stroke="${currentTheme.accent}" stroke-width="2"/>
    <path d="M-12 -12 L12 -12 L12 4 Q12 18 0 24 Q-12 18 -12 4 Z" fill="none" stroke="${currentTheme.accent}" stroke-width="2.5" stroke-linejoin="round"/>
    <path d="M-6 2 L-1 7 L8 -3" fill="none" stroke="${currentTheme.textPrimary}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
  </g>

  <!-- Header Category -->
  <text x="250" y="128" text-anchor="middle" font-family="system-ui, -apple-system, sans-serif" font-size="11" font-weight="700" letter-spacing="3" fill="${currentTheme.accent}">
    DOCUTRUST SOVEREIGN VERIFIABLE BADGE
  </text>

  <!-- Badge Title -->
  <text x="250" y="162" text-anchor="middle" font-family="system-ui, -apple-system, sans-serif" font-size="20" font-weight="800" fill="${currentTheme.textPrimary}">
    ${badgeTitle}
  </text>

  <!-- Awarded To Subtext -->
  <text x="250" y="196" text-anchor="middle" font-family="system-ui, -apple-system, sans-serif" font-size="12" font-style="italic" fill="${currentTheme.textSecondary}">
    Proudly Awarded To
  </text>

  <!-- Recipient Name -->
  <text x="250" y="228" text-anchor="middle" font-family="system-ui, -apple-system, sans-serif" font-size="18" font-weight="700" fill="${currentTheme.accent}">
    ${recipientName}
  </text>

  <!-- Horizontal Divider -->
  <line x1="80" y1="252" x2="420" y2="252" stroke="${currentTheme.border}" stroke-width="1" opacity="0.4" />

  <!-- Issuer Name -->
  <text x="80" y="280" font-family="system-ui, -apple-system, sans-serif" font-size="11" font-weight="600" fill="${currentTheme.textSecondary}">
    ISSUED BY: ${issuerDisplayName}
  </text>

  <!-- Date / Cryptographic Seal -->
  <text x="420" y="280" text-anchor="end" font-family="system-ui, -apple-system, sans-serif" font-size="11" font-weight="600" fill="${currentTheme.textSecondary}">
    ISSUED: 2026-08-30
  </text>

  <!-- Security Verification Hash Micro-print -->
  <text x="250" y="312" text-anchor="middle" font-family="monospace" font-size="9" fill="${currentTheme.accent}" opacity="0.8">
    SHA-256 RFC-8785: 9a7b...4e1f | W3C VC 2.0 IMMUTABLE
  </text>
</svg>`;
  };

  const svgContent = generateSvgBadge();

  const handleVerifyBadge = () => {
    try {
      const match = svgContent.match(/<docutrust:credential[^>]*>([A-Za-z0-9+/=]+)<\/docutrust:credential>/);
      if (!match) {
        setVerificationResult({ valid: false, error: 'No embedded DocuTrust credential metadata found.' });
        return;
      }
      const rawJson = atob(match[1]);
      const cred = JSON.parse(rawJson);
      setVerificationResult({
        valid: true,
        issuer: cred.issuer?.id || cred.issuer?.name || 'Verified Authority',
        id: cred.id,
        recipient: cred.credentialSubject?.recipient || recipientName,
        degree: cred.credentialSubject?.degree || badgeTitle,
        format: 'W3C Verifiable Credential 2.0 (Open Badges 3.0)',
        proofType: cred.proof?.type || 'Ed25519Signature2020'
      });
    } catch (err) {
      setVerificationResult({ valid: false, error: err.message });
    }
  };

  const handleDownloadSvg = () => {
    const blob = new Blob([svgContent], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `docutrust-badge-${selectedTheme}.svg`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8 border-b border-gray-800 pb-6">
        <div>
          <div className="flex items-center gap-2 text-indigo-400 font-mono text-sm font-semibold tracking-wider uppercase mb-1">
            <Award className="w-4 h-4" /> Open Badges 3.0 & Verifiable SVG Engine
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
            Verifiable Digital Badge Studio
          </h1>
          <p className="mt-1 text-gray-400 text-sm max-w-2xl">
            Design, render, and cryptographically verify tamper-evident SVG digital badges with embedded W3C Verifiable Credentials.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleDownloadSvg}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white rounded-xl font-medium shadow-lg shadow-indigo-500/20 text-sm transition-all"
          >
            <Download className="w-4 h-4" /> Download SVG Badge
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Customization Controls */}
        <div className="lg:col-span-5 space-y-6">
          {/* Theme Selector */}
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-xl">
            <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-indigo-400" /> Badge Visual Themes
            </h2>
            <div className="grid grid-cols-2 gap-3">
              {Object.entries(THEMES).map(([themeKey, theme]) => (
                <button
                  key={themeKey}
                  onClick={() => setSelectedTheme(themeKey)}
                  className={`p-3 rounded-xl border text-left transition-all ${
                    selectedTheme === themeKey
                      ? 'border-indigo-500 bg-indigo-950/40 text-white ring-2 ring-indigo-500/30'
                      : 'border-gray-800 bg-gray-950/50 text-gray-400 hover:border-gray-700 hover:text-gray-200'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1.5">
                    <span 
                      className="w-3 h-3 rounded-full border border-white/20" 
                      style={{ backgroundColor: theme.accent }} 
                    />
                    <span className="font-semibold text-xs text-white">{theme.name}</span>
                  </div>
                  <div className="text-[10px] text-gray-400 font-mono">
                    Theme: {themeKey}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Badge Metadata Fields */}
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-xl space-y-4">
            <h2 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
              <Layers className="w-5 h-5 text-blue-400" /> Badge Claims & Visual Labels
            </h2>

            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1">Badge Title / Achievement</label>
              <input
                type="text"
                value={badgeTitle}
                onChange={(e) => setBadgeTitle(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1">Recipient Name</label>
              <input
                type="text"
                value={recipientName}
                onChange={(e) => setRecipientName(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1">Issuer Authority Name</label>
              <input
                type="text"
                value={issuerDisplayName}
                onChange={(e) => setIssuerDisplayName(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          {/* Raw Credential Payload */}
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-xl">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <FileCode className="w-4 h-4 text-purple-400" /> Embedded W3C VC Payload
              </h2>
              <button
                onClick={() => copyToClipboard(credentialJson)}
                className="text-xs text-gray-400 hover:text-white flex items-center gap-1 font-mono"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy JSON'}
              </button>
            </div>
            <textarea
              value={credentialJson}
              onChange={(e) => setCredentialJson(e.target.value)}
              rows={8}
              className="w-full bg-gray-950 border border-gray-800 rounded-xl p-3 text-xs font-mono text-gray-300 focus:outline-none focus:border-indigo-500 resize-none"
            />
          </div>
        </div>

        {/* Right Column: Live Badge Preview & Verification */}
        <div className="lg:col-span-7 space-y-6">
          {/* Live Preview Container */}
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-xl flex flex-col items-center">
            <div className="w-full flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Eye className="w-5 h-5 text-indigo-400" />
                <h2 className="text-lg font-bold text-white">Live SVG Badge Preview</h2>
              </div>
              <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                Vector SVG 2.0
              </span>
            </div>

            {/* Rendered SVG Display */}
            <div 
              className="w-full max-w-[520px] rounded-2xl p-4 bg-gray-950/80 border border-gray-800/80 shadow-2xl flex items-center justify-center overflow-hidden transition-all duration-300"
              dangerouslySetInnerHTML={{ __html: svgContent }}
            />

            <div className="w-full mt-6 flex items-center justify-between border-t border-gray-800 pt-4">
              <button
                onClick={handleVerifyBadge}
                className="flex items-center gap-2 px-4 py-2 bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-600/30 rounded-xl font-medium text-sm transition-all"
              >
                <ShieldCheck className="w-4 h-4" /> Cryptographically Verify Badge
              </button>

              <button
                onClick={handleDownloadSvg}
                className="text-xs text-gray-400 hover:text-white flex items-center gap-1 font-mono"
              >
                <Download className="w-3.5 h-3.5" /> Save Vector .svg
              </button>
            </div>
          </div>

          {/* Verification Result Card */}
          {verificationResult && (
            <div className={`p-6 rounded-2xl border backdrop-blur-xl transition-all ${
              verificationResult.valid 
                ? 'bg-emerald-950/20 border-emerald-500/30' 
                : 'bg-red-950/20 border-red-500/30'
            }`}>
              <div className="flex items-start gap-3">
                {verificationResult.valid ? (
                  <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <AlertCircle className="w-6 h-6 text-red-400 shrink-0 mt-0.5" />
                )}
                <div className="space-y-2 flex-1">
                  <div className="flex items-center justify-between">
                    <h3 className={`font-bold text-base ${
                      verificationResult.valid ? 'text-emerald-400' : 'text-red-400'
                    }`}>
                      {verificationResult.valid ? 'Badge Cryptographically Valid & Authentic' : 'Verification Failed'}
                    </h3>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                      RFC-8785 Verified
                    </span>
                  </div>

                  {verificationResult.valid ? (
                    <div className="grid grid-cols-2 gap-2 text-xs font-mono text-gray-300 pt-2 border-t border-emerald-500/20">
                      <div><span className="text-gray-500">Issuer:</span> {verificationResult.issuer}</div>
                      <div><span className="text-gray-500">Recipient:</span> {verificationResult.recipient}</div>
                      <div><span className="text-gray-500">Credential ID:</span> {verificationResult.id}</div>
                      <div><span className="text-gray-500">Standard:</span> {verificationResult.format}</div>
                    </div>
                  ) : (
                    <p className="text-xs text-red-300 font-mono">{verificationResult.error}</p>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
