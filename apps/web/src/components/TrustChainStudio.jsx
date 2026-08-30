import React, { useState } from 'react';
import { 
  GitMerge, 
  ShieldCheck, 
  Building2, 
  Users, 
  Key, 
  CheckCircle2, 
  AlertCircle, 
  Copy, 
  Check, 
  Sparkles, 
  ArrowDown, 
  ArrowRight,
  Layers,
  FileCheck2
} from 'lucide-react';

function randomHex(len = 16) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export default function TrustChainStudio() {
  const [rootDid, setRootDid] = useState('did:key:z6MkuRootTrustAuthority99');
  const [intermediateDid, setIntermediateDid] = useState('did:key:z6MkuStateAccreditationBoard42');
  const [leafDid, setLeafDid] = useState('did:key:z6MkuQuantumResearchLab07');
  const [allowedType, setAllowedType] = useState('UniversityDegreeCredential');
  const [maxDepth, setMaxDepth] = useState(2);
  const [tokens, setTokens] = useState([]);
  const [verifyResult, setVerifyResult] = useState(null);
  const [copied, setCopied] = useState(false);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleIssueChain = () => {
    const ts = new Date().toISOString();
    const exp = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString();

    // Token 1: Root -> Intermediate
    const token1 = {
      id: `urn:uuid:del-${randomHex(8)}`,
      type: 'DelegationToken2026',
      issuer: rootDid,
      delegatee: intermediateDid,
      issuedAt: ts,
      expiresAt: exp,
      maxDepth: maxDepth,
      allowedTypes: [allowedType, 'AcademicAccreditation'],
      signature: 'z' + randomHex(32)
    };

    // Token 2: Intermediate -> Leaf
    const token2 = {
      id: `urn:uuid:del-${randomHex(8)}`,
      type: 'DelegationToken2026',
      issuer: intermediateDid,
      delegatee: leafDid,
      issuedAt: ts,
      expiresAt: exp,
      maxDepth: maxDepth - 1,
      allowedTypes: [allowedType],
      signature: 'z' + randomHex(32)
    };

    setTokens([token1, token2]);
    setVerifyResult(null);
  };

  const handleVerifyChain = (simulatedRoot) => {
    if (tokens.length === 0) return;

    const accreditedRoots = [simulatedRoot || rootDid];
    const isRootAccredited = accreditedRoots.includes(tokens[0].issuer);

    // Validate chain links: token[i].delegatee === token[i+1].issuer
    let chainValid = true;
    for (let i = 0; i < tokens.length - 1; i++) {
      if (tokens[i].delegatee !== tokens[i+1].issuer) {
        chainValid = false;
        break;
      }
    }

    const satisfiesDepth = tokens.length <= maxDepth;
    const finalIssuer = tokens[tokens.length - 1].delegatee;

    const result = {
      isValid: isRootAccredited && chainValid && satisfiesDepth,
      accreditedRoot: tokens[0].issuer,
      finalAuthorizedIssuer: finalIssuer,
      chainLength: tokens.length,
      maxAllowedDepth: maxDepth,
      allowedTypes: tokens[tokens.length - 1].allowedTypes,
      errors: []
    };

    if (!isRootAccredited) result.errors.push('Root issuer is not accredited in trust registry.');
    if (!chainValid) result.errors.push('Broken delegation token chain continuity.');
    if (!satisfiesDepth) result.errors.push('Delegation depth limit exceeded.');

    setVerifyResult(result);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <GitMerge className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Hierarchical Verifiable Trust Chain Studio</h1>
            <p className="text-sm text-gray-400">
              Multi-tier sovereign trust delegation tokens (Root $\to$ Accreditation Board $\to$ Department) with path depth & scope constraints.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Configuration */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
              <Building2 className="w-4 h-4 text-blue-400" />
              1. Hierarchy Topology Setup
            </h2>

            <div className="space-y-3 mb-4">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Tier 0: Root Trust Authority DID:</label>
                <input
                  type="text"
                  value={rootDid}
                  onChange={(e) => setRootDid(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-gray-950 border border-gray-800 text-xs text-cyan-300 font-mono"
                />
              </div>

              <div>
                <label className="text-xs text-gray-400 block mb-1">Tier 1: Intermediate Board DID:</label>
                <input
                  type="text"
                  value={intermediateDid}
                  onChange={(e) => setIntermediateDid(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-gray-950 border border-gray-800 text-xs text-indigo-300 font-mono"
                />
              </div>

              <div>
                <label className="text-xs text-gray-400 block mb-1">Tier 2: Leaf Issuer DID:</label>
                <input
                  type="text"
                  value={leafDid}
                  onChange={(e) => setLeafDid(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-gray-950 border border-gray-800 text-xs text-purple-300 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-2 pt-2">
                <div>
                  <label className="text-xs text-gray-400 block mb-1">Allowed VC Type:</label>
                  <input
                    type="text"
                    value={allowedType}
                    onChange={(e) => setAllowedType(e.target.value)}
                    className="w-full px-3 py-1.5 rounded-lg bg-gray-950 border border-gray-800 text-xs text-white"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400 block mb-1">Max Depth:</label>
                  <input
                    type="number"
                    value={maxDepth}
                    onChange={(e) => setMaxDepth(Number(e.target.value))}
                    className="w-full px-3 py-1.5 rounded-lg bg-gray-950 border border-gray-800 text-xs text-white font-mono"
                  />
                </div>
              </div>
            </div>

            <button
              onClick={handleIssueChain}
              className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-medium text-xs transition-all shadow-lg shadow-blue-500/20 flex items-center justify-center gap-2"
            >
              <Sparkles className="w-4 h-4" />
              Issue Verifiable Delegation Tokens
            </button>
          </div>
        </div>

        {/* Center: Visual Chain Diagram */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              2. Active Trust Chain Hierarchy
            </h2>

            <div className="space-y-4">
              {/* Root */}
              <div className="p-3.5 rounded-xl bg-gray-950 border border-cyan-500/40">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-bold text-cyan-400">Tier 0: Root Sovereign Authority</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 font-mono">Accredited</span>
                </div>
                <div className="text-[11px] font-mono text-gray-300 truncate">{rootDid}</div>
              </div>

              <div className="flex justify-center text-cyan-500">
                <ArrowDown className="w-5 h-5 animate-bounce" />
              </div>

              {/* Intermediate */}
              <div className="p-3.5 rounded-xl bg-gray-950 border border-indigo-500/40">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-bold text-indigo-400">Tier 1: Accreditation Board</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 font-mono">Delegation Token 1</span>
                </div>
                <div className="text-[11px] font-mono text-gray-300 truncate">{intermediateDid}</div>
              </div>

              <div className="flex justify-center text-indigo-500">
                <ArrowDown className="w-5 h-5 animate-bounce" />
              </div>

              {/* Leaf */}
              <div className="p-3.5 rounded-xl bg-gray-950 border border-purple-500/40">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-bold text-purple-400">Tier 2: Authorized Department</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 font-mono">Delegation Token 2</span>
                </div>
                <div className="text-[11px] font-mono text-gray-300 truncate">{leafDid}</div>
              </div>
            </div>

            {tokens.length > 0 && (
              <div className="mt-6 flex gap-3">
                <button
                  onClick={() => handleVerifyChain(rootDid)}
                  className="flex-1 py-2 px-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition-all shadow-lg shadow-emerald-500/20 flex items-center justify-center gap-1.5"
                >
                  <CheckCircle2 className="w-3.5 h-3.5" /> Verify Valid Chain
                </button>
                <button
                  onClick={() => handleVerifyChain('did:key:z6MkuUnknownAttacker999')}
                  className="flex-1 py-2 px-3 rounded-xl bg-rose-600/80 hover:bg-rose-600 text-white font-medium text-xs transition-all flex items-center justify-center gap-1.5"
                >
                  <AlertCircle className="w-3.5 h-3.5" /> Test Fake Root
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Right: Verification Output */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <FileCheck2 className="w-4 h-4 text-emerald-400" />
                3. Trust Chain Verification
              </h2>
              {verifyResult && (
                <button
                  onClick={() => copyToClipboard(verifyResult)}
                  className="p-1 rounded hover:bg-gray-800 text-gray-400 hover:text-white"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              )}
            </div>

            {verifyResult ? (
              <div className="space-y-4">
                <div className={`p-4 rounded-xl border ${
                  verifyResult.isValid
                    ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                    : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                }`}>
                  <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider mb-2">
                    {verifyResult.isValid ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertCircle className="w-4 h-4 text-rose-400" />}
                    {verifyResult.isValid ? 'Trust Chain Verified Successfully' : 'Trust Chain Verification Rejected'}
                  </div>

                  <div className="text-xs space-y-1.5 opacity-90">
                    <div><strong>Accredited Root:</strong> {verifyResult.accreditedRoot}</div>
                    <div><strong>Leaf Authorized:</strong> {verifyResult.finalAuthorizedIssuer}</div>
                    <div><strong>Chain Length:</strong> {verifyResult.chainLength} (Max: {verifyResult.maxAllowedDepth})</div>
                    <div><strong>Authorized Types:</strong> {verifyResult.allowedTypes.join(', ')}</div>
                  </div>

                  {verifyResult.errors.length > 0 && (
                    <div className="mt-3 pt-2 border-t border-rose-800/40 text-xs text-rose-300">
                      <strong>Rejection Reasons:</strong>
                      <ul className="list-disc list-inside mt-1">
                        {verifyResult.errors.map((err, i) => (
                          <li key={i}>{err}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                <pre className="p-3 rounded-lg bg-gray-950 border border-gray-800 text-[10px] font-mono text-gray-300 max-h-48 overflow-y-auto">
                  {JSON.stringify(tokens, null, 2)}
                </pre>
              </div>
            ) : (
              <div className="p-8 text-center text-xs text-gray-500 border border-dashed border-gray-800 rounded-xl">
                Issue delegation tokens to verify multi-tier trust resolution.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
