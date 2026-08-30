import React, { useState } from 'react';
import { 
  Binary, 
  Search, 
  Plus, 
  ShieldCheck, 
  CheckCircle2, 
  AlertCircle, 
  Code2, 
  Copy, 
  Check, 
  Layers, 
  Database, 
  Sparkles,
  ArrowRight,
  Shield
} from 'lucide-react';

export default function KeyTransparencyStudio() {
  const [entries, setEntries] = useState([
    { key: 'did:key:alice_corporate_root', value: '0x8f2d5e7a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e', label: 'Active Corporate Identity Root' },
    { key: 'did:key:bob_accredited_auditor', value: '0x3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d', label: 'Valid Accreditation Cert' },
    { key: 'did:key:revoked_device_certificate_09', value: '0x0000000000000000000000000000000000000000000000000000000000000000', label: 'Revoked Leaf Status' }
  ]);

  const [newKey, setNewKey] = useState('');
  const [newVal, setNewVal] = useState('');
  const [searchKey, setSearchKey] = useState('did:key:alice_corporate_root');
  const [proofOutput, setProofOutput] = useState(null);
  const [auditResult, setAuditResult] = useState(null);
  const [solidityCode, setSolidityCode] = useState('');
  const [activeSubTab, setActiveSubTab] = useState('explorer'); // 'explorer' | 'solidity'
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleCopy = (text) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleAddEntry = () => {
    if (!newKey || !newVal) return;
    setEntries(prev => [...prev.filter(e => e.key !== newKey), { key: newKey, value: newVal, label: 'Custom Entry' }]);
    setNewKey('');
    setNewVal('');
  };

  const handleGenerateProof = async (targetKey) => {
    setLoading(true);
    setAuditResult(null);
    try {
      const entryMap = {};
      entries.forEach(e => {
        entryMap[e.key] = e.value;
      });

      const res = await fetch('/api/v1/smt/prove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          key: targetKey || searchKey,
          entries: entryMap
        })
      });

      if (!res.ok) throw new Error('Failed to generate proof');
      const data = await res.json();
      setProofOutput(data);
    } catch (err) {
      console.error(err);
      alert('Error generating SMT proof: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyProof = async () => {
    if (!proofOutput) return;
    setLoading(true);
    try {
      const res = await fetch('/api/v1/smt/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          proof: proofOutput.proof,
          root: proofOutput.root
        })
      });

      const data = await res.json();
      setAuditResult(data);
    } catch (err) {
      console.error(err);
      alert('Proof audit error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleExportSolidity = async () => {
    try {
      const res = await fetch('/api/v1/solidity/export-smt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contractName: 'DocuTrustSMTVerifier'
        })
      });

      const data = await res.json();
      setSolidityCode(data.solidityCode);
      setActiveSubTab('solidity');
    } catch (err) {
      console.error(err);
      alert('Error generating Solidity contract: ' + err.message);
    }
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="border-b border-gray-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-xl text-cyan-400">
            <Binary className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              Sparse Merkle Tree (SMT) Key Transparency Ledger
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-mono">
                256-Bit Cryptographic Ledger
              </span>
            </h1>
            <p className="text-sm text-gray-400 mt-1">
              Verify continuous key transparency, credential revocations, and decentralized identity state with logarithmic 256-depth inclusion and non-membership proofs.
            </p>
          </div>
        </div>

        {/* Sub Navigation */}
        <div className="flex items-center gap-2 mt-6">
          <button
            onClick={() => setActiveSubTab('explorer')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
              activeSubTab === 'explorer'
                ? 'bg-cyan-600/20 text-cyan-300 border border-cyan-500/40'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            Ledger & Proof Explorer
          </button>
          <button
            onClick={handleExportSolidity}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
              activeSubTab === 'solidity'
                ? 'bg-cyan-600/20 text-cyan-300 border border-cyan-500/40'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            Solidity SMT Verifier Export
          </button>
        </div>
      </div>

      {activeSubTab === 'explorer' ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* Left Column: Key-Value State Ledger */}
          <div className="lg:col-span-6 space-y-6">
            <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                  <Database className="w-4 h-4 text-cyan-400" />
                  Key Transparency Ledger Entries ({entries.length})
                </h2>
              </div>

              <div className="space-y-2.5">
                {entries.map((item, idx) => (
                  <div 
                    key={idx}
                    onClick={() => { setSearchKey(item.key); handleGenerateProof(item.key); }}
                    className="p-3 bg-gray-950/60 border border-gray-800/80 rounded-lg cursor-pointer hover:border-cyan-500/50 transition-all"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-cyan-300 font-mono">{item.key}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400">{item.label}</span>
                    </div>
                    <div className="mt-1 text-[11px] font-mono text-gray-400 truncate">
                      <span className="text-gray-500">Value:</span> {item.value}
                    </div>
                  </div>
                ))}
              </div>

              {/* Add New Key */}
              <div className="pt-2 border-t border-gray-800/80 space-y-2">
                <span className="text-xs font-semibold text-gray-300">Add or Update Leaf</span>
                <input
                  type="text"
                  placeholder="Key (e.g. did:key:new_holder)"
                  value={newKey}
                  onChange={(e) => setNewKey(e.target.value)}
                  className="w-full text-xs font-mono bg-gray-950 border border-gray-800 rounded px-3 py-2 text-gray-200 focus:outline-none focus:border-cyan-500"
                />
                <input
                  type="text"
                  placeholder="Value hex (e.g. 0xabcdef...)"
                  value={newVal}
                  onChange={(e) => setNewVal(e.target.value)}
                  className="w-full text-xs font-mono bg-gray-950 border border-gray-800 rounded px-3 py-2 text-gray-200 focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={handleAddEntry}
                  className="w-full py-2 bg-gray-800 hover:bg-gray-700 text-cyan-300 text-xs font-medium rounded flex items-center justify-center gap-1.5 transition-all"
                >
                  <Plus className="w-3.5 h-3.5" /> Set SMT Leaf
                </button>
              </div>
            </div>

            {/* Proof Generator Card */}
            <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 space-y-4">
              <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                <Search className="w-4 h-4 text-blue-400" />
                Query SMT Audit Proof
              </h2>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={searchKey}
                  onChange={(e) => setSearchKey(e.target.value)}
                  placeholder="Enter key to prove (e.g. did:key:alice...)"
                  className="flex-1 text-xs font-mono bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-gray-200 focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={() => handleGenerateProof(searchKey)}
                  disabled={loading}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 transition-all disabled:opacity-50"
                >
                  <Search className="w-3.5 h-3.5" /> Prove
                </button>
              </div>
            </div>
          </div>

          {/* Right Column: Proof Verification & Inspection */}
          <div className="lg:col-span-6 space-y-6">
            <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  SMT Audit Proof ({proofOutput ? (proofOutput.exists ? 'Inclusion Proof' : 'Non-Membership Proof') : 'Awaiting Query'})
                </h2>
                {proofOutput && (
                  <button
                    onClick={() => handleCopy(proofOutput)}
                    className="flex items-center gap-1 text-xs text-gray-400 hover:text-white transition-colors"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                )}
              </div>

              {proofOutput ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="p-2.5 bg-gray-950/60 rounded border border-gray-800">
                      <span className="text-gray-500 text-[10px] block">Tree Root Hash:</span>
                      <span className="font-mono text-cyan-400 truncate block mt-0.5">{proofOutput.root}</span>
                    </div>
                    <div className="p-2.5 bg-gray-950/60 rounded border border-gray-800">
                      <span className="text-gray-500 text-[10px] block">Membership Status:</span>
                      <span className={`font-mono block mt-0.5 ${proofOutput.exists ? 'text-emerald-400' : 'text-amber-400'}`}>
                        {proofOutput.exists ? 'Key Present in SMT' : 'Non-Existent (Non-Membership)'}
                      </span>
                    </div>
                  </div>

                  <div className="p-3 bg-gray-950/90 rounded-lg border border-gray-800 font-mono text-[11px] text-gray-300 max-h-56 overflow-y-auto">
                    <pre>{JSON.stringify(proofOutput.proof, null, 2)}</pre>
                  </div>

                  <button
                    onClick={handleVerifyProof}
                    disabled={loading}
                    className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded-lg text-xs flex items-center justify-center gap-1.5 transition-all shadow-md shadow-emerald-900/20 disabled:opacity-50"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    Verify SMT Inclusion / Non-Membership Proof
                  </button>
                </div>
              ) : (
                <div className="p-8 border border-dashed border-gray-800 rounded-lg text-center text-gray-500 text-xs">
                  Select a ledger key or click Prove to generate a 256-bit SMT audit path.
                </div>
              )}
            </div>

            {/* Verification Result */}
            {auditResult && (
              <div className={`p-4 rounded-xl border ${
                auditResult.valid 
                  ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300' 
                  : 'bg-rose-950/20 border-rose-500/40 text-rose-300'
              }`}>
                <div className="flex items-center gap-2">
                  {auditResult.valid ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <AlertCircle className="w-5 h-5 text-rose-400" />
                  )}
                  <span className="font-semibold text-sm">
                    {auditResult.valid ? 'SMT Cryptographic Audit Passed' : 'SMT Proof Verification Failed'}
                  </span>
                </div>
                <p className="text-xs mt-2 opacity-90">
                  {auditResult.valid 
                    ? `Proof for ${auditResult.key?.slice(0, 16)}... mathematically reconstructed the root hash (${auditResult.root?.slice(0, 16)}...) across 256 tree depths.`
                    : 'The reconstructed root hash did not match the expected state anchor.'}
                </p>
              </div>
            )}
          </div>
        </div>
      ) : (
        /* Solidity Export Tab */
        <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              Production Solidity Smart Contract (DocuTrustSMTVerifier.sol)
            </h2>
            <button
              onClick={() => handleCopy(solidityCode)}
              className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Copy Contract'}
            </button>
          </div>
          <div className="p-4 bg-gray-950 rounded-lg border border-gray-800 font-mono text-xs text-gray-300 max-h-[500px] overflow-y-auto">
            <pre>{solidityCode}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
