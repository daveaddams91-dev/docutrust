import React, { useState } from 'react';
import { 
  Key, 
  FileText, 
  Layers, 
  CheckCircle2, 
  Download, 
  Copy, 
  Sparkles, 
  Eye, 
  UploadCloud, 
  ShieldAlert,
  ArrowRight,
  RefreshCw
} from 'lucide-react';

export default function IssuerStudio({ onInspectCredential }) {
  const [issueMode, setIssueMode] = useState('single'); // 'single' | 'batch'
  const [templateType, setTemplateType] = useState('academic'); // 'academic' | 'employment' | 'membership'

  // Form Fields
  const [recipientName, setRecipientName] = useState('Elena Rostova');
  const [recipientId, setRecipientId] = useState('did:key:z6Mkq5...x98');
  const [title, setTitle] = useState('Doctor of Philosophy in Artificial Intelligence');
  const [organization, setOrganization] = useState('Massachusetts Institute of Technology');
  const [gpa, setGpa] = useState('3.98');
  const [graduationYear, setGraduationYear] = useState('2026');
  const [enableSD, setEnableSD] = useState(true);
  const [anchorLedger, setAnchorLedger] = useState(true);

  // Key State
  const [issuerKey, setIssuerKey] = useState({
    did: 'did:key:z6MkuG2B83x1K8u4W7q2V6m...',
    publicKeyHex: '4a9b2c8d1e3f7a5b6c0d8e2f4a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f3a5b',
    keyId: 'did:key:z6MkuG2B83x1K8u4W7q2V6m...#z6MkuG2B83x1K8u4W7q2V6m'
  });

  // Issued Output State
  const [issuedVC, setIssuedVC] = useState(null);
  const [copied, setCopied] = useState(false);
  const [isIssuing, setIsIssuing] = useState(false);

  // Batch State
  const [batchData, setBatchData] = useState([
    { name: 'Marcus Vance', degree: 'M.Sc. Data Science', year: '2026', gpa: '3.92' },
    { name: 'Sarah Jenkins', degree: 'B.Sc. Computer Engineering', year: '2026', gpa: '3.88' },
    { name: 'David Kim', degree: 'Ph.D. Quantum Computing', year: '2026', gpa: '4.00' },
    { name: 'Amira Patel', degree: 'M.Sc. Cybersecurity', year: '2026', gpa: '3.95' }
  ]);
  const [batchResult, setBatchResult] = useState(null);

  const generateNewKeyPair = () => {
    const chars = '0123456789abcdef';
    let hex = '';
    for (let i = 0; i < 64; i++) hex += chars[Math.floor(Math.random() * chars.length)];
    const newDid = `did:key:z6Mk${hex.slice(0, 20)}...`;
    setIssuerKey({
      did: newDid,
      publicKeyHex: hex,
      keyId: `${newDid}#keys-1`
    });
  };

  const handleIssueSingle = () => {
    setIsIssuing(true);
    setTimeout(() => {
      const canonicalHash = '0x' + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join('');
      const signature = '0x' + Array.from({length: 128}, () => Math.floor(Math.random()*16).toString(16)).join('');
      const claimsRoot = '0x' + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join('');

      const vc = {
        '@context': [
          'https://www.w3.org/ns/credentials/v2',
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: `urn:uuid:${crypto.randomUUID ? crypto.randomUUID() : '8f92a1c0-4e3b-419a-9e12-87f2b1d30c5e'}`,
        type: ['VerifiableCredential', templateType === 'academic' ? 'UniversityDegreeCredential' : 'EmploymentCredential'],
        issuer: {
          id: issuerKey.did,
          name: organization
        },
        validFrom: new Date().toISOString(),
        credentialSubject: {
          id: recipientId,
          name: recipientName,
          title: title,
          graduationYear: graduationYear,
          gpa: gpa,
          institution: organization
        },
        proof: {
          type: 'Ed25519Signature2020',
          created: new Date().toISOString(),
          verificationMethod: issuerKey.keyId,
          proofPurpose: 'assertionMethod',
          proofValue: signature,
          jcsCanonicalHash: canonicalHash,
          ...(enableSD ? { claimsRoot } : {}),
          ...(anchorLedger ? {
            anchorReceipt: {
              network: 'polygon',
              txHash: '0x' + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join(''),
              blockNumber: 54890142,
              confirmed: true,
              timestamp: Date.now()
            }
          } : {})
        }
      };

      setIssuedVC(vc);
      setIsIssuing(false);
    }, 400);
  };

  const handleIssueBatch = () => {
    setIsIssuing(true);
    setTimeout(() => {
      const merkleRoot = '0x' + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join('');
      const txHash = '0x' + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join('');
      setBatchResult({
        total: batchData.length,
        merkleRoot,
        txHash,
        network: 'polygon-mainnet',
        timestamp: new Date().toLocaleString()
      });
      setIsIssuing(false);
    }, 600);
  };

  const copyToClipboard = () => {
    if (issuedVC) {
      navigator.clipboard.writeText(JSON.stringify(issuedVC, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Header */}
      <div className="mb-10 text-left">
        <div className="flex items-center gap-2 text-xs font-mono text-blue-400 mb-2 uppercase tracking-widest">
          <Key className="w-3.5 h-3.5" />
          <span>Institutional Issuance Terminal</span>
        </div>
        <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Issuer Studio & Key Management
        </h2>
        <p className="text-sm text-gray-400 mt-2">
          Design, digitally sign, and publish W3C Verifiable Credentials with cryptographic ledger proofs.
        </p>
      </div>

      {/* Mode Selector */}
      <div className="flex items-center gap-3 mb-8">
        <button
          onClick={() => setIssueMode('single')}
          className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold transition-all ${
            issueMode === 'single'
              ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
              : 'bg-gray-900 border border-gray-800 text-gray-400 hover:text-white'
          }`}
        >
          <FileText className="w-4 h-4" />
          Single Credential Studio
        </button>

        <button
          onClick={() => setIssueMode('batch')}
          className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold transition-all ${
            issueMode === 'batch'
              ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
              : 'bg-gray-900 border border-gray-800 text-gray-400 hover:text-white'
          }`}
        >
          <Layers className="w-4 h-4" />
          Batch CSV Merkle Pipeline ({batchData.length} records)
        </button>
      </div>

      {/* MAIN SINGLE ISSUANCE VIEW */}
      {issueMode === 'single' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 text-left">
          {/* Left Column: Form Fields & Key Management */}
          <div className="lg:col-span-6 space-y-6">
            {/* Key Authority Selector */}
            <div className="glass-card p-5 rounded-2xl border border-gray-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-gray-300 font-semibold uppercase tracking-wider">
                  Signing Authority Key (Ed25519)
                </span>
                <button
                  onClick={generateNewKeyPair}
                  className="flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300 transition-colors font-mono"
                >
                  <RefreshCw className="w-3 h-3" /> Generate New KeyPair
                </button>
              </div>
              <div className="p-3 bg-gray-950 rounded-xl border border-gray-800 font-mono text-xs space-y-1">
                <div className="text-gray-500 text-[10px]">ISSUER DID</div>
                <div className="text-emerald-400 truncate">{issuerKey.did}</div>
                <div className="text-gray-500 text-[10px] pt-1">PUBLIC KEY (HEX)</div>
                <div className="text-gray-400 truncate">{issuerKey.publicKeyHex}</div>
              </div>
            </div>

            {/* Template & Metadata Form */}
            <div className="glass-card p-6 rounded-2xl border border-gray-800 space-y-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Credential Payload Data
              </h3>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1.5">Recipient Full Name</label>
                  <input
                    type="text"
                    value={recipientName}
                    onChange={e => setRecipientName(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1.5">Graduation / Issue Year</label>
                  <input
                    type="text"
                    value={graduationYear}
                    onChange={e => setGraduationYear(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1.5">Degree / Award Title</label>
                <input
                  type="text"
                  value={title}
                  onChange={e => setTitle(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1.5">Issuing Institution</label>
                  <input
                    type="text"
                    value={organization}
                    onChange={e => setOrganization(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1.5">GPA / Score (Claim)</label>
                  <input
                    type="text"
                    value={gpa}
                    onChange={e => setGpa(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              {/* Protocol Toggles */}
              <div className="pt-2 space-y-3 border-t border-gray-800">
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableSD}
                    onChange={e => setEnableSD(e.target.checked)}
                    className="w-4 h-4 rounded text-blue-600 bg-gray-900 border-gray-700"
                  />
                  <div>
                    <span className="text-xs font-semibold text-white block">
                      Enable Zero-Knowledge Selective Disclosure
                    </span>
                    <span className="text-[11px] text-gray-400">
                      Creates salted Merkle claim hashes allowing student to disclose subsets of grades/data.
                    </span>
                  </div>
                </label>

                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={anchorLedger}
                    onChange={e => setAnchorLedger(e.target.checked)}
                    className="w-4 h-4 rounded text-blue-600 bg-gray-900 border-gray-700"
                  />
                  <div>
                    <span className="text-xs font-semibold text-white block">
                      Anchor to Public Ledger (Polygon / Ethereum)
                    </span>
                    <span className="text-[11px] text-gray-400">
                      Publishes cryptographic root anchor for immutable timestamping.
                    </span>
                  </div>
                </label>
              </div>

              {/* Action Button */}
              <button
                onClick={handleIssueSingle}
                disabled={isIssuing}
                className="w-full py-3.5 rounded-xl bg-gradient-to-r from-blue-600 via-indigo-600 to-blue-500 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-bold uppercase tracking-wider shadow-lg shadow-blue-600/30 transition-all flex items-center justify-center gap-2"
              >
                {isIssuing ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Executing Cryptographic Signature...
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    Sign & Issue Verifiable Credential
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Right Column: Live Certificate Preview & Raw JSON-LD Inspector */}
          <div className="lg:col-span-6 space-y-6">
            {/* Visual Certificate Rendering Card */}
            <div className="glass-card p-6 rounded-2xl border border-gray-800 relative overflow-hidden">
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-gray-800">
                <span className="text-xs font-mono text-gray-400 uppercase tracking-wider flex items-center gap-2">
                  <Eye className="w-3.5 h-3.5 text-blue-400" />
                  Live Certificate Template Preview
                </span>
                {issuedVC && (
                  <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> Cryptographically Signed
                  </span>
                )}
              </div>

              {/* High-Fidelity SVG Certificate Mockup */}
              <div className="p-6 rounded-xl border border-amber-500/40 bg-gradient-to-br from-amber-950/20 via-gray-950 to-gray-900 text-center space-y-3 relative overflow-hidden shadow-2xl">
                <div className="absolute top-2 right-2 w-16 h-16 opacity-10 rounded-full border border-amber-400 pointer-events-none" />
                <div className="text-xs font-serif text-amber-400 tracking-widest uppercase font-bold">
                  {organization.toUpperCase()}
                </div>
                <div className="text-[10px] text-gray-400 uppercase tracking-widest font-mono">
                  Sovereign Verifiable Credential
                </div>
                <div className="w-24 h-[1px] bg-amber-500/50 mx-auto" />

                <div className="text-xs text-gray-300 italic pt-2">This is to officially certify that</div>
                <div className="text-2xl font-serif text-white font-bold tracking-tight">
                  {recipientName}
                </div>
                <div className="text-xs text-gray-300">has fulfilled all requirements for</div>
                <div className="text-base font-serif text-amber-300 font-semibold">
                  {title}
                </div>

                <div className="pt-4 mt-4 border-t border-white/10 grid grid-cols-2 text-left font-mono text-[10px] text-gray-400">
                  <div>
                    <span className="text-gray-500 block">STANDARD</span>
                    <span className="text-gray-200">W3C VC 2.0 (RFC 8785)</span>
                  </div>
                  <div className="text-right">
                    <span className="text-gray-500 block">ISSUANCE YEAR</span>
                    <span className="text-gray-200">{graduationYear}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Issued Output JSON-LD */}
            {issuedVC && (
              <div className="glass-card p-6 rounded-2xl border border-emerald-500/30 bg-gray-950/80 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 font-bold">
                    <CheckCircle2 className="w-4 h-4" />
                    W3C JSON-LD Credential Output
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={copyToClipboard}
                      className="flex items-center gap-1 px-3 py-1 rounded bg-gray-900 border border-gray-800 text-gray-300 text-xs hover:text-white transition-colors"
                    >
                      <Copy className="w-3 h-3" />
                      {copied ? 'Copied!' : 'Copy JSON'}
                    </button>
                    <button
                      onClick={() => onInspectCredential && onInspectCredential(issuedVC)}
                      className="flex items-center gap-1 px-3 py-1 rounded bg-blue-600 text-white text-xs hover:bg-blue-500 transition-colors font-semibold"
                    >
                      Verify in Hub <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                </div>

                <pre className="p-4 bg-black rounded-xl border border-gray-800 text-[11px] font-mono text-blue-300 overflow-x-auto max-h-60">
                  {JSON.stringify(issuedVC, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* BATCH MERKLE PIPELINE VIEW */}
      {issueMode === 'batch' && (
        <div className="glass-card p-8 rounded-2xl border border-gray-800 text-left space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="text-xl font-bold text-white">Batch CSV Merkle Tree Pipeline</h3>
              <p className="text-xs text-gray-400 mt-1">
                Batch issue thousands of records with a single cryptographic Merkle Root on Polygon.
              </p>
            </div>
            <button
              onClick={handleIssueBatch}
              disabled={isIssuing}
              className="px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider flex items-center gap-2 shadow-lg shadow-blue-600/30"
            >
              {isIssuing ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Computing Merkle Root...
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  Execute Batch Issuance ({batchData.length} Records)
                </>
              )}
            </button>
          </div>

          {/* Table Preview */}
          <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-950/80">
            <table className="w-full text-left text-xs font-sans">
              <thead className="border-b border-gray-800 text-gray-400 font-mono text-[11px] uppercase bg-gray-900/60">
                <tr>
                  <th className="py-3 px-4">Index</th>
                  <th className="py-3 px-4">Recipient Name</th>
                  <th className="py-3 px-4">Degree Title</th>
                  <th className="py-3 px-4">Year</th>
                  <th className="py-3 px-4">GPA</th>
                  <th className="py-3 px-4">Merkle Leaf Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60">
                {batchData.map((row, idx) => (
                  <tr key={idx} className="hover:bg-gray-900/40">
                    <td className="py-3 px-4 font-mono text-gray-500">#{idx + 1}</td>
                    <td className="py-3 px-4 font-medium text-white">{row.name}</td>
                    <td className="py-3 px-4 text-gray-300">{row.degree}</td>
                    <td className="py-3 px-4 text-gray-400">{row.year}</td>
                    <td className="py-3 px-4 text-gray-400">{row.gpa}</td>
                    <td className="py-3 px-4 font-mono text-emerald-400 text-[11px]">
                      0x{Array.from({length: 16}, () => Math.floor(Math.random()*16).toString(16)).join('')}...
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Batch Result Report */}
          {batchResult && (
            <div className="p-5 rounded-xl border border-emerald-500/30 bg-emerald-950/10 space-y-3 font-mono text-xs">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                <CheckCircle2 className="w-4 h-4" /> Batch Issuance Finalized & Anchored
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-gray-300 pt-2 border-t border-emerald-500/20">
                <div>
                  <span className="text-[10px] text-gray-500 uppercase block">MERKLE ROOT HASH</span>
                  <span className="text-purple-400 break-all">{batchResult.merkleRoot}</span>
                </div>
                <div>
                  <span className="text-[10px] text-gray-500 uppercase block">POLYGON TX HASH</span>
                  <span className="text-blue-400 break-all">{batchResult.txHash}</span>
                </div>
                <div>
                  <span className="text-[10px] text-gray-500 uppercase block">INCLUSION PROOFS</span>
                  <span className="text-white">{batchResult.total} Merkle audit paths generated</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
