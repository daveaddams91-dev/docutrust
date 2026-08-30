import React, { useState } from 'react';
import {
  Layers,
  CheckCircle2,
  XCircle,
  FileCode,
  Sparkles,
  GitBranch,
  Key,
  ShieldCheck,
  Zap,
  Lock,
  Search,
  Sliders,
  RefreshCw,
  Copy,
  Check,
  AlertTriangle
} from 'lucide-react';

export default function SovereignStudio() {
  const [activeSubTab, setActiveSubTab] = useState('statuslist');
  const [copied, setCopied] = useState(false);

  // --- Status List 2024 State ---
  const [statusListSize, setStatusListSize] = useState(1000);
  const [statusBitSize, setStatusBitSize] = useState(2); // 1, 2, 4, 8
  const [statusPurpose, setStatusPurpose] = useState('revocation');
  const [testIndex, setTestIndex] = useState(15);
  const [statusMap, setStatusMap] = useState({ 15: 1, 42: 2, 99: 3 });
  const [statusListResult, setStatusListResult] = useState(null);

  // --- Presentation Exchange 2.0 State ---
  const [peDefinitionId, setPeDefinitionId] = useState('kyc_degree_verification_v2');
  const [peRequiredDegree, setPeRequiredDegree] = useState('Cybersecurity');
  const [peMinGpa, setPeMinGpa] = useState(3.5);
  const [peEvalResult, setPeEvalResult] = useState(null);

  // --- Accumulator Non-Membership State ---
  const [accMembers, setAccMembers] = useState([
    'did:key:z6Mku1111111111111111111111111111111111111111111',
    'did:key:z6Mku2222222222222222222222222222222222222222222',
    'did:key:z6Mku3333333333333333333333333333333333333333333'
  ]);
  const [newAccMember, setNewAccMember] = useState('');
  const [nonMemberQuery, setNonMemberQuery] = useState('did:key:z6Mku9999999999999999999999999999999999999999999');
  const [accWitnessResult, setAccWitnessResult] = useState(null);

  // --- Recursive ZK Graph State ---
  const [graphOperator, setGraphOperator] = useState('AND');
  const [graphThreshold, setGraphThreshold] = useState(2);
  const [graphLeaves, setGraphLeaves] = useState([
    { id: 'leaf_age', type: 'ZKAgePredicateProof2026', satisfied: true, desc: 'Age >= 21' },
    { id: 'leaf_clearance', type: 'ZKSetMembershipProof2026', satisfied: true, desc: 'Role IN [ADMIN, AUDITOR]' },
    { id: 'leaf_sanctions', type: 'ZKSetNonMembershipProof2026', satisfied: true, desc: 'Not on Sanctions List' }
  ]);
  const [graphEvalResult, setGraphEvalResult] = useState(null);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Simulate Bitstring Status List 2024
  const handleGenerateStatusList = () => {
    const totalBits = statusListSize * statusBitSize;
    const byteLen = Math.ceil(totalBits / 8);
    const mockEncoded = 'uH4sIC' + btoa(String.fromCharCode(...new Uint8Array(32))).replace(/=/g, '');
    const currentStatus = statusMap[testIndex] || 0;
    
    let statusLabel = 'VALID (Active)';
    if (statusBitSize === 1) {
      statusLabel = currentStatus === 1 ? 'REVOKED' : 'VALID';
    } else {
      if (currentStatus === 1) statusLabel = 'REVOKED';
      else if (currentStatus === 2) statusLabel = 'SUSPENDED';
      else if (currentStatus === 3) statusLabel = 'UNDER REVIEW';
    }

    setStatusListResult({
      statusListCredential: {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://w3id.org/vc/status-list/v1"
        ],
        "id": `urn:uuid:status-list-${Date.now()}`,
        "type": ["VerifiableCredential", "StatusList2024Credential"],
        "issuer": "did:key:z6MkuDocuTrustRootAuthority2026",
        "validFrom": new Date().toISOString(),
        "credentialSubject": {
          "id": `urn:uuid:status-list-${Date.now()}#list`,
          "type": "StatusList2024",
          "statusPurpose": statusPurpose,
          "statusSize": statusBitSize,
          "encodedList": mockEncoded
        }
      },
      metrics: {
        totalBits,
        byteLength: byteLen,
        compressionRatio: '94.2%',
        testIndex,
        statusCode: currentStatus,
        statusLabel
      }
    });
  };

  // Simulate DIF Presentation Exchange 2.0
  const handleEvaluatePE = () => {
    const candidateVC = {
      type: ["VerifiableCredential", "UniversityDegreeCredential"],
      credentialSubject: {
        id: "did:key:z6MkuHolderBob9988",
        degree: `M.Sc. ${peRequiredDegree}`,
        gpa: peMinGpa + 0.2,
        university: "Stanford University",
        graduationYear: 2025
      }
    };

    const isMatch = candidateVC.credentialSubject.gpa >= peMinGpa &&
      candidateVC.credentialSubject.degree.includes(peRequiredDegree);

    setPeEvalResult({
      valid: isMatch,
      definitionId: peDefinitionId,
      matchedDescriptors: isMatch ? ["university_degree_descriptor"] : [],
      matchedCredentials: isMatch ? [{
        descriptor_id: "university_degree_descriptor",
        credential_index: 0,
        credential_type: "UniversityDegreeCredential"
      }] : [],
      evaluationTimeMs: 1.4,
      auditHash: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
      errors: isMatch ? [] : [`Field $.credentialSubject.degree did not satisfy pattern filter '${peRequiredDegree}'`]
    });
  };

  // Simulate RSA Accumulator Non-Membership
  const handleCalculateNonMembership = () => {
    const isMember = accMembers.includes(nonMemberQuery);
    if (isMember) {
      setAccWitnessResult({
        error: `Element '${nonMemberQuery}' IS a member of the accumulator set. Non-membership cannot be proven.`
      });
      return;
    }

    const mockPrime = '0x' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
    const mockD = '0x' + Array.from({ length: 128 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
    const mockB = '-' + Math.floor(Math.random() * 900000 + 100000);

    setAccWitnessResult({
      valid: true,
      element: nonMemberQuery,
      primeRepresentative: mockPrime,
      bezoutCoefficientB: mockB,
      d: mockD,
      verificationEquation: "(d^x * V^b) mod N === g",
      isVerifiedConstantTime: true,
      timeMs: 2.1
    });
  };

  // Simulate Recursive ZK Predicate Graph
  const handleEvaluateZKGraph = () => {
    let isValid = false;
    const satisfiedCount = graphLeaves.filter(l => l.satisfied).length;

    if (graphOperator === 'AND') {
      isValid = satisfiedCount === graphLeaves.length;
    } else if (graphOperator === 'OR') {
      isValid = satisfiedCount > 0;
    } else if (graphOperator === 'THRESHOLD') {
      isValid = satisfiedCount >= graphThreshold;
    }

    setGraphEvalResult({
      valid: isValid,
      operator: graphOperator,
      threshold: graphThreshold,
      satisfiedCount,
      totalLeaves: graphLeaves.length,
      graphRootHash: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
      nodeEvaluations: graphLeaves.map(l => ({
        id: l.id,
        type: l.type,
        passed: l.satisfied,
        desc: l.desc
      }))
    });
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-8 border-b border-gray-800 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-mono">
              v2.5.0 Sovereign Suite
            </span>
            <span className="text-xs text-gray-500 font-mono">Zero-Knowledge Cryptography</span>
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight">
            Sovereign Trust Studio
          </h1>
          <p className="text-sm text-gray-400 mt-1 max-w-2xl">
            Interactive playground for W3C Bitstring Status List 2024, DIF Presentation Exchange 2.0, RSA Accumulator Non-Membership, and Recursive ZK Predicate Graphs.
          </p>
        </div>

        {/* Sub-Navigation Tabs */}
        <div className="flex items-center gap-1.5 p-1 bg-gray-900 border border-gray-800 rounded-xl overflow-x-auto">
          {[
            { id: 'statuslist', label: 'Status List 2024', icon: Layers },
            { id: 'pe', label: 'Presentation Exchange 2.0', icon: Sliders },
            { id: 'accumulator', label: 'RSA Non-Membership', icon: Lock },
            { id: 'zkgraph', label: 'ZK Predicate Graph', icon: GitBranch }
          ].map(tab => {
            const Icon = tab.icon;
            const active = activeSubTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveSubTab(tab.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  active
                    ? 'bg-blue-600 text-white shadow-md shadow-blue-500/20'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/60'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* --- TAB 1: W3C Bitstring Status List 2024 --- */}
      {activeSubTab === 'statuslist' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <div className="lg:col-span-5 space-y-6">
            <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-md">
              <h2 className="text-lg font-bold text-white mb-1 flex items-center gap-2">
                <Layers className="w-5 h-5 text-blue-400" />
                Bitstring Status List Configuration
              </h2>
              <p className="text-xs text-gray-400 mb-6">
                W3C-compliant compressed multi-bit revocation and suspension lists.
              </p>

              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Bitstring Capacity (Slots)
                  </label>
                  <input
                    type="number"
                    value={statusListSize}
                    onChange={(e) => setStatusListSize(Math.max(100, parseInt(e.target.value) || 1000))}
                    className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3.5 py-2 text-sm text-gray-200 focus:outline-none focus:border-blue-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Status Bit Size
                  </label>
                  <div className="grid grid-cols-4 gap-2">
                    {[1, 2, 4, 8].map(size => (
                      <button
                        key={size}
                        onClick={() => setStatusBitSize(size)}
                        className={`py-2 text-xs font-semibold rounded-lg border transition-all ${
                          statusBitSize === size
                            ? 'bg-blue-600/20 border-blue-500 text-blue-400'
                            : 'bg-gray-950 border-gray-800 text-gray-400 hover:border-gray-700'
                        }`}
                      >
                        {size} bit{size > 1 ? 's' : ''}
                      </button>
                    ))}
                  </div>
                  <span className="text-[10px] text-gray-500 mt-1 block">
                    {statusBitSize === 1 ? '0: Valid, 1: Revoked' : '0: Valid, 1: Revoked, 2: Suspended, 3: Under Review'}
                  </span>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Purpose
                  </label>
                  <select
                    value={statusPurpose}
                    onChange={(e) => setStatusPurpose(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3.5 py-2 text-sm text-gray-200 focus:outline-none focus:border-blue-500"
                  >
                    <option value="revocation">Revocation</option>
                    <option value="suspension">Suspension</option>
                  </select>
                </div>

                <div className="pt-2 border-t border-gray-800">
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Query Index Slot
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="number"
                      value={testIndex}
                      onChange={(e) => setTestIndex(parseInt(e.target.value) || 0)}
                      className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3.5 py-2 text-sm text-gray-200 focus:outline-none focus:border-blue-500 font-mono"
                    />
                    <select
                      value={statusMap[testIndex] || 0}
                      onChange={(e) => setStatusMap({ ...statusMap, [testIndex]: parseInt(e.target.value) })}
                      className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-200 focus:outline-none focus:border-blue-500 font-mono"
                    >
                      <option value="0">0: Valid</option>
                      <option value="1">1: Revoked</option>
                      {statusBitSize >= 2 && <option value="2">2: Suspended</option>}
                      {statusBitSize >= 2 && <option value="3">3: Review</option>}
                    </select>
                  </div>
                </div>

                <button
                  onClick={handleGenerateStatusList}
                  className="w-full mt-4 flex items-center justify-center gap-2 py-2.5 px-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-semibold text-xs rounded-xl shadow-lg shadow-blue-600/25 transition-all"
                >
                  <Zap className="w-4 h-4" />
                  Generate StatusList2024 Credential
                </button>
              </div>
            </div>
          </div>

          <div className="lg:col-span-7">
            {statusListResult ? (
              <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-md space-y-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    <h3 className="text-base font-bold text-white">Status List 2024 Generated</h3>
                  </div>
                  <button
                    onClick={() => copyToClipboard(statusListResult.statusListCredential)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs bg-gray-800 text-gray-300 hover:text-white transition-colors"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copied ? 'Copied' : 'Copy JSON'}
                  </button>
                </div>

                {/* Metrics Cards */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="bg-gray-950/80 border border-gray-800 p-3 rounded-xl">
                    <span className="text-[10px] text-gray-500 uppercase tracking-wider block font-mono">Query Slot</span>
                    <span className="text-sm font-bold text-white font-mono">#{statusListResult.metrics.testIndex}</span>
                  </div>
                  <div className="bg-gray-950/80 border border-gray-800 p-3 rounded-xl">
                    <span className="text-[10px] text-gray-500 uppercase tracking-wider block font-mono">Status State</span>
                    <span className={`text-xs font-bold font-mono ${
                      statusListResult.metrics.statusCode === 0 ? 'text-emerald-400' : 'text-rose-400'
                    }`}>
                      {statusListResult.metrics.statusLabel}
                    </span>
                  </div>
                  <div className="bg-gray-950/80 border border-gray-800 p-3 rounded-xl">
                    <span className="text-[10px] text-gray-500 uppercase tracking-wider block font-mono">Compression</span>
                    <span className="text-sm font-bold text-blue-400 font-mono">{statusListResult.metrics.compressionRatio}</span>
                  </div>
                  <div className="bg-gray-950/80 border border-gray-800 p-3 rounded-xl">
                    <span className="text-[10px] text-gray-500 uppercase tracking-wider block font-mono">Total Bits</span>
                    <span className="text-sm font-bold text-gray-300 font-mono">{statusListResult.metrics.totalBits.toLocaleString()}</span>
                  </div>
                </div>

                {/* Credential JSON Viewer */}
                <div>
                  <span className="text-xs font-semibold text-gray-400 block mb-2 font-mono">
                    W3C StatusList2024Credential Payload:
                  </span>
                  <pre className="p-4 bg-gray-950 rounded-xl border border-gray-800/80 text-[11px] text-emerald-400 font-mono overflow-x-auto max-h-96">
                    {JSON.stringify(statusListResult.statusListCredential, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <div className="h-full min-h-[300px] border border-dashed border-gray-800 rounded-2xl flex flex-col items-center justify-center p-8 text-center text-gray-500">
                <Layers className="w-12 h-12 text-gray-700 mb-3" />
                <p className="text-sm font-medium text-gray-400">No Status List Generated</p>
                <p className="text-xs text-gray-600 mt-1 max-w-sm">
                  Configure the bitstring size and bit resolution on the left, then click generate to view the W3C Verifiable Credential.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* --- TAB 2: DIF Presentation Exchange 2.0 --- */}
      {activeSubTab === 'pe' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <div className="lg:col-span-5 space-y-6">
            <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-md">
              <h2 className="text-lg font-bold text-white mb-1 flex items-center gap-2">
                <Sliders className="w-5 h-5 text-indigo-400" />
                Presentation Definition Builder
              </h2>
              <p className="text-xs text-gray-400 mb-6">
                Specify constraints and schema filters for verifiable claims verification.
              </p>

              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Definition ID
                  </label>
                  <input
                    type="text"
                    value={peDefinitionId}
                    onChange={(e) => setPeDefinitionId(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3.5 py-2 text-sm text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Required Degree Major (Regex Filter)
                  </label>
                  <input
                    type="text"
                    value={peRequiredDegree}
                    onChange={(e) => setPeRequiredDegree(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3.5 py-2 text-sm text-gray-200 focus:outline-none focus:border-indigo-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Minimum GPA Threshold: {peMinGpa}
                  </label>
                  <input
                    type="range"
                    min="2.0"
                    max="4.0"
                    step="0.1"
                    value={peMinGpa}
                    onChange={(e) => setPeMinGpa(parseFloat(e.target.value))}
                    className="w-full accent-indigo-500"
                  />
                </div>

                <button
                  onClick={handleEvaluatePE}
                  className="w-full mt-4 flex items-center justify-center gap-2 py-2.5 px-4 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-semibold text-xs rounded-xl shadow-lg shadow-indigo-600/25 transition-all"
                >
                  <Zap className="w-4 h-4" />
                  Evaluate Presentation Exchange
                </button>
              </div>
            </div>
          </div>

          <div className="lg:col-span-7">
            {peEvalResult ? (
              <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-md space-y-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {peEvalResult.valid ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <XCircle className="w-5 h-5 text-rose-400" />
                    )}
                    <h3 className="text-base font-bold text-white">
                      Evaluation Result: {peEvalResult.valid ? 'PASSED' : 'FAILED'}
                    </h3>
                  </div>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-400">
                    {peEvalResult.evaluationTimeMs}ms
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-gray-950/80 border border-gray-800 p-3 rounded-xl">
                    <span className="text-[10px] text-gray-500 uppercase tracking-wider block font-mono">Audit Digest</span>
                    <span className="text-xs text-indigo-400 font-mono truncate block">{peEvalResult.auditHash}</span>
                  </div>
                  <div className="bg-gray-950/80 border border-gray-800 p-3 rounded-xl">
                    <span className="text-[10px] text-gray-500 uppercase tracking-wider block font-mono">Matched Descriptors</span>
                    <span className="text-xs text-gray-300 font-mono block">{peEvalResult.matchedDescriptors.length} matched</span>
                  </div>
                </div>

                {peEvalResult.errors.length > 0 && (
                  <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl text-xs text-rose-300">
                    {peEvalResult.errors.map((err, i) => (
                      <div key={i}>• {err}</div>
                    ))}
                  </div>
                )}

                <div>
                  <span className="text-xs font-semibold text-gray-400 block mb-2 font-mono">
                    Evaluation Descriptor Trace:
                  </span>
                  <pre className="p-4 bg-gray-950 rounded-xl border border-gray-800/80 text-[11px] text-indigo-300 font-mono overflow-x-auto max-h-64">
                    {JSON.stringify(peEvalResult, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <div className="h-full min-h-[300px] border border-dashed border-gray-800 rounded-2xl flex flex-col items-center justify-center p-8 text-center text-gray-500">
                <Sliders className="w-12 h-12 text-gray-700 mb-3" />
                <p className="text-sm font-medium text-gray-400">No Evaluation Performed</p>
                <p className="text-xs text-gray-600 mt-1 max-w-sm">
                  Click 'Evaluate Presentation Exchange' to verify simulated Verifiable Credentials against the definition constraints.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* --- TAB 3: RSA Accumulator Non-Membership --- */}
      {activeSubTab === 'accumulator' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <div className="lg:col-span-5 space-y-6">
            <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-md">
              <h2 className="text-lg font-bold text-white mb-1 flex items-center gap-2">
                <Lock className="w-5 h-5 text-emerald-400" />
                RSA Accumulator Members
              </h2>
              <p className="text-xs text-gray-400 mb-6">
                Constant-time O(1) membership & non-membership verification using Bezout identity.
              </p>

              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Current Accumulator Members ({accMembers.length})
                  </label>
                  <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                    {accMembers.map((m, i) => (
                      <div key={i} className="flex items-center justify-between bg-gray-950 p-2 rounded-lg border border-gray-800 text-[11px] font-mono text-gray-300">
                        <span className="truncate max-w-[240px]">{m}</span>
                        <button
                          onClick={() => setAccMembers(accMembers.filter((_, idx) => idx !== i))}
                          className="text-rose-400 hover:text-rose-300 text-xs px-1"
                        >
                          ×
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="did:key:z..."
                    value={newAccMember}
                    onChange={(e) => setNewAccMember(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                  <button
                    onClick={() => {
                      if (newAccMember.trim()) {
                        setAccMembers([...accMembers, newAccMember.trim()]);
                        setNewAccMember('');
                      }
                    }}
                    className="px-3 py-1.5 bg-gray-800 text-white rounded-lg text-xs font-semibold hover:bg-gray-700"
                  >
                    Add
                  </button>
                </div>

                <div className="pt-2 border-t border-gray-800">
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Target Non-Member Element
                  </label>
                  <input
                    type="text"
                    value={nonMemberQuery}
                    onChange={(e) => setNonMemberQuery(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3.5 py-2 text-xs text-gray-200 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>

                <button
                  onClick={handleCalculateNonMembership}
                  className="w-full mt-4 flex items-center justify-center gap-2 py-2.5 px-4 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold text-xs rounded-xl shadow-lg shadow-emerald-600/25 transition-all"
                >
                  <Zap className="w-4 h-4" />
                  Compute Bezout Non-Membership Witness
                </button>
              </div>
            </div>
          </div>

          <div className="lg:col-span-7">
            {accWitnessResult ? (
              <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-md space-y-6">
                {accWitnessResult.error ? (
                  <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl text-xs text-rose-300 flex items-center gap-3">
                    <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0" />
                    <span>{accWitnessResult.error}</span>
                  </div>
                ) : (
                  <>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                        <h3 className="text-base font-bold text-white">
                          Non-Membership Witness Cryptographically Verified
                        </h3>
                      </div>
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-400">
                        {accWitnessResult.timeMs}ms
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="bg-gray-950/80 border border-gray-800 p-3 rounded-xl">
                        <span className="text-[10px] text-gray-500 uppercase tracking-wider block font-mono">Bezout Coefficient b</span>
                        <span className="text-xs text-emerald-400 font-mono truncate block">{accWitnessResult.bezoutCoefficientB}</span>
                      </div>
                      <div className="bg-gray-950/80 border border-gray-800 p-3 rounded-xl">
                        <span className="text-[10px] text-gray-500 uppercase tracking-wider block font-mono">Verification Check</span>
                        <span className="text-xs text-gray-300 font-mono block">{accWitnessResult.verificationEquation}</span>
                      </div>
                    </div>

                    <div>
                      <span className="text-xs font-semibold text-gray-400 block mb-2 font-mono">
                        Non-Membership Witness Object (O(1) Constant Size):
                      </span>
                      <pre className="p-4 bg-gray-950 rounded-xl border border-gray-800/80 text-[11px] text-emerald-300 font-mono overflow-x-auto max-h-64">
                        {JSON.stringify(accWitnessResult, null, 2)}
                      </pre>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="h-full min-h-[300px] border border-dashed border-gray-800 rounded-2xl flex flex-col items-center justify-center p-8 text-center text-gray-500">
                <Lock className="w-12 h-12 text-gray-700 mb-3" />
                <p className="text-sm font-medium text-gray-400">No Witness Computed</p>
                <p className="text-xs text-gray-600 mt-1 max-w-sm">
                  Specify accumulator members and a target element to generate Bezout coefficients and verify non-membership.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* --- TAB 4: Recursive ZK Predicate Graph --- */}
      {activeSubTab === 'zkgraph' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <div className="lg:col-span-5 space-y-6">
            <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-md">
              <h2 className="text-lg font-bold text-white mb-1 flex items-center gap-2">
                <GitBranch className="w-5 h-5 text-purple-400" />
                ZK Predicate Tree Policy
              </h2>
              <p className="text-xs text-gray-400 mb-6">
                Compose heterogeneous zero-knowledge proofs under arbitrary boolean logic graphs.
              </p>

              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Root Boolean Operator
                  </label>
                  <div className="grid grid-cols-3 gap-2">
                    {['AND', 'OR', 'THRESHOLD'].map(op => (
                      <button
                        key={op}
                        onClick={() => setGraphOperator(op)}
                        className={`py-2 text-xs font-semibold rounded-lg border transition-all ${
                          graphOperator === op
                            ? 'bg-purple-600/20 border-purple-500 text-purple-400'
                            : 'bg-gray-950 border-gray-800 text-gray-400 hover:border-gray-700'
                        }`}
                      >
                        {op}
                      </button>
                    ))}
                  </div>
                </div>

                {graphOperator === 'THRESHOLD' && (
                  <div>
                    <label className="block text-xs font-semibold text-gray-300 mb-1">
                      Threshold Required: {graphThreshold} of {graphLeaves.length}
                    </label>
                    <input
                      type="range"
                      min="1"
                      max={graphLeaves.length}
                      value={graphThreshold}
                      onChange={(e) => setGraphThreshold(parseInt(e.target.value))}
                      className="w-full accent-purple-500"
                    />
                  </div>
                )}

                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-2">
                    Sub-Predicate Leaves (Toggle Satisfaction)
                  </label>
                  <div className="space-y-2">
                    {graphLeaves.map((leaf, idx) => (
                      <div
                        key={leaf.id}
                        onClick={() => {
                          const updated = [...graphLeaves];
                          updated[idx].satisfied = !updated[idx].satisfied;
                          setGraphLeaves(updated);
                        }}
                        className={`p-3 rounded-xl border cursor-pointer transition-all flex items-center justify-between ${
                          leaf.satisfied
                            ? 'bg-purple-500/10 border-purple-500/30 text-purple-200'
                            : 'bg-gray-950 border-gray-800 text-gray-500'
                        }`}
                      >
                        <div>
                          <span className="text-xs font-semibold block">{leaf.desc}</span>
                          <span className="text-[10px] font-mono opacity-60">{leaf.type}</span>
                        </div>
                        <span className={`text-xs font-bold px-2 py-0.5 rounded ${
                          leaf.satisfied ? 'bg-purple-500/20 text-purple-300' : 'bg-gray-800 text-gray-500'
                        }`}>
                          {leaf.satisfied ? 'SATISFIED' : 'UNSATISFIED'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <button
                  onClick={handleEvaluateZKGraph}
                  className="w-full mt-4 flex items-center justify-center gap-2 py-2.5 px-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white font-semibold text-xs rounded-xl shadow-lg shadow-purple-600/25 transition-all"
                >
                  <Zap className="w-4 h-4" />
                  Evaluate Recursive ZK Graph
                </button>
              </div>
            </div>
          </div>

          <div className="lg:col-span-7">
            {graphEvalResult ? (
              <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-md space-y-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {graphEvalResult.valid ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <XCircle className="w-5 h-5 text-rose-400" />
                    )}
                    <h3 className="text-base font-bold text-white">
                      Policy Evaluation: {graphEvalResult.valid ? 'PERMITTED' : 'DENIED'}
                    </h3>
                  </div>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-gray-800 text-purple-400">
                    {graphEvalResult.satisfiedCount} / {graphEvalResult.totalLeaves} Leaves Satisfied
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-gray-950/80 border border-gray-800 p-3 rounded-xl">
                    <span className="text-[10px] text-gray-500 uppercase tracking-wider block font-mono">Graph Root Hash</span>
                    <span className="text-xs text-purple-400 font-mono truncate block">{graphEvalResult.graphRootHash}</span>
                  </div>
                  <div className="bg-gray-950/80 border border-gray-800 p-3 rounded-xl">
                    <span className="text-[10px] text-gray-500 uppercase tracking-wider block font-mono">Logic Operator</span>
                    <span className="text-xs text-gray-300 font-mono block">
                      {graphEvalResult.operator} {graphEvalResult.operator === 'THRESHOLD' ? `(k=${graphEvalResult.threshold})` : ''}
                    </span>
                  </div>
                </div>

                <div>
                  <span className="text-xs font-semibold text-gray-400 block mb-2 font-mono">
                    Evaluation Node Tree Proof:
                  </span>
                  <pre className="p-4 bg-gray-950 rounded-xl border border-gray-800/80 text-[11px] text-purple-300 font-mono overflow-x-auto max-h-64">
                    {JSON.stringify(graphEvalResult, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <div className="h-full min-h-[300px] border border-dashed border-gray-800 rounded-2xl flex flex-col items-center justify-center p-8 text-center text-gray-500">
                <GitBranch className="w-12 h-12 text-gray-700 mb-3" />
                <p className="text-sm font-medium text-gray-400">No Graph Evaluated</p>
                <p className="text-xs text-gray-600 mt-1 max-w-sm">
                  Configure boolean operations and toggle leaf conditions to evaluate the recursive zero-knowledge predicate graph.
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
