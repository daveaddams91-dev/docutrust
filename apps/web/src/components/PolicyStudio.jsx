import React, { useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  FileCheck2, 
  Code2, 
  CheckCircle2, 
  AlertCircle, 
  Play, 
  Copy, 
  Check, 
  Key, 
  FileText, 
  Cpu, 
  Network, 
  RefreshCw,
  Download,
  Share2,
  Sparkles,
  Lock
} from 'lucide-react';

const SAMPLE_PAYLOAD = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "urn:uuid:cred-security-officer-4091",
  "type": ["VerifiableCredential", "SecurityOfficerCredential"],
  "issuer": "did:peer:0z6MkuSovereignAuthorityKeyNode",
  "validFrom": "2026-08-30T10:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkuAgentSubject44",
    "name": "Sarah Connor",
    "clearanceLevel": 5,
    "division": "CyberDefense",
    "jurisdiction": "EU-NORTH",
    "activeStatus": true,
    "certifications": ["CISSP", "CISM", "POST_QUANTUM_DEFENSE"]
  }
};

const SAMPLE_POLICY = {
  "id": "policy:cyber-l5-eu",
  "name": "Critical Infrastructure Level-5 Cyber Authorization",
  "description": "Requires Level 5 clearance, CyberDefense division, EU jurisdiction, and post-quantum certification",
  "condition": {
    "operator": "and",
    "conditions": [
      {
        "field": "credentialSubject.clearanceLevel",
        "operator": "gte",
        "value": 5
      },
      {
        "field": "credentialSubject.division",
        "operator": "eq",
        "value": "CyberDefense"
      },
      {
        "field": "credentialSubject.certifications",
        "operator": "contains",
        "value": "POST_QUANTUM_DEFENSE"
      },
      {
        "field": "credentialSubject.activeStatus",
        "operator": "eq",
        "value": true
      }
    ]
  }
};

const PRESETS = [
  {
    name: 'CyberDefense Clearance L5',
    policy: SAMPLE_POLICY,
    payload: SAMPLE_PAYLOAD
  },
  {
    name: 'Accredited Investor & KYC',
    policy: {
      id: 'policy:defi-accredited-kyc',
      name: 'DeFi Institutional Compliance Rule',
      description: 'Requires accredited status and verified KYC Tier >= 2',
      condition: {
        operator: 'and',
        conditions: [
          { field: 'credentialSubject.accredited', operator: 'eq', value: true },
          { field: 'credentialSubject.kycTier', operator: 'gte', value: 2 },
          { field: 'credentialSubject.jurisdiction', operator: 'not_in', value: ['SANCTIONED_ZONE'] }
        ]
      }
    },
    payload: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "id": "urn:uuid:investor-kyc-901",
      "type": ["VerifiableCredential", "InvestorCredential"],
      "issuer": "did:peer:0z6MkuKyvAuthorityNode",
      "credentialSubject": {
        "id": "did:key:z6MkuInvestorDave",
        "accredited": true,
        "kycTier": 3,
        "netWorthUSD": 2500000,
        "jurisdiction": "CH"
      }
    }
  },
  {
    name: 'GDPR Data Processor Audit',
    policy: {
      id: 'policy:gdpr-processor-eu',
      name: 'GDPR Processing Authorization',
      description: 'Requires ISO27001 audit and DPO registration',
      condition: {
        operator: 'or',
        conditions: [
          { field: 'credentialSubject.iso27001Compliant', operator: 'eq', value: true },
          {
            operator: 'and',
            conditions: [
              { field: 'credentialSubject.soc2Type2', operator: 'eq', value: true },
              { field: 'credentialSubject.dpoRegistered', operator: 'eq', value: true }
            ]
          }
        ]
      }
    },
    payload: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "id": "urn:uuid:gdpr-processor-12",
      "type": ["VerifiableCredential", "ProcessorAuditCredential"],
      "issuer": "did:peer:0z6MkuComplianceNode",
      "credentialSubject": {
        "id": "did:key:z6MkuCloudVendor",
        "iso27001Compliant": true,
        "soc2Type2": true,
        "dpoRegistered": true
      }
    }
  }
];

export default function PolicyStudio() {
  const [activeTab, setActiveTab] = useState('evaluate'); // 'evaluate' | 'verify' | 'did-peer' | 'solidity'
  const [selectedPreset, setSelectedPreset] = useState(0);
  const [payloadText, setPayloadText] = useState(JSON.stringify(SAMPLE_PAYLOAD, null, 2));
  const [policyText, setPolicyText] = useState(JSON.stringify(SAMPLE_POLICY, null, 2));
  const [evaluationResult, setEvaluationResult] = useState(null);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [receiptJson, setReceiptJson] = useState('');
  const [receiptVerifyResult, setReceiptVerifyResult] = useState(null);
  const [copied, setCopied] = useState(false);

  // DID Peer State
  const [peerMethod, setPeerMethod] = useState(0);
  const [peerServiceUrl, setPeerServiceUrl] = useState('https://agent.docutrust.org/didcomm');
  const [generatedPeerDid, setGeneratedPeerDid] = useState(null);
  const [peerDidToResolve, setPeerDidToResolve] = useState('');
  const [resolvedDidDoc, setResolvedDidDoc] = useState(null);

  // Solidity Registry Export State
  const [solidityContractName, setSolidityContractName] = useState('DocuTrustAccreditationRegistry');
  const [solidityCode, setSolidityCode] = useState('');

  const handleApplyPreset = (index) => {
    setSelectedPreset(index);
    setPayloadText(JSON.stringify(PRESETS[index].payload, null, 2));
    setPolicyText(JSON.stringify(PRESETS[index].policy, null, 2));
    setEvaluationResult(null);
  };

  const handleEvaluatePolicy = async () => {
    setIsEvaluating(true);
    setEvaluationResult(null);
    try {
      const parsedPayload = JSON.parse(payloadText);
      const parsedPolicy = JSON.parse(policyText);

      // Call API server or client evaluation
      const res = await fetch('http://localhost:4000/api/v1/policy/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: parsedPayload, policy: parsedPolicy })
      });

      if (res.ok) {
        const data = await res.json();
        setEvaluationResult(data);
        if (data.receipt) {
          setReceiptJson(JSON.stringify(data.receipt, null, 2));
        }
      } else {
        const err = await res.json();
        setEvaluationResult({ error: err.error || 'Evaluation failed' });
      }
    } catch (e) {
      setEvaluationResult({ error: e.message });
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleVerifyReceipt = async () => {
    setReceiptVerifyResult(null);
    try {
      const parsedReceipt = JSON.parse(receiptJson);
      const res = await fetch('http://localhost:4000/api/v1/policy/verify-receipt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ receipt: parsedReceipt })
      });
      const data = await res.json();
      setReceiptVerifyResult(data);
    } catch (e) {
      setReceiptVerifyResult({ error: e.message });
    }
  };

  const handleCreateDidPeer = async () => {
    try {
      const res = await fetch('http://localhost:4000/api/v1/did/peer/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method: peerMethod,
          serviceEndpoint: peerMethod === 2 ? peerServiceUrl : undefined
        })
      });
      const data = await res.json();
      if (data.success) {
        setGeneratedPeerDid(data);
        setPeerDidToResolve(data.did);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleResolveDidPeer = async () => {
    if (!peerDidToResolve) return;
    try {
      const res = await fetch(`http://localhost:4000/api/v1/did/peer/resolve?did=${encodeURIComponent(peerDidToResolve)}`);
      const data = await res.json();
      setResolvedDidDoc(data);
    } catch (e) {
      setResolvedDidDoc({ error: e.message });
    }
  };

  const handleExportSolidity = async () => {
    try {
      const res = await fetch('http://localhost:4000/api/v1/solidity/export-registry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contractName: solidityContractName })
      });
      const data = await res.json();
      if (data.success) {
        setSolidityCode(data.contractCode);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-8 border-b border-gray-800">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
              <Sparkles className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold text-white tracking-tight">Sovereign Policy Studio</h1>
                <span className="px-2 py-0.5 text-xs font-mono rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">v9.0.0</span>
              </div>
              <p className="text-sm text-gray-400 mt-1">
                Policy-as-Proof AST Engine, Cryptographic Evaluation Receipts, W3C did:peer RFC 0627, and EVM Multi-Issuer Trust Registries.
              </p>
            </div>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center bg-gray-900/80 p-1.5 rounded-xl border border-gray-800">
          <button
            onClick={() => setActiveTab('evaluate')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'evaluate'
                ? 'bg-blue-600 text-white shadow'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Policy Evaluator
          </button>
          <button
            onClick={() => setActiveTab('verify')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'verify'
                ? 'bg-blue-600 text-white shadow'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Verify Receipt
          </button>
          <button
            onClick={() => setActiveTab('did-peer')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'did-peer'
                ? 'bg-blue-600 text-white shadow'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            did:peer RFC 0627
          </button>
          <button
            onClick={() => setActiveTab('solidity')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'solidity'
                ? 'bg-blue-600 text-white shadow'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Solidity Registry
          </button>
        </div>
      </div>

      {/* TAB 1: Policy Evaluator */}
      {activeTab === 'evaluate' && (
        <div className="mt-8 space-y-6">
          {/* Preset Selector */}
          <div className="flex flex-wrap items-center gap-3 bg-gray-900/40 p-3 rounded-xl border border-gray-800">
            <span className="text-xs text-gray-400 font-medium">Compliance Templates:</span>
            {PRESETS.map((preset, idx) => (
              <button
                key={idx}
                onClick={() => handleApplyPreset(idx)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                  selectedPreset === idx
                    ? 'bg-blue-600/20 text-blue-300 border-blue-500/50'
                    : 'bg-gray-800/60 text-gray-400 border-gray-700 hover:text-white'
                }`}
              >
                {preset.name}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Input 1: Payload / VC */}
            <div className="flex flex-col rounded-2xl bg-gray-900/60 border border-gray-800 p-5 shadow-xl">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-blue-400" />
                  <span className="text-sm font-semibold text-white">Target Payload / Verifiable Credential</span>
                </div>
                <span className="text-xs text-gray-500 font-mono">JSON</span>
              </div>
              <textarea
                value={payloadText}
                onChange={(e) => setPayloadText(e.target.value)}
                rows={14}
                className="w-full bg-gray-950/80 border border-gray-800 rounded-xl p-3.5 font-mono text-xs text-gray-300 focus:outline-none focus:border-blue-500/60 transition-colors"
                spellCheck="false"
              />
            </div>

            {/* Input 2: Policy AST Definition */}
            <div className="flex flex-col rounded-2xl bg-gray-900/60 border border-gray-800 p-5 shadow-xl">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Code2 className="w-4 h-4 text-purple-400" />
                  <span className="text-sm font-semibold text-white">Sovereign Policy AST Definition</span>
                </div>
                <span className="text-xs text-gray-500 font-mono">AST Schema</span>
              </div>
              <textarea
                value={policyText}
                onChange={(e) => setPolicyText(e.target.value)}
                rows={14}
                className="w-full bg-gray-950/80 border border-gray-800 rounded-xl p-3.5 font-mono text-xs text-gray-300 focus:outline-none focus:border-purple-500/60 transition-colors"
                spellCheck="false"
              />
            </div>
          </div>

          {/* Evaluate Action Button */}
          <div className="flex justify-center pt-2">
            <button
              onClick={handleEvaluatePolicy}
              disabled={isEvaluating}
              className="flex items-center gap-2 px-8 py-3 rounded-xl font-semibold text-sm bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-lg shadow-blue-500/25 transition-all transform hover:-translate-y-0.5 disabled:opacity-50"
            >
              <Play className="w-4 h-4 fill-white" />
              {isEvaluating ? 'Evaluating AST Policy...' : 'Execute Sovereign Policy & Generate Signed Receipt'}
            </button>
          </div>

          {/* Results Display */}
          {evaluationResult && (
            <div className={`p-6 rounded-2xl border ${
              evaluationResult.error
                ? 'bg-red-950/30 border-red-500/40 text-red-300'
                : evaluationResult.passed
                ? 'bg-emerald-950/30 border-emerald-500/40'
                : 'bg-amber-950/30 border-amber-500/40'
            }`}>
              {evaluationResult.error ? (
                <div className="flex items-center gap-3">
                  <ShieldAlert className="w-6 h-6 text-red-400 shrink-0" />
                  <div>
                    <h3 className="font-semibold text-red-300">Policy Evaluation Error</h3>
                    <p className="text-xs text-red-400 mt-1">{evaluationResult.error}</p>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      {evaluationResult.passed ? (
                        <CheckCircle2 className="w-7 h-7 text-emerald-400 shrink-0" />
                      ) : (
                        <AlertCircle className="w-7 h-7 text-amber-400 shrink-0" />
                      )}
                      <div>
                        <h3 className={`text-base font-bold ${evaluationResult.passed ? 'text-emerald-300' : 'text-amber-300'}`}>
                          {evaluationResult.passed ? 'Policy Evaluation PASSED' : 'Policy Evaluation FAILED'}
                        </h3>
                        <p className="text-xs text-gray-400 mt-0.5">
                          Policy ID: <span className="font-mono text-gray-200">{evaluationResult.policyId}</span> &bull; 
                          Executed at: <span className="font-mono text-gray-200">{new Date(evaluationResult.evaluatedAt).toLocaleString()}</span>
                        </p>
                      </div>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-xs font-bold font-mono uppercase tracking-wider ${
                      evaluationResult.passed
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}>
                      {evaluationResult.passed ? 'AUTHORIZED' : 'DENIED'}
                    </span>
                  </div>

                  {/* AST Node Evaluation Breakdown */}
                  {evaluationResult.trace && (
                    <div className="bg-gray-950/70 p-4 rounded-xl border border-gray-800/80 space-y-2">
                      <span className="text-xs font-semibold text-gray-300">AST Rule Traversal Trace:</span>
                      <div className="space-y-1.5 max-h-48 overflow-y-auto">
                        {evaluationResult.trace.map((item, idx) => (
                          <div key={idx} className="flex items-center justify-between text-xs py-1 px-2.5 rounded bg-gray-900/60 font-mono">
                            <span className="text-gray-300">{item.field || 'Composite Node'} ({item.operator})</span>
                            <span className={item.passed ? 'text-emerald-400 font-semibold' : 'text-red-400 font-semibold'}>
                              {item.passed ? 'MATCH' : 'MISMATCH'}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Signed Policy Receipt */}
                  {evaluationResult.receipt && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-gray-300 flex items-center gap-1.5">
                          <Lock className="w-3.5 h-3.5 text-blue-400" />
                          Cryptographic PolicyEvaluationReceipt (Ed25519 Signed)
                        </span>
                        <button
                          onClick={() => copyToClipboard(JSON.stringify(evaluationResult.receipt, null, 2))}
                          className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 font-mono"
                        >
                          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          {copied ? 'Copied' : 'Copy Receipt'}
                        </button>
                      </div>
                      <pre className="bg-gray-950 p-4 rounded-xl border border-gray-800 text-xs font-mono text-gray-300 overflow-x-auto">
                        {JSON.stringify(evaluationResult.receipt, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: Verify Receipt */}
      {activeTab === 'verify' && (
        <div className="mt-8 max-w-3xl mx-auto space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 shadow-xl">
            <h2 className="text-base font-bold text-white mb-2 flex items-center gap-2">
              <FileCheck2 className="w-5 h-5 text-blue-400" />
              Verify Cryptographic Policy Receipt
            </h2>
            <p className="text-xs text-gray-400 mb-4">
              Independently verify an Ed25519-signed PolicyEvaluationReceipt proof without needing access to the original policy engine.
            </p>

            <textarea
              value={receiptJson}
              onChange={(e) => setReceiptJson(e.target.value)}
              placeholder="Paste PolicyEvaluationReceipt JSON here..."
              rows={12}
              className="w-full bg-gray-950/80 border border-gray-800 rounded-xl p-3.5 font-mono text-xs text-gray-300 focus:outline-none focus:border-blue-500/60 transition-colors"
              spellCheck="false"
            />

            <div className="flex justify-end mt-4">
              <button
                onClick={handleVerifyReceipt}
                className="flex items-center gap-2 px-6 py-2.5 rounded-xl font-semibold text-xs bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-500/20 transition-all"
              >
                <ShieldCheck className="w-4 h-4" />
                Verify Cryptographic Receipt
              </button>
            </div>
          </div>

          {receiptVerifyResult && (
            <div className={`p-5 rounded-2xl border ${
              receiptVerifyResult.valid
                ? 'bg-emerald-950/30 border-emerald-500/40'
                : 'bg-red-950/30 border-red-500/40 text-red-300'
            }`}>
              <div className="flex items-center gap-3">
                {receiptVerifyResult.valid ? (
                  <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                ) : (
                  <ShieldAlert className="w-6 h-6 text-red-400" />
                )}
                <div>
                  <h4 className="font-bold text-sm">
                    {receiptVerifyResult.valid ? 'Cryptographic Receipt is VALID' : 'Receipt Signature Verification FAILED'}
                  </h4>
                  <p className="text-xs text-gray-400 mt-0.5">
                    {receiptVerifyResult.valid
                      ? 'The signature and digest bindings are mathematically authentic and unforgeable.'
                      : (receiptVerifyResult.error || 'The receipt signature is invalid or payload has been tampered with.')}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: did:peer RFC 0627 */}
      {activeTab === 'did-peer' && (
        <div className="mt-8 grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Creator */}
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Network className="w-5 h-5 text-indigo-400" />
              W3C did:peer Identifier Generator
            </h2>
            <p className="text-xs text-gray-400">
              Create offline peer-to-peer DIDs compliant with RFC 0627 (Method 0 for Inception Key, Method 2 for Multiple Keys and Service Endpoints).
            </p>

            <div className="space-y-3 pt-2">
              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1.5">Peer DID Method:</label>
                <div className="flex gap-3">
                  <button
                    onClick={() => setPeerMethod(0)}
                    className={`flex-1 py-2 px-3 rounded-lg text-xs font-semibold border ${
                      peerMethod === 0
                        ? 'bg-indigo-600/20 text-indigo-300 border-indigo-500/50'
                        : 'bg-gray-800/40 text-gray-400 border-gray-700'
                    }`}
                  >
                    Method 0 (Inception Key)
                  </button>
                  <button
                    onClick={() => setPeerMethod(2)}
                    className={`flex-1 py-2 px-3 rounded-lg text-xs font-semibold border ${
                      peerMethod === 2
                        ? 'bg-indigo-600/20 text-indigo-300 border-indigo-500/50'
                        : 'bg-gray-800/40 text-gray-400 border-gray-700'
                    }`}
                  >
                    Method 2 (Keys + Services)
                  </button>
                </div>
              </div>

              {peerMethod === 2 && (
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1.5">Service Endpoint URL:</label>
                  <input
                    type="text"
                    value={peerServiceUrl}
                    onChange={(e) => setPeerServiceUrl(e.target.value)}
                    className="w-full bg-gray-950/80 border border-gray-800 rounded-lg px-3 py-2 text-xs font-mono text-gray-300"
                  />
                </div>
              )}

              <button
                onClick={handleCreateDidPeer}
                className="w-full py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 font-semibold text-xs text-white transition-colors"
              >
                Generate did:peer Identifier
              </button>
            </div>

            {generatedPeerDid && (
              <div className="pt-4 border-t border-gray-800 space-y-2">
                <span className="text-xs text-gray-400">Generated DID:</span>
                <div className="p-3 bg-gray-950 rounded-lg border border-gray-800 font-mono text-xs text-indigo-300 break-all select-all">
                  {generatedPeerDid.did}
                </div>
              </div>
            )}
          </div>

          {/* Universal Resolver */}
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Cpu className="w-5 h-5 text-blue-400" />
              Universal did:peer Resolver
            </h2>
            <p className="text-xs text-gray-400">
              Deterministically decode and resolve complete W3C DID Documents from did:peer strings without network dependencies.
            </p>

            <div className="space-y-3 pt-2">
              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1.5">Enter did:peer URI:</label>
                <input
                  type="text"
                  value={peerDidToResolve}
                  onChange={(e) => setPeerDidToResolve(e.target.value)}
                  placeholder="did:peer:0z6Mku... or did:peer:2.V..."
                  className="w-full bg-gray-950/80 border border-gray-800 rounded-lg px-3 py-2 text-xs font-mono text-gray-300"
                />
              </div>

              <button
                onClick={handleResolveDidPeer}
                className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 font-semibold text-xs text-white transition-colors"
              >
                Resolve DID Document
              </button>
            </div>

            {resolvedDidDoc && (
              <div className="pt-4 border-t border-gray-800 space-y-2">
                <span className="text-xs text-gray-400">Resolved W3C DID Document:</span>
                <pre className="p-4 bg-gray-950 rounded-xl border border-gray-800 font-mono text-xs text-gray-300 max-h-64 overflow-y-auto">
                  {JSON.stringify(resolvedDidDoc, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: Solidity Trust Registry */}
      {activeTab === 'solidity' && (
        <div className="mt-8 max-w-4xl mx-auto space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <Code2 className="w-5 h-5 text-emerald-400" />
                  EVM Multi-Issuer Accreditation Registry
                </h2>
                <p className="text-xs text-gray-400 mt-1">
                  Export production-grade Solidity smart contracts for decentralized on-chain trust registry governance and status list aggregation.
                </p>
              </div>
              <button
                onClick={handleExportSolidity}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-xs bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-500/20 transition-all"
              >
                <Download className="w-4 h-4" />
                Generate Contract Code
              </button>
            </div>

            <div>
              <label className="block text-xs font-semibold text-gray-300 mb-1.5">Solidity Contract Name:</label>
              <input
                type="text"
                value={solidityContractName}
                onChange={(e) => setSolidityContractName(e.target.value)}
                className="w-full bg-gray-950/80 border border-gray-800 rounded-lg px-3 py-2 text-xs font-mono text-gray-300"
              />
            </div>

            {solidityCode && (
              <div className="space-y-2 pt-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-gray-400">{solidityContractName}.sol</span>
                  <button
                    onClick={() => copyToClipboard(solidityCode)}
                    className="flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300 font-mono"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copied ? 'Copied' : 'Copy Solidity Code'}
                  </button>
                </div>
                <pre className="bg-gray-950 p-4 rounded-xl border border-gray-800 text-xs font-mono text-gray-300 max-h-96 overflow-y-auto">
                  {solidityCode}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
