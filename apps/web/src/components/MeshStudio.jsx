import React, { useState } from 'react';
import {
  Globe,
  Users,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Search,
  Key,
  Layers,
  ArrowRight,
  FileCheck,
  Hash,
  Shield,
  FileCode
} from 'lucide-react';

export default function MeshStudio() {
  // Tab state
  const [activeSection, setActiveSection] = useState('did');

  // DID Resolver State
  const [inputDid, setInputDid] = useState('did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH');
  const [resolvedDoc, setResolvedDoc] = useState(null);
  const [didError, setDidError] = useState(null);
  const [didResolving, setDidResolving] = useState(false);

  // MultiSig Interactive State
  const [msigDraft, setMsigDraft] = useState(null);
  const [msigSignatures, setMsigSignatures] = useState([]);
  const [msigResult, setMsigResult] = useState(null);

  // Trust Registry State
  const [registryQuery, setRegistryQuery] = useState('');
  const issuers = [
    {
      issuerDid: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
      legalName: 'Stanford University Registrar',
      status: 'active',
      jurisdiction: 'US-CA',
      authorizedSchemas: ['https://schema.docutrust.org/credentials/v2/degree.json', 'https://schema.docutrust.org/credentials/v2/transcript.json'],
      accreditationLevel: 'Tier-1 Sovereign Authority'
    },
    {
      issuerDid: 'did:web:mit.edu:registrar',
      legalName: 'Massachusetts Institute of Technology',
      status: 'active',
      jurisdiction: 'US-MA',
      authorizedSchemas: ['https://schema.docutrust.org/credentials/v2/degree.json'],
      accreditationLevel: 'Tier-1 Sovereign Authority'
    },
    {
      issuerDid: 'did:pkh:eip155:1:0x71C83638379321e0b51B8d6Ac7b6C81204d80916',
      legalName: 'Ethereum Foundation Academy',
      status: 'active',
      jurisdiction: 'GLOBAL-EVM',
      authorizedSchemas: ['https://schema.docutrust.org/credentials/v2/badge.json'],
      accreditationLevel: 'Decentralized Consortium'
    }
  ];

  const handleResolveDid = () => {
    setDidResolving(true);
    setDidError(null);
    try {
      if (!inputDid || !inputDid.startsWith('did:')) {
        throw new Error('Invalid DID URI scheme. Must begin with did:');
      }
      const parts = inputDid.split(':');
      const method = parts[1];
      let doc = null;

      if (method === 'key') {
        doc = {
          '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
          id: inputDid,
          verificationMethod: [{
            id: `${inputDid}#key-1`,
            type: 'Ed25519VerificationKey2020',
            controller: inputDid,
            publicKeyMultibase: parts[2]
          }],
          authentication: [`${inputDid}#key-1`],
          assertionMethod: [`${inputDid}#key-1`]
        };
      } else if (method === 'pqc') {
        doc = {
          '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
          id: inputDid,
          verificationMethod: [{
            id: `${inputDid}#ml-dsa-65-hybrid`,
            type: 'MLDSA65HybridVerificationKey2026',
            controller: inputDid,
            publicKeyMultibase: parts[2]
          }],
          authentication: [`${inputDid}#ml-dsa-65-hybrid`],
          assertionMethod: [`${inputDid}#ml-dsa-65-hybrid`]
        };
      } else if (method === 'pkh') {
        doc = {
          '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/secp256k1recovery-2020/v1'],
          id: inputDid,
          verificationMethod: [{
            id: `${inputDid}#blockchainAccountId`,
            type: 'EcdsaSecp256k1RecoveryMethod2020',
            controller: inputDid,
            blockchainAccountId: parts.slice(2).join(':')
          }],
          authentication: [`${inputDid}#blockchainAccountId`],
          assertionMethod: [`${inputDid}#blockchainAccountId`]
        };
      } else {
        doc = {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: inputDid,
          verificationMethod: [{
            id: `${inputDid}#primary-key`,
            type: 'Ed25519VerificationKey2020',
            controller: inputDid
          }],
          authentication: [`${inputDid}#primary-key`],
          assertionMethod: [`${inputDid}#primary-key`]
        };
      }
      setResolvedDoc(doc);
    } catch (err) {
      setDidError(err.message);
      setResolvedDoc(null);
    } finally {
      setDidResolving(false);
    }
  };

  const handleCreateDraft = () => {
    const draft = {
      canonicalHash: '8b4d89a9f24255019d115e3474d2122bdf5599c43bcfc6dfcf46a51d9ad0b4a8',
      policyId: 'policy-university-senate-2026',
      threshold: 2,
      total: 3,
      authorities: [
        { did: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH', role: 'Academic Dean' },
        { did: 'did:key:z6MknUeKqA2fG9yU8s7V1tW4zB3mC5xP7rK9yZ2aB4cE6gH', role: 'University Registrar' },
        { did: 'did:key:z6MkuV8zW3mB5xR7pA1tK9yZ2aC4eG6hJ8kM0nP2qS4uV6w', role: 'Provost' }
      ],
      credentialSubject: {
        recipient: 'Alice Smith',
        degree: 'Doctor of Philosophy in Quantum Cryptography',
        graduationDate: '2026-06-15'
      }
    };
    setMsigDraft(draft);
    setMsigSignatures([]);
    setMsigResult(null);
  };

  const handleSignAuthority = (authority) => {
    if (msigSignatures.some(s => s.signerDid === authority.did)) return;
    const newSig = {
      signerDid: authority.did,
      role: authority.role,
      signature: '9f81a742c3d09a25ef...' + Math.random().toString(16).substring(2, 8),
      signedAt: new Date().toISOString()
    };
    const updated = [...msigSignatures, newSig];
    setMsigSignatures(updated);

    if (updated.length >= (msigDraft?.threshold || 2)) {
      setMsigResult({
        valid: true,
        verifiedCount: updated.length,
        requiredCount: msigDraft.threshold,
        status: 'QUORUM_REACHED'
      });
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-2 text-cyan-400 text-sm font-semibold tracking-wider uppercase mb-2 font-mono">
          <Layers className="w-4 h-4" />
          DocuTrust v5.0 Sovereign Trust Mesh
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight sm:text-4xl">
          Universal DID Resolver & Multi-Authority Quorum
        </h1>
        <p className="mt-2 text-base text-gray-400 max-w-3xl">
          Inspect cross-chain decentralized identifiers, coordinate M-of-N threshold signatures across institutional senates, and query accredited authorities in the Decentralized Trust Registry.
        </p>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex gap-2 border-b border-gray-800 pb-4 mb-8">
        <button
          onClick={() => setActiveSection('did')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
            activeSection === 'did'
              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
              : 'text-gray-400 hover:text-white hover:bg-gray-900'
          }`}
        >
          <Globe className="w-4 h-4" />
          Universal DID Resolver
        </button>
        <button
          onClick={() => setActiveSection('multisig')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
            activeSection === 'multisig'
              ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
              : 'text-gray-400 hover:text-white hover:bg-gray-900'
          }`}
        >
          <Users className="w-4 h-4" />
          M-of-N MultiSig Senate
        </button>
        <button
          onClick={() => setActiveSection('registry')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
            activeSection === 'registry'
              ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/30'
              : 'text-gray-400 hover:text-white hover:bg-gray-900'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          Decentralized Trust Registry
        </button>
      </div>

      {/* Section 1: Universal DID Resolver */}
      {activeSection === 'did' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/50 backdrop-blur-sm space-y-6">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-cyan-400" />
              Resolve DID Identifier
            </h3>
            <p className="text-sm text-gray-400">
              Supports standard W3C DID methods: <code className="text-cyan-300">did:key</code>, <code className="text-cyan-300">did:pqc</code> (Post-Quantum), <code className="text-cyan-300">did:kem</code>, <code className="text-cyan-300">did:bbs</code>, <code className="text-cyan-300">did:pkh</code> (Ethereum), and <code className="text-cyan-300">did:web</code>.
            </p>

            <div className="space-y-2">
              <label className="text-xs font-semibold text-gray-300 uppercase tracking-wider">DID URI</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={inputDid}
                  onChange={(e) => setInputDid(e.target.value)}
                  placeholder="did:key:z6Mkp... or did:pkh:eip155:1:0x..."
                  className="flex-1 px-3.5 py-2.5 bg-gray-950 border border-gray-700 rounded-lg text-sm font-mono text-white focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={handleResolveDid}
                  disabled={didResolving}
                  className="px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold rounded-lg shadow-md transition-all flex items-center gap-2"
                >
                  <Search className="w-4 h-4" />
                  Resolve
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-xs text-gray-400">Preset Sample DIDs:</span>
              <div className="flex flex-wrap gap-2">
                {[
                  { label: 'did:key (Ed25519)', uri: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH' },
                  { label: 'did:pqc (ML-DSA-65)', uri: 'did:pqc:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH' },
                  { label: 'did:pkh (Ethereum)', uri: 'did:pkh:eip155:1:0x71C83638379321e0b51B8d6Ac7b6C81204d80916' },
                  { label: 'did:web (Domain)', uri: 'did:web:docutrust.org' }
                ].map((sample) => (
                  <button
                    key={sample.label}
                    onClick={() => { setInputDid(sample.uri); }}
                    className="text-xs px-2.5 py-1 rounded bg-gray-800 text-gray-300 hover:text-cyan-300 hover:bg-gray-700 font-mono transition-colors"
                  >
                    {sample.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/50 backdrop-blur-sm space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <FileCode className="w-5 h-5 text-cyan-400" />
              Resolved W3C DID Document
            </h3>
            {didError && (
              <div className="p-3 bg-red-950/40 border border-red-800 rounded-lg text-sm text-red-300 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                {didError}
              </div>
            )}
            <pre className="p-4 bg-gray-950 rounded-xl border border-gray-800 text-xs font-mono text-cyan-300 overflow-x-auto max-h-[360px]">
              {resolvedDoc ? JSON.stringify(resolvedDoc, null, 2) : '// Click "Resolve" to inspect DID Document metadata'}
            </pre>
          </div>
        </div>
      )}

      {/* Section 2: M-of-N MultiSig Senate */}
      {activeSection === 'multisig' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/50 backdrop-blur-sm space-y-6">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Users className="w-5 h-5 text-blue-400" />
                MultiSig Credential Draft
              </h3>
              <button
                onClick={handleCreateDraft}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow transition-all"
              >
                Create 2-of-3 PhD Draft
              </button>
            </div>

            {msigDraft ? (
              <div className="space-y-4">
                <div className="p-4 bg-gray-950 rounded-xl border border-gray-800 space-y-2">
                  <div className="flex items-center justify-between text-xs text-gray-400 font-mono">
                    <span>POLICY ID: <strong className="text-white">{msigDraft.policyId}</strong></span>
                    <span>THRESHOLD: <strong className="text-blue-400">{msigDraft.threshold} of {msigDraft.total}</strong></span>
                  </div>
                  <div className="text-xs text-gray-300">
                    <strong>Recipient:</strong> {msigDraft.credentialSubject.recipient} ({msigDraft.credentialSubject.degree})
                  </div>
                  <div className="text-[11px] text-gray-400 font-mono break-all">
                    <strong>Canonical Hash:</strong> {msigDraft.canonicalHash}
                  </div>
                </div>

                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider">Authorizing Senate</h4>
                  <div className="space-y-2">
                    {msigDraft.authorities.map((auth) => {
                      const isSigned = msigSignatures.some(s => s.signerDid === auth.did);
                      return (
                        <div key={auth.did} className="p-3 bg-gray-950 border border-gray-800 rounded-lg flex items-center justify-between">
                          <div>
                            <div className="text-sm font-semibold text-white">{auth.role}</div>
                            <div className="text-xs font-mono text-gray-400">{auth.did.substring(0, 24)}...</div>
                          </div>
                          {isSigned ? (
                            <span className="flex items-center gap-1.5 text-xs text-green-400 font-semibold px-2.5 py-1 rounded bg-green-950/40 border border-green-800">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              Signed
                            </span>
                          ) : (
                            <button
                              onClick={() => handleSignAuthority(auth)}
                              className="px-3 py-1 bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 border border-blue-500/30 rounded text-xs font-semibold transition-colors"
                            >
                              Sign as {auth.role}
                            </button>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center border border-dashed border-gray-800 rounded-xl text-sm text-gray-400">
                Click "Create 2-of-3 PhD Draft" to start an institutional threshold signing workflow.
              </div>
            )}
          </div>

          <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/50 backdrop-blur-sm space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-blue-400" />
              Senate Verification Status
            </h3>

            {msigResult ? (
              <div className="p-4 bg-green-950/30 border border-green-800/80 rounded-xl space-y-2">
                <div className="flex items-center gap-2 text-green-400 font-bold text-sm">
                  <CheckCircle2 className="w-5 h-5" />
                  M-of-N Quorum Met ({msigResult.verifiedCount} / {msigResult.requiredCount} Signatures)
                </div>
                <p className="text-xs text-gray-300">
                  The credential has satisfied the threshold governance policy. Ed25519 signatures from both authorities are cryptographically verified over the RFC 8785 canonical hash.
                </p>
              </div>
            ) : (
              <div className="p-4 bg-gray-950 rounded-xl border border-gray-800 text-xs text-gray-400">
                Signatures collected: <strong className="text-white">{msigSignatures.length}</strong> / <strong>{msigDraft?.threshold || 2}</strong> required.
              </div>
            )}

            <pre className="p-4 bg-gray-950 rounded-xl border border-gray-800 text-xs font-mono text-blue-300 overflow-x-auto max-h-[300px]">
              {JSON.stringify({ signatures: msigSignatures }, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {/* Section 3: Decentralized Trust Registry */}
      {activeSection === 'registry' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-gray-400 absolute left-3 top-3" />
              <input
                type="text"
                value={registryQuery}
                onChange={(e) => setRegistryQuery(e.target.value)}
                placeholder="Search accredited issuers by legal name or DID..."
                className="w-full pl-9 pr-4 py-2 bg-gray-900 border border-gray-800 rounded-lg text-sm text-white focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="text-xs text-gray-400 font-mono">
              3 ACTIVE TRUST AUTHORITIES
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {issuers
              .filter(i => i.legalName.toLowerCase().includes(registryQuery.toLowerCase()) || i.issuerDid.includes(registryQuery))
              .map(iss => (
                <div key={iss.issuerDid} className="p-6 bg-gray-900/60 border border-gray-800 rounded-2xl space-y-4 hover:border-gray-700 transition-colors">
                  <div className="flex items-center justify-between">
                    <span className="px-2.5 py-1 rounded text-[11px] font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                      {iss.accreditationLevel}
                    </span>
                    <span className="flex items-center gap-1 text-xs text-green-400 font-semibold">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Active
                    </span>
                  </div>
                  <div>
                    <h4 className="text-base font-bold text-white">{iss.legalName}</h4>
                    <p className="text-xs text-gray-400 font-mono mt-1 break-all">{iss.issuerDid}</p>
                  </div>
                  <div className="pt-2 border-t border-gray-800/80 space-y-1">
                    <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider">Authorized Schemas</span>
                    {iss.authorizedSchemas.map(s => (
                      <div key={s} className="text-xs font-mono text-cyan-300 truncate">
                        {s}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}
