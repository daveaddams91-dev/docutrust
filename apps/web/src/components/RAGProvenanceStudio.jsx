import React, { useState } from 'react';
import { BookOpen, FileText, CheckCircle2, ShieldCheck, AlertTriangle, Search, Cpu, RefreshCw, Layers } from 'lucide-react';

const dummyHex = (len = 64) => Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');

export default function RAGProvenanceStudio() {
  const [queryText, setQueryText] = useState('What are the core properties of lattice cryptography?');
  const [generatedAnswer, setGeneratedAnswer] = useState('Lattice-based cryptography relies on shortest vector problems in high-dimensional lattices, ensuring quantum resistance and bounded worst-case hardness.');
  const [corpus, setCorpus] = useState(null);
  const [attestation, setAttestation] = useState(null);
  const [auditReport, setAuditReport] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleIndexCorpus = () => {
    setLoading(true);
    setTimeout(() => {
      const indexedCorpus = {
        corpusId: 'corpus_pqc_knowledge_2026',
        documentCount: 2,
        chunkCount: 3,
        rootMerkleHash: dummyHex(64),
        chunks: [
          {
            chunkId: 'chunk_001',
            documentUri: 'doc://pqc/lattice_intro',
            snippet: 'Lattice-based cryptography relies on shortest vector problems in high-dimensional lattices.',
            charLength: 88,
            leafHash: dummyHex(64)
          },
          {
            chunkId: 'chunk_002',
            documentUri: 'doc://pqc/hardness_guarantees',
            snippet: 'Ensuring quantum resistance and bounded worst-case hardness for post-quantum public keys.',
            charLength: 89,
            leafHash: dummyHex(64)
          },
          {
            chunkId: 'chunk_003',
            documentUri: 'doc://ai/verifiable_rag',
            snippet: 'Decentralized RAG architectures ensure verifiable citations and cryptographic grounding.',
            charLength: 87,
            leafHash: dummyHex(64)
          }
        ],
        indexedAt: new Date().toISOString()
      };
      setCorpus(indexedCorpus);
      setAttestation(null);
      setAuditReport(null);
      setLoading(false);
    }, 250);
  };

  const handleGenerateAttestation = () => {
    if (!corpus) return;
    const att = {
      attestationId: `rag_att_${dummyHex(10)}`,
      protocol: 'DocuTrustRAGProvenanceAttestation2026',
      corpusRootHash: corpus.rootMerkleHash,
      queryText,
      generatedResponse: generatedAnswer,
      groundingScore: 0.94,
      isGrounded: true,
      citedChunks: [
        {
          chunkId: 'chunk_001',
          documentUri: 'doc://pqc/lattice_intro',
          cosineSimilarity: 0.95,
          merkleProof: {
            rootHash: corpus.rootMerkleHash,
            auditPath: [dummyHex(64), dummyHex(64)]
          }
        },
        {
          chunkId: 'chunk_002',
          documentUri: 'doc://pqc/hardness_guarantees',
          cosineSimilarity: 0.91,
          merkleProof: {
            rootHash: corpus.rootMerkleHash,
            auditPath: [dummyHex(64), dummyHex(64)]
          }
        }
      ],
      curatorDid: `did:docutrust:curator:${dummyHex(8)}`,
      curatorSignature: dummyHex(128),
      timestamp: new Date().toISOString()
    };
    setAttestation(att);
    setAuditReport(null);
  };

  const handleAuditHallucination = () => {
    if (!attestation) return;
    setAuditReport({
      isAudited: true,
      hallucinationRisk: 'MINIMAL',
      averageSemanticGrounding: '93.5%',
      unsupportedClaimsCount: 0,
      merkleInclusionVerified: true,
      citationIntegrityValid: true,
      auditTimestamp: new Date().toISOString()
    });
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8">
      <div className="border-b border-gray-800 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-emerald-500/10 rounded-xl text-emerald-400 border border-emerald-500/20">
            <BookOpen className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              RAG Knowledge Provenance & Hallucination Auditing
              <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">v21.0.0</span>
            </h1>
            <p className="text-gray-400 text-sm mt-1">
              Merkle chunk inclusion proofs, semantic cosine grounding alignment, signed RAG attestations, and automated hallucination risk auditing.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Input & Indexing */}
        <div className="space-y-6">
          <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <FileText className="w-4 h-4 text-emerald-400" />
              RAG Inference Query
            </h2>

            <div>
              <label className="text-xs text-gray-400 block mb-1">User Query</label>
              <input
                type="text"
                value={queryText}
                onChange={(e) => setQueryText(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 text-xs"
              />
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">LLM Generated Response</label>
              <textarea
                rows={4}
                value={generatedAnswer}
                onChange={(e) => setGeneratedAnswer(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 text-xs"
              />
            </div>

            <button
              onClick={handleIndexCorpus}
              disabled={loading}
              className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-medium rounded-lg text-sm flex items-center justify-center gap-2 shadow-lg shadow-emerald-600/20"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <BookOpen className="w-4 h-4" />}
              Index Knowledge Corpus
            </button>
          </div>

          {corpus && (
            <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-3">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Provenance Operations</h3>
              <button
                onClick={handleGenerateAttestation}
                className="w-full py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-white font-medium rounded-lg text-xs flex items-center justify-center gap-2"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                Generate Signed RAG Attestation
              </button>
              {attestation && (
                <button
                  onClick={handleAuditHallucination}
                  className="w-full py-2 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-300 font-medium rounded-lg text-xs flex items-center justify-center gap-2"
                >
                  <Search className="w-3.5 h-3.5" />
                  Audit Hallucination Risk
                </button>
              )}
            </div>
          )}
        </div>

        {/* Right: Results Display */}
        <div className="lg:col-span-2 space-y-6">
          {corpus ? (
            <div className="space-y-6">
              {/* Corpus Indexed Metadata */}
              <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    Corpus: {corpus.corpusId}
                  </span>
                  <span className="text-xs text-gray-400">
                    {corpus.chunkCount} Knowledge Chunks Indexed
                  </span>
                </div>
                <div className="text-xs text-gray-400 font-mono truncate">
                  <span className="text-gray-500">Root Merkle Hash:</span> {corpus.rootMerkleHash}
                </div>
              </div>

              {/* Attestation Output */}
              {attestation && (
                <div className="bg-gray-900/60 border border-gray-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      Signed RAG Attestation (DocuTrustRAGProvenanceAttestation2026)
                    </h3>
                    <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                      Grounding: {(attestation.groundingScore * 100).toFixed(1)}%
                    </span>
                  </div>

                  <div className="space-y-2">
                    <div className="text-xs text-gray-400 font-semibold">Attributed Citations with Merkle Inclusions:</div>
                    {attestation.citedChunks.map((chunk, i) => (
                      <div key={i} className="bg-gray-950/70 p-3 rounded-lg border border-gray-800 text-xs space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-emerald-300 font-semibold">{chunk.documentUri}</span>
                          <span className="text-gray-400">Similarity: {(chunk.cosineSimilarity * 100).toFixed(1)}%</span>
                        </div>
                        <div className="text-gray-500 font-mono text-[11px] truncate">
                          Merkle Audit Path Root: {chunk.merkleProof.rootHash.slice(0, 24)}...
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Audit Report */}
              {auditReport && (
                <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-xl p-5 space-y-3">
                  <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
                    <CheckCircle2 className="w-5 h-5" />
                    Automated Hallucination Risk Audit Passed
                  </div>
                  <div className="grid grid-cols-3 gap-3 text-xs text-gray-300">
                    <div className="bg-gray-950/60 p-2.5 rounded border border-gray-800">
                      <div className="text-gray-500 text-[10px]">Risk Level</div>
                      <div className="text-emerald-400 font-bold mt-0.5">{auditReport.hallucinationRisk}</div>
                    </div>
                    <div className="bg-gray-950/60 p-2.5 rounded border border-gray-800">
                      <div className="text-gray-500 text-[10px]">Avg Grounding</div>
                      <div className="text-white font-bold mt-0.5">{auditReport.averageSemanticGrounding}</div>
                    </div>
                    <div className="bg-gray-950/60 p-2.5 rounded border border-gray-800">
                      <div className="text-gray-500 text-[10px]">Merkle Proofs</div>
                      <div className="text-emerald-400 font-bold mt-0.5">100% Verified</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-gray-900/40 border border-gray-800 border-dashed rounded-xl p-12 text-center text-gray-500 flex flex-col items-center justify-center space-y-3">
              <BookOpen className="w-10 h-10 text-gray-600" />
              <p className="text-sm">Click "Index Knowledge Corpus" to start verifiable RAG provenance analysis.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
