from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class RagMixin:

    def rag_provenance_index_corpus(
        self,
        corpus_id: str,
        documents: List[Dict[str, str]],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Indexes knowledge documents into Merkleized chunk nodes."""
        from .rag_provenance import RAGProvenanceEngine
        return RAGProvenanceEngine.index_corpus(corpus_id, documents, options)

    def rag_provenance_attest(
        self,
        corpus: Dict[str, Any],
        query_text: str,
        generated_response: str,
        claimed_citations: List[Dict[str, Any]],
        curator_key_pair: Dict[str, str]
    ) -> Dict[str, Any]:
        """Creates a signed RAG Knowledge Provenance Attestation with Merkle inclusion and cosine similarity."""
        from .rag_provenance import RAGProvenanceEngine
        return RAGProvenanceEngine.attest_provenance(corpus, query_text, generated_response, claimed_citations, curator_key_pair)

    def rag_provenance_verify_attestation(
        self,
        attestation: Dict[str, Any],
        expected_corpus_root_hash: str,
        signer_public_key_hex: str
    ) -> bool:
        """Cryptographically validates RAG provenance attestation signature and Merkle root."""
        from .rag_provenance import RAGProvenanceEngine
        return RAGProvenanceEngine.verify_attestation(attestation, expected_corpus_root_hash, signer_public_key_hex)

    def rag_provenance_audit_hallucination(
        self,
        attestation: Dict[str, Any],
        similarity_threshold: float = 0.5
    ) -> Dict[str, Any]:
        """Audits hallucination risk based on citation grounding scores."""
        from .rag_provenance import RAGProvenanceEngine
        return RAGProvenanceEngine.audit_hallucination_risk(attestation, similarity_threshold)
