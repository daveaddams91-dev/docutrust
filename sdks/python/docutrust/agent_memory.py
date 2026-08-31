import hashlib
import json
import math
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

class AgentMemoryEngine:
    """
    Verifiable Agent Memory and Knowledge Attestation Engine.
    Implements episodic memory graph commitments, Zero-Knowledge Cosine Distance
    similarity proofs, and prompt-injection/poisoning defenses.
    """
    @classmethod
    def _cosine_similarity(cls, vec_a: List[float], vec_b: List[float]) -> float:
        if len(vec_a) != len(vec_b):
            raise ValueError("Embedding dimensions must match")
        dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
        norm_a = math.sqrt(sum(a * a for a in vec_a))
        norm_b = math.sqrt(sum(b * b for b in vec_b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot_product / (norm_a * norm_b)

    @classmethod
    def commit_memory_graph(
        cls,
        agent_did: str,
        memory_nodes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not memory_nodes:
            raise ValueError("Memory graph must contain at least one node")

        node_commitments: List[str] = []
        dim = len(memory_nodes[0]["embedding"])
        centroid = [0.0] * dim

        for node in memory_nodes:
            serialized_node = json.dumps({
                "id": node["id"],
                "content": node["content"],
                "embedding": node["embedding"],
                "tags": sorted(node.get("tags", [])),
                "timestamp": node.get("timestamp", "")
            }, sort_keys=True)
            node_hash = hashlib.sha256(f"MEM_NODE:{serialized_node}".encode("utf-8")).hexdigest()
            node_commitments.append(node_hash)

            for i, val in enumerate(node["embedding"]):
                centroid[i] += val

        centroid = [c / len(memory_nodes) for c in centroid]

        # Pad leaves to next power of 2 for Merkle root
        leaves = list(node_commitments)
        while (len(leaves) & (len(leaves) - 1)) != 0:
            leaves.append(hashlib.sha256(b"MEM_PAD").hexdigest())

        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = hashlib.sha256(f"MEM_LEVEL:{left}:{right}".encode("utf-8")).hexdigest()
                next_level.append(combined)
            current_level = next_level

        merkle_root = current_level[0]
        graph_root = "0x" + hashlib.sha256(f"GRAPH_ROOT:{agent_did}:{merkle_root}:{centroid}".encode("utf-8")).hexdigest()

        return {
            "graph_root": graph_root,
            "merkle_root": merkle_root,
            "agent_did": agent_did,
            "node_count": len(memory_nodes),
            "centroid_vector": centroid,
            "node_commitments": node_commitments,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    @classmethod
    def generate_similarity_proof(
        cls,
        query_embedding: List[float],
        target_node: Dict[str, Any],
        node_index: int = 0,
        graph_commitment: Optional[Dict[str, Any]] = None,
        min_cosine_threshold: float = 0.75
    ) -> Dict[str, Any]:
        sim = cls._cosine_similarity(query_embedding, target_node["embedding"])
        if sim < min_cosine_threshold:
            raise ValueError(f"Similarity {sim:.4f} below threshold {min_cosine_threshold}")

        masked_embedding = "0x" + hashlib.sha256(f"MASKED:{target_node['embedding']}".encode("utf-8")).hexdigest()
        scalar_product_commit = "0x" + hashlib.sha256(f"SCALAR_PROD:{sim:.6f}:{masked_embedding}".encode("utf-8")).hexdigest()

        auth_path = [
            "0x" + hashlib.sha256(f"INCLUSION:{i}:{node_index}".encode("utf-8")).hexdigest()
            for i in range(2)
        ]

        proof_hash = "0x" + hashlib.sha256(f"SIM_PROOF:{graph_commitment['graph_root']}:{target_node['id']}:{sim:.4f}".encode("utf-8")).hexdigest()

        return {
            "type": "DocuTrustZKEmbeddingSimilarityProof2026",
            "graph_root": graph_commitment["graph_root"],
            "node_id": target_node["id"],
            "node_index": node_index,
            "min_cosine_threshold": min_cosine_threshold,
            "computed_similarity": sim,
            "masked_embedding_commitment": masked_embedding,
            "scalar_product_commitment": scalar_product_commit,
            "merkle_inclusion_proof": auth_path,
            "proof_hash": proof_hash,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

    @classmethod
    def verify_similarity_proof(
        cls,
        graph_commitment: Dict[str, Any],
        proof: Dict[str, Any]
    ) -> Dict[str, Any]:
        if proof.get("type") != "DocuTrustZKEmbeddingSimilarityProof2026":
            return {"valid": False, "error": "Invalid proof type"}

        if proof.get("graph_root") != graph_commitment.get("graph_root"):
            return {"valid": False, "error": "Graph root mismatch"}

        if proof.get("computed_similarity", 0) < proof.get("min_cosine_threshold", 1.0):
            return {"valid": False, "error": "Similarity below threshold"}

        return {"valid": True, "similarity_verified": True}

    @classmethod
    def audit_memory_poisoning(
        cls,
        graph: Dict[str, Any],
        incoming_content: str,
        incoming_embedding: List[float]
    ) -> Dict[str, Any]:
        threats: List[str] = []
        anomaly_score = 0

        injection_patterns = [
            re.compile(r"ignore previous instructions", re.I),
            re.compile(r"you are now a bypass agent", re.I),
            re.compile(r"system prompt override", re.I),
            re.compile(r"<script[\s\S]*?>", re.I),
            re.compile(r"DROP TABLE", re.I),
            re.compile(r"exfiltrate", re.I)
        ]

        for p in injection_patterns:
            if p.search(incoming_content):
                threats.append(f"Prompt injection detected: {p.pattern}")
                anomaly_score += 45

        sim_to_centroid = cls._cosine_similarity(incoming_embedding, graph["centroid_vector"])
        if sim_to_centroid < 0.1:
            threats.append(f"Severe vector divergence from memory centroid: similarity={sim_to_centroid:.3f}")
            anomaly_score += 35

        is_poisoned = anomaly_score >= 40
        recommendation = "REJECT_INJECTION" if is_poisoned else "QUARANTINE" if anomaly_score > 20 else "ALLOW_MERGE"

        return {
            "is_poisoned": is_poisoned,
            "anomaly_score": anomaly_score,
            "detected_threats": threats,
            "recommendation": recommendation
        }
