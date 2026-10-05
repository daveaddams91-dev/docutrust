from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class MemoryMixin:

    def memory_quarantine_detect(
        self,
        nodes: List[Dict[str, Any]],
        ground_truth_baselines: Optional[List[Dict[str, Any]]] = None,
        threshold: float = 0.65
    ) -> List[Dict[str, Any]]:
        """Scans memory nodes against baseline embeddings to detect semantic drift."""
        from .memory_quarantine import MemoryQuarantineEngine
        return MemoryQuarantineEngine.detect_anomalies(nodes, ground_truth_baselines, threshold)

    def memory_quarantine_issue_certificate(
        self,
        agent_did: str,
        quarantined_nodes: List[Dict[str, Any]],
        boundary_node_ids: Optional[List[str]] = None,
        issuer_secret_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Issues a cryptographic quarantine certificate isolating compromised memory nodes."""
        from .memory_quarantine import MemoryQuarantineEngine
        return MemoryQuarantineEngine.issue_quarantine_certificate(
            agent_did, quarantined_nodes, boundary_node_ids, issuer_secret_key_hex
        )

    def memory_quarantine_rollback(
        self,
        full_graph: Dict[str, Any],
        quarantine_cert: Dict[str, Any],
        clean_nodes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generates a zero-knowledge verifiable rollback proof demonstrating state recovery."""
        from .memory_quarantine import MemoryQuarantineEngine
        return MemoryQuarantineEngine.generate_rollback_proof(full_graph, quarantine_cert, clean_nodes)
