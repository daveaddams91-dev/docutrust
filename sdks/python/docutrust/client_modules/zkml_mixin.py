from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class ZkmlMixin:

    def zkml_commit_model(
        self,
        model_id: str,
        architecture: str,
        layers: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Commits neural network weights and architecture into a Merkle-like root."""
        from .zkml_inference import ZKMLEngine
        return ZKMLEngine.commit_model_weights(model_id, architecture, layers)

    def zkml_prove_inference(
        self,
        model_id: str,
        weight_commitment: Dict[str, Any],
        layers: List[Dict[str, Any]],
        input_data: List[float]
    ) -> Dict[str, Any]:
        """Generates a zero-knowledge inference trace and proof."""
        from .zkml_inference import ZKMLEngine
        return ZKMLEngine.prove_inference(model_id, weight_commitment, layers, input_data)

    def zkml_verify_inference(
        self,
        proof: Dict[str, Any],
        expected_weight_root: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies a zkML inference proof."""
        from .zkml_inference import ZKMLEngine
        return ZKMLEngine.verify_inference_proof(proof, expected_weight_root)

    def zkml_export_solidity_calldata(
        self,
        proof: Dict[str, Any]
    ) -> Dict[str, str]:
        """Synthesizes EVM calldata for on-chain verification."""
        from .zkml_inference import ZKMLEngine
        return ZKMLEngine.export_solidity_calldata(proof)
