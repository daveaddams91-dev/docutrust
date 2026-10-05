from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class StarkMixin:

    def stark_generate_trace(
        self,
        steps: int = 8,
        initial_state: Optional[List[int]] = None,
        transition_type: str = "fibonacci"
    ) -> Dict[str, Any]:
        """Generates an AIR execution trace table for STARK synthesis."""
        from .stark_fri import STARKEngine
        return STARKEngine.generate_air_trace(steps, initial_state, transition_type)

    def stark_generate_proof(
        self,
        trace: Dict[str, Any],
        num_queries: int = 4
    ) -> Dict[str, Any]:
        """Generates a Transparent STARK proof with FRI polynomial folding layers."""
        from .stark_fri import STARKEngine
        return STARKEngine.generate_stark_proof(trace, num_queries)

    def stark_verify_proof(
        self,
        proof: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verifies a Transparent STARK proof."""
        from .stark_fri import STARKEngine
        return STARKEngine.verify_stark_proof(proof)
