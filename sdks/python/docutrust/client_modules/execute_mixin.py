from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class ExecuteMixin:

    def execute_verifiable_compute(
        self,
        program: Dict[str, Any],
        inputs: Dict[str, Any],
        prover_key_pair: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Executes a deterministic AST program and generates execution trace & receipt."""
        from .verifiable_compute import VerifiableComputeEngine
        return VerifiableComputeEngine.execute_program(program, inputs, prover_key_pair)
