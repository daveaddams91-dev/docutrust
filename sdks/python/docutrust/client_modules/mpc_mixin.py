from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class MpcMixin:

    def mpc_garble_circuit(
        self,
        circuit_id: str,
        input_wires_garbler: List[str],
        input_wires_evaluator: List[str],
        output_wires: List[str],
        gates: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Garbles a Boolean logic circuit using Yao's Garbled Circuits protocol."""
        from .mpc_garbled_circuits import MPCGarbledCircuitEngine
        return MPCGarbledCircuitEngine.garble_circuit(
            circuit_id, input_wires_garbler, input_wires_evaluator, output_wires, gates
        )

    def mpc_init_oblivious_transfer(
        self,
        session_id: str,
        wire_zero_label: str,
        wire_one_label: str,
        evaluator_choice_bit: int = 0
    ) -> Dict[str, Any]:
        """Initializes a 1-out-of-2 Oblivious Transfer session for an evaluator input bit."""
        from .mpc_garbled_circuits import MPCGarbledCircuitEngine
        return MPCGarbledCircuitEngine.init_oblivious_transfer(
            session_id, wire_zero_label, wire_one_label, evaluator_choice_bit
        )

    def mpc_evaluate_circuit(
        self,
        circuit: Dict[str, Any],
        active_input_labels: Dict[str, str],
        garbler_did: str = "did:docutrust:garbler",
        evaluator_did: str = "did:docutrust:evaluator"
    ) -> Dict[str, Any]:
        """Evaluates a garbled circuit given active input wire labels."""
        from .mpc_garbled_circuits import MPCGarbledCircuitEngine
        return MPCGarbledCircuitEngine.evaluate_circuit(
            circuit, active_input_labels, garbler_did, evaluator_did
        )

    def mpc_verify_receipt(
        self,
        receipt: Dict[str, Any],
        expected_circuit_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies an MPC Garbled Circuit execution receipt."""
        from .mpc_garbled_circuits import MPCGarbledCircuitEngine
        return MPCGarbledCircuitEngine.verify_receipt(receipt, expected_circuit_hash)
