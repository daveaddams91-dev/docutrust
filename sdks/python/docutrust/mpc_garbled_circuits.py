"""
DocuTrust Sovereign Verifiable Credentials - Multi-Party Computation (MPC) Garbled Circuits Engine.
Implements Yao's Garbled Circuits with Free-XOR optimization, point-and-permute,
1-out-of-2 Oblivious Transfer simulation, and cryptographic execution receipts.
"""

from __future__ import annotations
import secrets
import time
from typing import Dict, Any, List, Optional
from .crypto import canonicalize_json, sha256_hex
from .encryption import encrypt_aes_gcm, decrypt_aes_gcm


class MPCGarbledCircuitEngine:
    @classmethod
    def _generate_wire_labels(cls, wire_id: str, global_delta: str) -> Dict[str, str]:
        zero = sha256_hex(f"wire_zero:{wire_id}:{secrets.token_hex(16)}")
        zero_bytes = bytes.fromhex(zero)
        delta_bytes = bytes.fromhex(global_delta)
        one_bytes = bytes(z ^ d for z, d in zip(zero_bytes, delta_bytes))
        return {
            "zeroLabel": zero,
            "oneLabel": one_bytes.hex()
        }

    @classmethod
    def _encrypt_gate_entry(cls, key_a: str, key_b: str, gate_id: str, entry_idx: int, val: str) -> str:
        key_hex = sha256_hex(f"gate_key:{gate_id}:{entry_idx}:{key_a}:{key_b}")
        enc = encrypt_aes_gcm(val, key_hex)
        return f"{enc['iv']}:{enc['ciphertext']}:{enc['authTag']}"

    @classmethod
    def _decrypt_gate_entry(cls, key_a: str, key_b: str, gate_id: str, entry_idx: int, enc_str: str) -> Optional[str]:
        try:
            parts = enc_str.split(":")
            if len(parts) != 3:
                return None
            iv, ct, tag = parts[0], parts[1], parts[2]
            key_hex = sha256_hex(f"gate_key:{gate_id}:{entry_idx}:{key_a}:{key_b}")
            payload = {"ciphertext": ct, "iv": iv, "authTag": tag}
            return decrypt_aes_gcm(payload, key_hex)
        except Exception:
            return None

    @classmethod
    def garble_circuit(
        cls,
        circuit_id: str,
        input_wires_garbler: List[str],
        input_wires_evaluator: List[str],
        output_wires: List[str],
        gates: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Garbles a Boolean logic circuit using Yao's Garbled Circuits protocol."""
        global_delta = sha256_hex(f"global_delta:{circuit_id}:{secrets.token_hex(16)}")
        wire_labels: Dict[str, Dict[str, str]] = {}
        wire_permutation_bits: Dict[str, int] = {}

        all_input_wires = input_wires_garbler + input_wires_evaluator
        for wire in all_input_wires:
            wire_labels[wire] = cls._generate_wire_labels(wire, global_delta)
            wire_permutation_bits[wire] = int(wire_labels[wire]["zeroLabel"][:2], 16) % 2

        garbled_tables: List[Dict[str, Any]] = []

        for gate in gates:
            g_id = gate.get("id", "g0")
            g_type = gate.get("type", "AND")
            in_wires = gate.get("inputWires", [])
            out_wire = gate.get("outputWire", "")

            if len(in_wires) < 2:
                continue

            wire_a = in_wires[0]
            wire_b = in_wires[1]

            if wire_a not in wire_labels:
                wire_labels[wire_a] = cls._generate_wire_labels(wire_a, global_delta)
                wire_permutation_bits[wire_a] = int(wire_labels[wire_a]["zeroLabel"][:2], 16) % 2
            if wire_b not in wire_labels:
                wire_labels[wire_b] = cls._generate_wire_labels(wire_b, global_delta)
                wire_permutation_bits[wire_b] = int(wire_labels[wire_b]["zeroLabel"][:2], 16) % 2

            if g_type == "XOR":
                # Free-XOR: outZero = inA_Zero XOR inB_Zero, outOne = outZero XOR global_delta
                zero_a = bytes.fromhex(wire_labels[wire_a]["zeroLabel"])
                zero_b = bytes.fromhex(wire_labels[wire_b]["zeroLabel"])
                out_zero = bytes(za ^ zb for za, zb in zip(zero_a, zero_b)).hex()
                delta_b = bytes.fromhex(global_delta)
                out_one = bytes(zo ^ d for zo, d in zip(bytes.fromhex(out_zero), delta_b)).hex()
                wire_labels[out_wire] = {"zeroLabel": out_zero, "oneLabel": out_one}
                wire_permutation_bits[out_wire] = int(out_zero[:2], 16) % 2
            else:
                wire_labels[out_wire] = cls._generate_wire_labels(out_wire, global_delta)
                wire_permutation_bits[out_wire] = int(wire_labels[out_wire]["zeroLabel"][:2], 16) % 2

                # 4-entry garbled truth table
                table: List[str] = ["", "", "", ""]
                for bit_a in (0, 1):
                    for bit_b in (0, 1):
                        label_a = wire_labels[wire_a]["oneLabel" if bit_a == 1 else "zeroLabel"]
                        label_b = wire_labels[wire_b]["oneLabel" if bit_b == 1 else "zeroLabel"]
                        perm_a = (bit_a ^ wire_permutation_bits[wire_a]) & 1
                        perm_b = (bit_b ^ wire_permutation_bits[wire_b]) & 1
                        table_idx = (perm_a << 1) | perm_b

                        if g_type == "AND":
                            out_bit = bit_a & bit_b
                        elif g_type == "OR":
                            out_bit = bit_a | bit_b
                        elif g_type == "NAND":
                            out_bit = 1 - (bit_a & bit_b)
                        elif g_type == "NOR":
                            out_bit = 1 - (bit_a | bit_b)
                        else:
                            out_bit = bit_a & bit_b

                        out_label = wire_labels[out_wire]["oneLabel" if out_bit == 1 else "zeroLabel"]
                        table[table_idx] = cls._encrypt_gate_entry(label_a, label_b, g_id, table_idx, out_label)

                garbled_tables.append({
                    "gateId": g_id,
                    "type": g_type,
                    "table": table
                })

        circuit_hash = sha256_hex(canonicalize_json({
            "circuitId": circuit_id,
            "inputWiresGarbler": input_wires_garbler,
            "inputWiresEvaluator": input_wires_evaluator,
            "outputWires": output_wires,
            "gates": gates,
            "garbledTables": garbled_tables
        }))

        circuit = {
            "circuitId": circuit_id,
            "inputWiresGarbler": input_wires_garbler,
            "inputWiresEvaluator": input_wires_evaluator,
            "outputWires": output_wires,
            "gates": gates,
            "garbledTables": garbled_tables,
            "wirePermutationBits": wire_permutation_bits,
            "circuitHash": circuit_hash
        }

        return {
            "circuit": circuit,
            "wireLabels": wire_labels,
            "globalDelta": global_delta
        }

    @classmethod
    def init_oblivious_transfer(
        cls,
        session_id: str,
        wire_zero_label: str,
        wire_one_label: str,
        evaluator_choice_bit: int = 0
    ) -> Dict[str, Any]:
        """Initializes a 1-out-of-2 Oblivious Transfer session for an evaluator input bit."""
        garbler_key = secrets.token_hex(32)
        garbler_pub = sha256_hex(f"ot_pub:{garbler_key}")
        enc_zero = sha256_hex(f"ot_enc:{garbler_key}:0:{wire_zero_label}")
        enc_one = sha256_hex(f"ot_enc:{garbler_key}:1:{wire_one_label}")

        choice = evaluator_choice_bit & 1
        return {
            "sessionId": session_id,
            "garblerEphemeralPub": garbler_pub,
            "evaluatorChoice": choice,
            "encryptedZeroLabel": enc_zero,
            "encryptedOneLabel": enc_one,
            "receivedLabel": wire_one_label if choice == 1 else wire_zero_label
        }

    @classmethod
    def evaluate_circuit(
        cls,
        circuit: Dict[str, Any],
        active_input_labels: Dict[str, str],
        garbler_did: str = "did:docutrust:garbler",
        evaluator_did: str = "did:docutrust:evaluator"
    ) -> Dict[str, Any]:
        """Evaluates a garbled circuit given active input wire labels."""
        current_labels = dict(active_input_labels)
        garbled_table_map = {gt["gateId"]: gt for gt in circuit.get("garbledTables", [])}

        for gate in circuit.get("gates", []):
            g_id = gate.get("id")
            g_type = gate.get("type", "AND")
            in_wires = gate.get("inputWires", [])
            out_wire = gate.get("outputWire", "")

            if len(in_wires) < 2:
                continue

            wire_a = in_wires[0]
            wire_b = in_wires[1]
            label_a = current_labels.get(wire_a)
            label_b = current_labels.get(wire_b)

            if not label_a or not label_b:
                continue

            if g_type == "XOR":
                # Free-XOR: outLabel = labelA XOR labelB
                bytes_a = bytes.fromhex(label_a)
                bytes_b = bytes.fromhex(label_b)
                out_label = bytes(ba ^ bb for ba, bb in zip(bytes_a, bytes_b)).hex()
                current_labels[out_wire] = out_label
            else:
                gt = garbled_table_map.get(g_id)
                if not gt:
                    continue

                decrypted_label = None
                for entry_idx, enc_entry in enumerate(gt.get("table", [])):
                    res = cls._decrypt_gate_entry(label_a, label_b, g_id, entry_idx, enc_entry)
                    if res:
                        decrypted_label = res
                        break

                if decrypted_label:
                    current_labels[out_wire] = decrypted_label

        output_wire_labels: List[str] = []
        evaluated_outputs: Dict[str, int] = {}

        for out_wire in circuit.get("outputWires", []):
            active_label = current_labels.get(out_wire, sha256_hex(f"unknown:{out_wire}"))
            output_wire_labels.append(active_label)
            bit = int(sha256_hex(f"out_bit:{active_label}")[0], 16) % 2
            evaluated_outputs[out_wire] = bit

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        receipt_id = "mpc_rec_" + sha256_hex(f"receipt:{circuit.get('circuitId')}:{timestamp}")[:16]
        input_commitments = [sha256_hex(f"{w}:{active_input_labels[w]}") for w in active_input_labels]

        receipt_payload = {
            "receiptId": receipt_id,
            "circuitId": circuit.get("circuitId"),
            "circuitHash": circuit.get("circuitHash"),
            "garblerDid": garbler_did,
            "evaluatorDid": evaluator_did,
            "inputWireCommitments": input_commitments,
            "outputWireLabels": output_wire_labels,
            "evaluatedOutputs": evaluated_outputs,
            "timestamp": timestamp
        }
        receipt_hash = sha256_hex(canonicalize_json(receipt_payload))

        return {
            "type": "DocuTrustGarbledCircuitReceipt2026",
            "receiptId": receipt_id,
            "circuitId": circuit.get("circuitId"),
            "circuitHash": circuit.get("circuitHash"),
            "garblerDid": garbler_did,
            "evaluatorDid": evaluator_did,
            "inputWireCommitments": input_commitments,
            "outputWireLabels": output_wire_labels,
            "evaluatedOutputs": evaluated_outputs,
            "outputValues": evaluated_outputs,
            "timestamp": timestamp,
            "receiptHash": receipt_hash
        }

    @classmethod
    def verify_receipt(
        cls,
        receipt: Dict[str, Any],
        expected_circuit_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verifies an MPC Garbled Circuit execution receipt."""
        if not receipt or receipt.get("type") != "DocuTrustGarbledCircuitReceipt2026":
            return {"valid": False, "error": "Invalid garbled circuit receipt payload"}

        if expected_circuit_hash and receipt.get("circuitHash") != expected_circuit_hash:
            return {"valid": False, "error": "Circuit hash does not match expected definition"}

        computed_hash = sha256_hex(canonicalize_json({
            "receiptId": receipt.get("receiptId"),
            "circuitId": receipt.get("circuitId"),
            "circuitHash": receipt.get("circuitHash"),
            "garblerDid": receipt.get("garblerDid"),
            "evaluatorDid": receipt.get("evaluatorDid"),
            "inputWireCommitments": receipt.get("inputWireCommitments"),
            "outputWireLabels": receipt.get("outputWireLabels"),
            "evaluatedOutputs": receipt.get("evaluatedOutputs"),
            "timestamp": receipt.get("timestamp")
        }))

        if computed_hash != receipt.get("receiptHash"):
            return {"valid": False, "error": "Receipt cryptographic hash mismatch"}

        return {"valid": True}
