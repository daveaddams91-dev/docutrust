from __future__ import annotations
import hashlib
import time
import hmac
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex, MerkleTree

class VerifiableComputeEngine:
    """Deterministic Off-Chain Compute Engine with Cryptographic Step Traces and Execution Receipts."""

    @staticmethod
    def execute_program(
        program: Dict[str, Any],
        inputs: Dict[str, Any],
        prover_key_pair: Dict[str, Any]
    ) -> Dict[str, Any]:
        env = dict(inputs)
        trace = []
        instructions = program.get('instructions', [])

        for idx, instr in enumerate(instructions):
            op = instr.get('op')
            args = instr.get('args', [])
            out_var = instr.get('outputVar')

            resolved_args = []
            for arg in args:
                if isinstance(arg, str) and arg.startswith('$'):
                    var_name = arg[1:]
                    resolved_args.append(env.get(var_name))
                elif isinstance(arg, list):
                    resolved_list = []
                    for item in arg:
                        if isinstance(item, str) and item.startswith('$'):
                            resolved_list.append(env.get(item[1:]))
                        else:
                            resolved_list.append(item)
                    resolved_args.append(resolved_list)
                else:
                    resolved_args.append(arg)

            result = None
            if op == 'ADD':
                result = (resolved_args[0] or 0) + (resolved_args[1] or 0)
            elif op == 'SUB':
                result = (resolved_args[0] or 0) - (resolved_args[1] or 0)
            elif op == 'MUL':
                result = (resolved_args[0] or 0) * (resolved_args[1] or 0)
            elif op == 'DIV':
                divisor = resolved_args[1] or 1
                result = (resolved_args[0] or 0) / divisor if divisor != 0 else 0
            elif op == 'WEIGHTED_SUM':
                vals = resolved_args[0] or []
                weights = resolved_args[1] or []
                total = sum(v * w for v, w in zip(vals, weights))
                result = total
            elif op == 'THRESHOLD_CHECK':
                val = resolved_args[0] or 0
                thresh = resolved_args[1] or 0
                result = val >= thresh
            elif op == 'RANGE_CHECK':
                val = resolved_args[0] or 0
                low = resolved_args[1] or 0
                high = resolved_args[2] or 0
                result = low <= val <= high
            elif op == 'HASH_CHAIN':
                val = str(resolved_args[0])
                rounds = int(resolved_args[1] or 1)
                curr = val
                for _ in range(rounds):
                    curr = sha256_hex(curr)
                result = curr
            else:
                result = resolved_args[0] if resolved_args else None

            if out_var:
                env[out_var] = result

            step_record = {
                'step': idx + 1,
                'op': op,
                'args': resolved_args,
                'outputVar': out_var,
                'result': result,
                'stepHash': sha256_hex(canonicalize_json({
                    'step': idx + 1,
                    'op': op,
                    'args': resolved_args,
                    'outputVar': out_var,
                    'result': result
                }))
            }
            trace.append(step_record)

        step_hashes = [s['stepHash'] for s in trace]
        if not step_hashes:
            step_hashes = [sha256_hex('EMPTY_TRACE')]
        
        merkle = MerkleTree(step_hashes)
        trace_merkle_root = merkle.get_root()

        final_outputs = {k: v for k, v in env.items() if k not in inputs}
        output_state_hash = sha256_hex(canonicalize_json(final_outputs))

        receipt_payload = {
            'type': 'DocuTrustComputeReceipt2026',
            'programId': program.get('programId', 'anonymous-compute'),
            'programVersion': program.get('version', '1.0.0'),
            'inputsHash': sha256_hex(canonicalize_json(inputs)),
            'outputStateHash': output_state_hash,
            'traceMerkleRoot': trace_merkle_root,
            'stepCount': len(trace),
            'proverDid': prover_key_pair.get('did', 'did:key:prover'),
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

        canon = canonicalize_json(receipt_payload)
        priv_key = prover_key_pair.get('privateKeyHex', '')
        signature_hex = hmac.new(priv_key.encode('utf-8'), canon.encode('utf-8'), hashlib.sha256).hexdigest()

        return {
            'finalOutputs': final_outputs,
            'trace': trace,
            'receipt': {
                **receipt_payload,
                'signatureHex': signature_hex
            }
        }

    @staticmethod
    def verify_compute_receipt(
        receipt: Dict[str, Any],
        prover_public_key: str,
        inputs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        errors = []
        if receipt.get('type') != 'DocuTrustComputeReceipt2026':
            errors.append('Invalid receipt type. Expected DocuTrustComputeReceipt2026')

        if inputs is not None:
            expected_input_hash = sha256_hex(canonicalize_json(inputs))
            if receipt.get('inputsHash') != expected_input_hash:
                errors.append(f"Input state mismatch. Expected {expected_input_hash}, got {receipt.get('inputsHash')}")

        sig = receipt.get('signatureHex', '')
        if not sig or len(sig) < 32:
            errors.append('Invalid compute receipt signature')

        valid = len(errors) == 0
        return {
            'valid': valid,
            'traceMerkleRoot': receipt.get('traceMerkleRoot'),
            'outputStateHash': receipt.get('outputStateHash'),
            'errors': errors
        }
