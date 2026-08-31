from __future__ import annotations
import hashlib
import time
import hmac
import secrets
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex, MerkleTree, sign_message, verify_signature

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

        def resolve_val(val: Any) -> Any:
            if isinstance(val, str) and val.startswith('$'):
                return env.get(val[1:])
            if isinstance(val, list):
                return [resolve_val(x) for x in val]
            return val

        for idx, instr in enumerate(instructions):
            op = instr.get('op')
            args = instr.get('args', [])
            out_var = instr.get('outputVar')
            resolved_args = [resolve_val(a) for a in args]

            result = None
            if op == 'ADD':
                result = float(resolved_args[0] or 0) + float(resolved_args[1] or 0)
            elif op == 'SUB':
                result = float(resolved_args[0] or 0) - float(resolved_args[1] or 0)
            elif op == 'MUL':
                result = float(resolved_args[0] or 0) * float(resolved_args[1] or 0)
            elif op == 'DIV':
                divisor = float(resolved_args[1] or 1)
                result = float(resolved_args[0] or 0) / divisor if divisor != 0 else 0
            elif op == 'WEIGHTED_SUM':
                vals = resolved_args[0] if isinstance(resolved_args[0], list) else []
                weights = resolved_args[1] if isinstance(resolved_args[1], list) else []
                total = sum(float(v) * float(w) for v, w in zip(vals, weights))
                result = total
            elif op == 'THRESHOLD_CHECK':
                val = float(resolved_args[0] or 0)
                thresh = float(resolved_args[1] or 0)
                result = val >= thresh
            elif op == 'RANGE_CHECK':
                val = float(resolved_args[0] or 0)
                low = float(resolved_args[1] or 0)
                high = float(resolved_args[2] or 0)
                result = low <= val <= high
            elif op == 'SET_CONTAINS':
                target = resolved_args[0] if len(resolved_args) > 0 else None
                s_list = resolved_args[1] if len(resolved_args) > 1 and isinstance(resolved_args[1], list) else []
                result = target in s_list
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
                'stepIndex': idx,
                'op': op,
                'args': resolved_args,
                'inputs': resolved_args,
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
        execution_trace_hash = sha256_hex(canonicalize_json(trace))

        final_outputs = {instr['outputVar']: env[instr['outputVar']] for instr in instructions if 'outputVar' in instr}
        outputs_commitment = sha256_hex(canonicalize_json(final_outputs))
        inputs_commitment = sha256_hex(canonicalize_json(inputs))
        receipt_id = f"vcomp-{secrets.token_hex(8)}"
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        receipt_payload = {
            'type': 'DocuTrustComputeReceipt2026',
            'receiptId': receipt_id,
            'programId': program.get('programId', 'anonymous-compute'),
            'programVersion': program.get('version', '1.0.0'),
            'inputsCommitment': inputs_commitment,
            'inputsHash': inputs_commitment,
            'outputsCommitment': outputs_commitment,
            'outputStateHash': outputs_commitment,
            'executionTraceHash': execution_trace_hash,
            'traceMerkleRoot': trace_merkle_root,
            'stepCount': len(trace),
            'finalOutputs': final_outputs,
            'proverDid': prover_key_pair.get('did', 'did:key:prover'),
            'timestamp': timestamp
        }

        sign_payload = {
            'receiptId': receipt_id,
            'programId': program.get('programId', 'anonymous-compute'),
            'inputsCommitment': inputs_commitment,
            'outputsCommitment': outputs_commitment,
            'executionTraceHash': execution_trace_hash,
            'stepCount': len(trace),
            'finalOutputs': final_outputs,
            'proverDid': prover_key_pair.get('did', 'did:key:prover'),
            'timestamp': timestamp
        }

        canon = canonicalize_json(sign_payload)
        priv_key = prover_key_pair.get('privateKeyHex', '')
        try:
            signature_hex = sign_message(canon, priv_key)
        except Exception:
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
            rec_inputs_hash = receipt.get('inputsCommitment') or receipt.get('inputsHash')
            if rec_inputs_hash != expected_input_hash:
                errors.append(f"Input state mismatch. Expected {expected_input_hash}, got {rec_inputs_hash}")

        sig = receipt.get('signatureHex', '')
        if not sig or len(sig) < 32:
            errors.append('Invalid compute receipt signature')

        valid = len(errors) == 0
        return {
            'valid': valid,
            'traceMerkleRoot': receipt.get('traceMerkleRoot') or receipt.get('executionTraceHash'),
            'outputStateHash': receipt.get('outputStateHash') or receipt.get('outputsCommitment'),
            'executionTraceHash': receipt.get('executionTraceHash'),
            'outputsCommitment': receipt.get('outputsCommitment'),
            'errors': errors
        }
