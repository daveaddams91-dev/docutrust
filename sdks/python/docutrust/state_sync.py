from __future__ import annotations
import hashlib
import time
import hmac
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex

class StateSyncEngine:
    """Compact O(Delta) Cross-Ledger State Synchronization and Reconciliation Engine."""

    @staticmethod
    def compute_state_root(state: Dict[str, Any]) -> str:
        keys = sorted(state.keys())
        leaves = [sha256_hex(canonicalize_json({'k': k, 'v': state[k]})) for k in keys]
        if not leaves:
            return sha256_hex('EMPTY_STATE')
        
        current = leaves
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                combined = sha256_hex(left + right)
                next_level.append(combined)
            current = next_level
        return current[0]

    @staticmethod
    def generate_delta_proof(
        base_state: Dict[str, Any],
        target_state: Dict[str, Any],
        relayer_key_pair: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        options = options or {}
        route = {
            'source': options.get('source', 'Mesh:Source'),
            'destination': options.get('destination', 'Mesh:Destination')
        }

        base_root = StateSyncEngine.compute_state_root(base_state)
        target_root = StateSyncEngine.compute_state_root(target_state)

        upserted_keys = []
        deleted_keys = []

        for k, v in target_state.items():
            if k not in base_state or canonicalize_json(base_state[k]) != canonicalize_json(v):
                upserted_keys.append(k)

        for k in base_state:
            if k not in target_state:
                deleted_keys.append(k)

        ops = []
        for k in upserted_keys:
            ops.append({
                'type': 'UPSERT',
                'key': k,
                'value': target_state[k],
                'valueHash': sha256_hex(canonicalize_json(target_state[k]))
            })

        for k in deleted_keys:
            ops.append({
                'type': 'DELETE',
                'key': k,
                'valueHash': sha256_hex('DELETED')
            })

        ops_root = sha256_hex(canonicalize_json(ops))

        proof_payload = {
            'type': 'DocuTrustStateDeltaProof2026',
            'sourceChain': route['source'],
            'destinationChain': route['destination'],
            'baseStateRoot': base_root,
            'targetStateRoot': target_root,
            'deltaOperationsCount': len(ops),
            'operationsRoot': ops_root,
            'operations': ops,
            'relayerDid': relayer_key_pair.get('did', 'did:key:relayer'),
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

        canon = canonicalize_json(proof_payload)
        priv_key = relayer_key_pair.get('privateKeyHex', '')
        signature_hex = hmac.new(priv_key.encode('utf-8'), canon.encode('utf-8'), hashlib.sha256).hexdigest()

        return {
            **proof_payload,
            'signatureHex': signature_hex
        }

    @staticmethod
    def verify_and_reconcile(
        base_state: Dict[str, Any],
        delta_proof: Dict[str, Any],
        relayer_public_key: str
    ) -> Dict[str, Any]:
        errors = []
        if delta_proof.get('type') != 'DocuTrustStateDeltaProof2026':
            errors.append('Invalid proof type. Expected DocuTrustStateDeltaProof2026')

        computed_base_root = StateSyncEngine.compute_state_root(base_state)
        if computed_base_root != delta_proof.get('baseStateRoot'):
            errors.append(f"Base state root mismatch. Computed {computed_base_root}, proof specifies {delta_proof.get('baseStateRoot')}")

        sig = delta_proof.get('signatureHex', '')
        if not sig or len(sig) < 32:
            errors.append('Invalid relayer delta proof signature')

        working_state = dict(base_state)
        for op in delta_proof.get('operations', []):
            op_type = op.get('type')
            k = op.get('key')
            if op_type == 'UPSERT':
                working_state[k] = op.get('value')
            elif op_type == 'DELETE':
                working_state.pop(k, None)

        reconciled_target_root = StateSyncEngine.compute_state_root(working_state)
        if reconciled_target_root != delta_proof.get('targetStateRoot'):
            errors.append(f"Target state root mismatch after applying delta ops. Computed {reconciled_target_root}, proof expects {delta_proof.get('targetStateRoot')}")

        valid = len(errors) == 0
        return {
            'valid': valid,
            'reconciledTargetRoot': reconciled_target_root,
            'deltaAppliedCount': len(delta_proof.get('operations', [])),
            'errors': errors
        }
