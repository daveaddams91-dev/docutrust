from __future__ import annotations
import secrets
import time
from typing import Dict, Any, List, Optional
from .crypto import canonicalize_json, sha256_hex, sign_message, verify_signature

class RevocationLatticeEngine:
    """
    2D Multi-Epoch Revocation Lattice & Dynamic Accumulator Engine (DocuTrust v13.0.0).
    Manages temporal-spatial lattice revocation slices and generates O(1) non-revocation witnesses.
    """

    @classmethod
    def initialize_lattice(cls, lattice_id: str, issuer_did: str, shards_count: int = 4) -> Dict[str, Any]:
        epochs: Dict[str, Any] = {}
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        for s in range(shards_count):
            key = f"0_{s}"
            acc_root = sha256_hex(f"EMPTY_LATTICE_SLICE:{lattice_id}:0:{s}")
            epochs[key] = {
                'epochIndex': 0,
                'shardIndex': s,
                'revokedMemberCount': 0,
                'accumulatorRoot': acc_root,
                'revokedMembers': [],
                'timestamp': ts
            }

        state = {
            'latticeId': lattice_id,
            'issuerDid': issuer_did,
            'shardsCount': shards_count,
            'currentEpoch': 0,
            'epochs': epochs,
            'globalLatticeRoot': ''
        }
        state['globalLatticeRoot'] = cls.compute_global_lattice_root(state)
        return state

    @staticmethod
    def compute_global_lattice_root(state: Dict[str, Any]) -> str:
        keys = sorted(state['epochs'].keys())
        serialized = '|'.join([f"{k}:{state['epochs'][k]['accumulatorRoot']}" for k in keys])
        return sha256_hex(f"LATTICE_GLOBAL_ROOT:{state['latticeId']}:{state['currentEpoch']}:{serialized}")

    @staticmethod
    def compute_shard_index(credential_id: str, shards_count: int) -> int:
        digest = sha256_hex(credential_id)
        num = int(digest[:8], 16)
        return num % shards_count

    @classmethod
    def accumulate_revocations(
        cls,
        state: Dict[str, Any],
        revoked_credential_ids: List[str],
        advance_epoch: bool = False
    ) -> Dict[str, Any]:
        next_state = {
            'latticeId': state['latticeId'],
            'issuerDid': state['issuerDid'],
            'shardsCount': state['shardsCount'],
            'currentEpoch': state['currentEpoch'],
            'epochs': {k: dict(v) for k, v in state['epochs'].items()}
        }

        if advance_epoch:
            next_state['currentEpoch'] += 1
            ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            for s in range(next_state['shardsCount']):
                prev_key = f"{state['currentEpoch']}_{s}"
                prev_slice = next_state['epochs'].get(prev_key, {
                    'epochIndex': state['currentEpoch'],
                    'shardIndex': s,
                    'revokedMemberCount': 0,
                    'accumulatorRoot': sha256_hex(f"EMPTY_LATTICE_SLICE:{state['latticeId']}:{state['currentEpoch']}:{s}"),
                    'revokedMembers': [],
                    'timestamp': ts
                })
                new_key = f"{next_state['currentEpoch']}_{s}"
                next_state['epochs'][new_key] = {
                    'epochIndex': next_state['currentEpoch'],
                    'shardIndex': s,
                    'revokedMemberCount': prev_slice['revokedMemberCount'],
                    'accumulatorRoot': prev_slice['accumulatorRoot'],
                    'revokedMembers': list(prev_slice['revokedMembers']),
                    'timestamp': ts
                }

        current_epoch = next_state['currentEpoch']
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        for raw_id in revoked_credential_ids:
            cred_digest = sha256_hex(raw_id)
            shard = cls.compute_shard_index(raw_id, next_state['shardsCount'])
            key = f"{current_epoch}_{shard}"

            slice_obj = next_state['epochs'].get(key)
            if not slice_obj:
                slice_obj = {
                    'epochIndex': current_epoch,
                    'shardIndex': shard,
                    'revokedMemberCount': 0,
                    'accumulatorRoot': sha256_hex(f"EMPTY_LATTICE_SLICE:{state['latticeId']}:{current_epoch}:{shard}"),
                    'revokedMembers': [],
                    'timestamp': ts
                }

            if cred_digest not in slice_obj['revokedMembers']:
                updated_members = sorted(slice_obj['revokedMembers'] + [cred_digest])
                updated_root = sha256_hex(f"SLICE_ACCUMULATOR:{current_epoch}:{shard}:{'+'.join(updated_members)}")
                next_state['epochs'][key] = {
                    'epochIndex': current_epoch,
                    'shardIndex': shard,
                    'revokedMemberCount': len(updated_members),
                    'accumulatorRoot': updated_root,
                    'revokedMembers': updated_members,
                    'timestamp': ts
                }

        next_state['globalLatticeRoot'] = cls.compute_global_lattice_root(next_state)
        return next_state

    @classmethod
    def generate_lattice_proof(
        cls,
        state: Dict[str, Any],
        credential_id: str,
        issuer_key_pair: Dict[str, Any],
        target_epoch: Optional[int] = None
    ) -> Dict[str, Any]:
        epoch = target_epoch if target_epoch is not None else state['currentEpoch']
        shard = cls.compute_shard_index(credential_id, state['shardsCount'])
        key = f"{epoch}_{shard}"
        slice_obj = state['epochs'].get(key)

        if not slice_obj:
            raise ValueError(f"Epoch slice {key} does not exist in lattice.")

        credential_digest = sha256_hex(credential_id)
        is_revoked = credential_digest in slice_obj['revokedMembers']

        other_members = [m for m in slice_obj['revokedMembers'] if m != credential_digest]
        status_tag = 'REVOKED' if is_revoked else 'ACTIVE'
        witness_hash = sha256_hex(f"LATTICE_WITNESS:{epoch}:{shard}:{status_tag}:{'|'.join(other_members)}")

        proof_id = f"lat-prf-{secrets.token_hex(8)}"
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        sign_payload = {
            'proofId': proof_id,
            'latticeId': state['latticeId'],
            'credentialId': credential_id,
            'credentialDigest': credential_digest,
            'targetEpoch': epoch,
            'targetShard': shard,
            'isRevoked': is_revoked,
            'accumulatorRoot': slice_obj['accumulatorRoot'],
            'witnessHash': witness_hash,
            'latticeRoot': state['globalLatticeRoot'],
            'issuerDid': issuer_key_pair.get('did', 'did:key:issuer'),
            'timestamp': ts
        }

        signature_hex = sign_message(canonicalize_json(sign_payload), issuer_key_pair.get('privateKeyHex', ''))

        return {
            'type': 'DocuTrustLatticeProof2026',
            'proofId': proof_id,
            'latticeId': state['latticeId'],
            'credentialId': credential_id,
            'credentialDigest': credential_digest,
            'targetEpoch': epoch,
            'targetShard': shard,
            'isRevoked': is_revoked,
            'accumulatorRoot': slice_obj['accumulatorRoot'],
            'witnessHash': witness_hash,
            'latticeRoot': state['globalLatticeRoot'],
            'issuerDid': issuer_key_pair.get('did', 'did:key:issuer'),
            'signatureHex': signature_hex,
            'timestamp': ts
        }

    @classmethod
    def verify_lattice_proof(
        cls,
        proof: Dict[str, Any],
        issuer_public_key_hex: str,
        expected_lattice_root: Optional[str] = None
    ) -> Dict[str, Any]:
        errors = []

        if not proof or proof.get('type') != 'DocuTrustLatticeProof2026':
            return {
                'valid': False,
                'isRevoked': True,
                'latticeId': proof.get('latticeId', 'unknown') if proof else 'unknown',
                'targetEpoch': proof.get('targetEpoch', 0) if proof else 0,
                'errors': ['Invalid lattice proof structure or type mismatch.']
            }

        # 1. Verify credential digest
        expected_digest = sha256_hex(proof.get('credentialId', ''))
        if expected_digest.lower() != str(proof.get('credentialDigest', '')).lower():
            errors.append('Credential digest mismatch in lattice proof.')

        # 2. Verify signature
        sign_payload = {
            'proofId': proof.get('proofId'),
            'latticeId': proof.get('latticeId'),
            'credentialId': proof.get('credentialId'),
            'credentialDigest': proof.get('credentialDigest'),
            'targetEpoch': proof.get('targetEpoch'),
            'targetShard': proof.get('targetShard'),
            'isRevoked': proof.get('isRevoked'),
            'accumulatorRoot': proof.get('accumulatorRoot'),
            'witnessHash': proof.get('witnessHash'),
            'latticeRoot': proof.get('latticeRoot'),
            'issuerDid': proof.get('issuerDid'),
            'timestamp': proof.get('timestamp')
        }

        is_sig_valid = verify_signature(
            canonicalize_json(sign_payload),
            proof.get('signatureHex', ''),
            issuer_public_key_hex
        )
        if not is_sig_valid:
            errors.append('Issuer cryptographic signature verification failed on lattice proof.')

        if expected_lattice_root and expected_lattice_root.lower() != str(proof.get('latticeRoot', '')).lower():
            errors.append(f"Lattice global root mismatch.")

        return {
            'valid': len(errors) == 0,
            'isRevoked': proof.get('isRevoked', False),
            'latticeId': proof.get('latticeId'),
            'targetEpoch': proof.get('targetEpoch'),
            'errors': errors
        }
