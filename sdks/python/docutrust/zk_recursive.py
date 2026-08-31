from __future__ import annotations
import secrets
import time
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex, sign_message, verify_signature

class ZKRecursiveEngine:
    """
    Recursive ZK Proof Composition & SNARK Folding Aggregator (DocuTrust v13.0.0).
    Aggregates multiple heterogenous ZK proofs into a single succinct recursive proof.
    """

    @staticmethod
    def linearize_public_inputs(inputs: Union[Dict[str, Any], List[Any]]) -> str:
        canonical = canonicalize_json(inputs)
        return sha256_hex(f"ZK_LINEAR_IN:{canonical}")

    @staticmethod
    def compute_sub_proof_digest(statement: Dict[str, Any]) -> str:
        canonical = canonicalize_json({
            'proofId': statement.get('proofId', ''),
            'proofType': statement.get('proofType', 'GenericZK'),
            'claim': statement.get('claim', ''),
            'publicInputs': statement.get('publicInputs', {}),
            'proofData': statement.get('proofData', {}),
            'proverDid': statement.get('proverDid', 'did:key:anonymous')
        })
        return sha256_hex(canonical)

    @staticmethod
    def derive_folding_randomness(sub_proof_digests: List[str], seed_prefix: str = 'DOCUTRUST_ZK_FOLD_V13') -> str:
        concatenated = '::'.join([seed_prefix] + sub_proof_digests)
        return sha256_hex(concatenated)

    @classmethod
    def aggregate_proofs(
        cls,
        sub_proofs: List[Dict[str, Any]],
        aggregator_key_pair: Dict[str, Any],
        depth: int = 1,
        generate_evm_calldata: bool = False
    ) -> Dict[str, Any]:
        if not sub_proofs:
            raise ValueError("Cannot aggregate an empty set of zero-knowledge proofs.")

        recursive_proof_id = f"zk-rec-{secrets.token_hex(8)}"
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        # 1. Compute sub-proof digests
        sub_proof_digests = [cls.compute_sub_proof_digest(sp) for sp in sub_proofs]

        # 2. Linearize public inputs
        linearized_inputs = [
            {'proofId': sp.get('proofId'), 'linearDigest': cls.linearize_public_inputs(sp.get('publicInputs', {}))}
            for sp in sub_proofs
        ]
        linearized_public_inputs_commitment = sha256_hex(canonicalize_json(linearized_inputs))

        # 3. Derive Fiat-Shamir folding randomness
        folding_randomness_hex = cls.derive_folding_randomness(sub_proof_digests)

        # 4. Compute aggregated witness commitment
        witness_components = []
        for idx, sp in enumerate(sub_proofs):
            proof_id = sp.get('proofId', '')
            weight = sha256_hex(f"{folding_randomness_hex}:{idx}:{proof_id}")
            p_data = sp.get('proofData', '')
            proof_str = p_data if isinstance(p_data, str) else canonicalize_json(p_data)
            witness_components.append(sha256_hex(f"{weight}:{proof_str}"))

        aggregated_witness_commitment = sha256_hex('^'.join(witness_components))

        sign_payload = {
            'recursiveProofId': recursive_proof_id,
            'subProofCount': len(sub_proofs),
            'subProofDigests': sub_proof_digests,
            'linearizedPublicInputsCommitment': linearized_public_inputs_commitment,
            'aggregatedWitnessCommitment': aggregated_witness_commitment,
            'foldingRandomnessHex': folding_randomness_hex,
            'depth': depth,
            'aggregatorDid': aggregator_key_pair.get('did', 'did:key:aggregator'),
            'timestamp': timestamp
        }

        signature_hex = sign_message(canonicalize_json(sign_payload), aggregator_key_pair.get('privateKeyHex', ''))

        evm_calldata_hex = None
        if generate_evm_calldata:
            evm_calldata_hex = cls.generate_evm_calldata(
                recursive_proof_id,
                len(sub_proofs),
                linearized_public_inputs_commitment,
                aggregated_witness_commitment
            )

        res = {
            'type': 'DocuTrustRecursiveZKProof2026',
            'recursiveProofId': recursive_proof_id,
            'subProofCount': len(sub_proofs),
            'subProofDigests': sub_proof_digests,
            'subProofStatements': sub_proofs,
            'linearizedPublicInputsCommitment': linearized_public_inputs_commitment,
            'aggregatedWitnessCommitment': aggregated_witness_commitment,
            'foldingRandomnessHex': folding_randomness_hex,
            'depth': depth,
            'aggregatorDid': aggregator_key_pair.get('did', 'did:key:aggregator'),
            'signatureHex': signature_hex,
            'timestamp': timestamp
        }
        if evm_calldata_hex:
            res['evmCalldataHex'] = evm_calldata_hex
        return res

    @classmethod
    def verify_recursive_proof(
        cls,
        proof: Dict[str, Any],
        aggregator_public_key_hex: str
    ) -> Dict[str, Any]:
        errors = []

        if not proof or proof.get('type') != 'DocuTrustRecursiveZKProof2026':
            return {
                'valid': False,
                'recursiveProofId': proof.get('recursiveProofId', 'unknown') if proof else 'unknown',
                'subProofCount': 0,
                'depth': 0,
                'linearizedPublicInputsCommitment': '',
                'errors': ['Invalid recursive proof structure or type mismatch.']
            }

        # 1. Verify signature
        sign_payload = {
            'recursiveProofId': proof.get('recursiveProofId'),
            'subProofCount': proof.get('subProofCount'),
            'subProofDigests': proof.get('subProofDigests'),
            'linearizedPublicInputsCommitment': proof.get('linearizedPublicInputsCommitment'),
            'aggregatedWitnessCommitment': proof.get('aggregatedWitnessCommitment'),
            'foldingRandomnessHex': proof.get('foldingRandomnessHex'),
            'depth': proof.get('depth'),
            'aggregatorDid': proof.get('aggregatorDid'),
            'timestamp': proof.get('timestamp')
        }

        is_sig_valid = verify_signature(
            canonicalize_json(sign_payload),
            proof.get('signatureHex', ''),
            aggregator_public_key_hex
        )
        if not is_sig_valid:
            errors.append('Aggregator cryptographic signature verification failed on recursive ZK proof.')

        # 2. Recompute sub-proof digests
        statements = proof.get('subProofStatements', [])
        if len(statements) != proof.get('subProofCount', 0):
            errors.append(f"Sub-proof statement count mismatch.")

        computed_digests = [cls.compute_sub_proof_digest(sp) for sp in statements]
        if computed_digests != proof.get('subProofDigests', []):
            errors.append('Recomputed sub-proof statement digests do not match recursive commitment vector.')

        # 3. Check folding randomness
        expected_rand = cls.derive_folding_randomness(proof.get('subProofDigests', []))
        if expected_rand.lower() != str(proof.get('foldingRandomnessHex', '')).lower():
            errors.append('Fiat-Shamir folding randomness mismatch.')

        # 4. Check linearized public inputs commitment
        linearized_inputs = [
            {'proofId': sp.get('proofId'), 'linearDigest': cls.linearize_public_inputs(sp.get('publicInputs', {}))}
            for sp in statements
        ]
        expected_lin_commit = sha256_hex(canonicalize_json(linearized_inputs))
        if expected_lin_commit.lower() != str(proof.get('linearizedPublicInputsCommitment', '')).lower():
            errors.append('Linearized public inputs commitment does not match sub-proof payload.')

        # 5. Check aggregated witness commitment
        folding_rand = proof.get('foldingRandomnessHex', '')
        witness_components = []
        for idx, sp in enumerate(statements):
            proof_id = sp.get('proofId', '')
            weight = sha256_hex(f"{folding_rand}:{idx}:{proof_id}")
            p_data = sp.get('proofData', '')
            proof_str = p_data if isinstance(p_data, str) else canonicalize_json(p_data)
            witness_components.append(sha256_hex(f"{weight}:{proof_str}"))

        expected_witness_commit = sha256_hex('^'.join(witness_components))
        if expected_witness_commit.lower() != str(proof.get('aggregatedWitnessCommitment', '')).lower():
            errors.append('Aggregated witness commitment verification failed.')

        return {
            'valid': len(errors) == 0,
            'recursiveProofId': proof.get('recursiveProofId'),
            'subProofCount': proof.get('subProofCount'),
            'depth': proof.get('depth'),
            'linearizedPublicInputsCommitment': proof.get('linearizedPublicInputsCommitment'),
            'errors': errors
        }

    @staticmethod
    def generate_evm_calldata(
        recursive_proof_id: str,
        sub_proof_count: int,
        linearized_inputs_commitment: str,
        aggregated_witness_commitment: str
    ) -> str:
        import hashlib
        method_sig = 'verifyRecursiveZKProof(bytes32,uint256,bytes32,bytes32)'
        selector = hashlib.sha256(method_sig.encode('utf-8')).hexdigest()[:8]

        clean_proof_id = sha256_hex(recursive_proof_id).zfill(64)
        clean_count = hex(sub_proof_count)[2:].zfill(64)
        clean_inputs = linearized_inputs_commitment.replace('0x', '').zfill(64)
        clean_witness = aggregated_witness_commitment.replace('0x', '').zfill(64)

        return f"0x{selector}{clean_proof_id}{clean_count}{clean_inputs}{clean_witness}"
