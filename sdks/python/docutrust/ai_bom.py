from __future__ import annotations
"""Module for mathematical computation and analysis."""


from typing import Dict, Any, List, Optional, Union
import secrets
import time

from .crypto import canonicalize_json, sha256_hex, sign_message, verify_signature


class AIBOMRegistryEngine:
    """
    DocuTrust AI Bill of Materials (AI-BOM) & Model Weights Registry Engine (v14.0.0).
    Computes per-layer Merkle trees, layer inclusion proofs, and verifies fine-tuning adapter lineages.
    """

    @classmethod
    def compute_layer_hash(cls, layer: Dict[str, Any]) -> str:
        """Compute layer hash using optimized algorithms.
        
        Args:
            layer:
        
        Returns:
            The computed result
        
        """
        canonical = canonicalize_json({
            'layerIndex': layer.get('layerIndex', 0),
            'layerName': layer.get('layerName', ''),
            'tensorShape': layer.get('tensorShape', '[]'),
            'dataType': layer.get('dataType', 'FP16'),
            'tensorDigestHex': layer.get('tensorDigestHex', '')
        })
        return sha256_hex(f"AI_LAYER:{canonical}")

    @classmethod
    def compute_weights_merkle_root(cls, layers: List[Dict[str, Any]]) -> str:
        """Compute weights merkle root using optimized algorithms.
        
        Args:
            layers:
        
        Returns:
            The computed result
        
        """
        if not layers:
            return sha256_hex('EMPTY_WEIGHTS')

        hashes = [cls.compute_layer_hash(l) for l in layers]
        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])
            next_level = []
            for i in range(0, len(hashes), 2):
                combined = sha256_hex(f"{hashes[i]}:{hashes[i+1]}")
                next_level.append(combined)
            hashes = next_level
        return hashes[0]

    @classmethod
    def generate_layer_proof(
        cls,
        manifest: Dict[str, Any],
        layer_index: int
    ) -> Dict[str, Any]:
        """Create layer proof.
        
        Args:
            manifest:
            layer_index:
        
        Returns:
            dict: Result of type dict
        
        """
        layers = manifest.get('layers', [])
        # Ensure indices
        indexed_layers = []
        for i, l in enumerate(layers):
            c = dict(l)
            if 'layerIndex' not in c:
                c['layerIndex'] = i
            indexed_layers.append(c)

        target_layer = next((l for l in indexed_layers if l.get('layerIndex') == layer_index), None)
        if not target_layer:
            raise ValueError(f"Layer index {layer_index} not found in manifest")

        hashes = [cls.compute_layer_hash(l) for l in indexed_layers]
        cur_idx = layer_index
        proof = []

        level = list(hashes)
        while len(level) > 1:
            if len(level) % 2 != 0:
                level.append(level[-1])
            sibling_idx = cur_idx + 1 if cur_idx % 2 == 0 else cur_idx - 1
            if sibling_idx < len(level):
                proof.append(level[sibling_idx])
            else:
                proof.append(level[cur_idx])

            next_level = []
            for i in range(0, len(level), 2):
                combined = sha256_hex(f"{level[i]}:{level[i+1]}")
                next_level.append(combined)
            level = next_level
            cur_idx //= 2

        return {
            'layer': target_layer,
            'proof': proof,
            'root': level[0]
        }

    @classmethod
    def verify_layer_proof(
        cls,
        proof_obj: Dict[str, Any],
        expected_root: str
    ) -> Dict[str, Any]:
        """Check whether layer proof.
        
        Args:
            proof_obj:
            expected_root:
        
        Returns:
            dict: Result of type dict
        
        """
        layer = proof_obj.get('layer', {})
        proof = proof_obj.get('proof', [])

        current_hash = cls.compute_layer_hash(layer)
        idx = layer.get('layerIndex', 0)

        for sibling in proof:
            if idx % 2 == 0:
                current_hash = sha256_hex(f"{current_hash}:{sibling}")
            else:
                current_hash = sha256_hex(f"{sibling}:{current_hash}")
            idx //= 2

        valid = current_hash == expected_root
        return {
            'valid': valid,
            'layerName': layer.get('layerName'),
            'layerIndex': layer.get('layerIndex'),
            'errors': [] if valid else ['Layer Merkle proof did not resolve to expected root']
        }

    @classmethod
    def create_aibom_receipt(
        cls,
        manifest: Dict[str, Any],
        certifier_key_pair: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create aibom receipt.
        
        Args:
            manifest:
            certifier_key_pair:
        
        Returns:
            dict: Result of type dict
        
        """
        layers = manifest.get('layers', [])
        weights_merkle_root = cls.compute_weights_merkle_root(layers)

        adapters = manifest.get('fineTuningAdapters', [])
        adapters_chain_hash = sha256_hex(canonicalize_json(adapters))

        dataset_lineage = manifest.get('datasetLineage', [])
        dataset_lineage_hash = sha256_hex(canonicalize_json(dataset_lineage))

        overall_bom_digest = sha256_hex(
            f"AIBOM:{weights_merkle_root}:{adapters_chain_hash}:{dataset_lineage_hash}"
        )

        receipt_id = f"aibom-rcpt-{secrets.token_hex(8)}"
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        sign_payload = {
            'receiptId': receipt_id,
            'modelId': manifest.get('modelId', f"model-{secrets.token_hex(4)}"),
            'modelName': manifest.get('modelName', ''),
            'weightsMerkleRoot': weights_merkle_root,
            'overallBOMDigest': overall_bom_digest,
            'certifierDid': certifier_key_pair.get('did', 'did:key:certifier')
        }
        priv = certifier_key_pair.get('privateKeyHex') or certifier_key_pair.get('secretKeyHex') or ''
        sig = sign_message(canonicalize_json(sign_payload), priv)

        return {
            'type': 'DocuTrustAIBOMReceipt2026',
            'receiptId': receipt_id,
            'modelId': sign_payload['modelId'],
            'modelName': manifest.get('modelName', ''),
            'architecture': manifest.get('architecture', 'transformer'),
            'parametersCount': manifest.get('parametersCount', 0),
            'quantization': manifest.get('quantization', 'FP16'),
            'layerCount': len(layers),
            'weightsMerkleRoot': weights_merkle_root,
            'adaptersChainHash': adapters_chain_hash,
            'datasetLineageHash': dataset_lineage_hash,
            'overallBOMDigest': overall_bom_digest,
            'certifierDid': sign_payload['certifierDid'],
            'signatureHex': sig,
            'timestamp': timestamp
        }

    @classmethod
    def verify_aibom_receipt(
        cls,
        receipt: Dict[str, Any],
        certifier_public_key: str,
        expected_weights_root: Optional[str] = None
    ) -> Dict[str, Any]:
        """Check whether aibom receipt.
        
        Args:
            receipt:
            certifier_public_key:
            expected_weights_root:
        
        Returns:
            dict: Result of type dict
        
        """
        errors = []
        if not isinstance(receipt, dict):
            return {'valid': False, 'errors': ['Invalid AI-BOM receipt']}

        if expected_weights_root and expected_weights_root != receipt.get('weightsMerkleRoot'):
            errors.append('Weights Merkle root mismatch')

        sign_payload = {
            'receiptId': receipt.get('receiptId'),
            'modelId': receipt.get('modelId'),
            'modelName': receipt.get('modelName'),
            'weightsMerkleRoot': receipt.get('weightsMerkleRoot'),
            'overallBOMDigest': receipt.get('overallBOMDigest'),
            'certifierDid': receipt.get('certifierDid')
        }
        sig = receipt.get('signatureHex', '')
        valid_sig = verify_signature(canonicalize_json(sign_payload), sig, certifier_public_key)
        if not valid_sig:
            errors.append('Invalid certifier signature on AI-BOM receipt')

        return {
            'valid': not errors,
            'weightsRootMatches': not errors,
            'errors': errors
        }
