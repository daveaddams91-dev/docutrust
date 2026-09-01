"""Succinct Vector Commitments & Subvector Openings Engine for DocuTrust v19.0.0."""

from __future__ import annotations
import time
from typing import Dict, Any, List, Optional
from .crypto import canonicalize_json, sha256_hex

VC_PRIME = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47  # BN254 scalar field


class VectorCommitmentEngine:
    """Succinct Vector Commitments and Subvector Openings Engine."""
    _crs_cache: Dict[int, Dict[str, Any]] = {}

    @classmethod
    def derive_generator(cls, seed: str, index: int) -> int:
        """Derives a deterministic generator scalar for index i."""
        h = sha256_hex(f"VC_SRS_GEN_V19:{seed}:{index}")
        return int(h, 16) % VC_PRIME

    @classmethod
    def generate_crs(cls, max_vector_length: int = 64, seed: str = "docutrust_srs_master_seed_v19") -> Dict[str, Any]:
        """Generates Structured Reference String (CRS)."""
        if max_vector_length in cls._crs_cache:
            return cls._crs_cache[max_vector_length]

        generators_hex = []
        for i in range(max_vector_length):
            g = cls.derive_generator(seed, i)
            generators_hex.append(hex(g)[2:].zfill(64))

        crs_hash = sha256_hex(canonicalize_json({
            "maxVectorLength": max_vector_length,
            "seed": seed,
            "generatorSample": generators_hex[:4]
        }))

        crs = {
            "maxVectorLength": max_vector_length,
            "generatorSeed": seed,
            "generatorsHex": generators_hex,
            "crsHash": crs_hash
        }
        cls._crs_cache[max_vector_length] = crs
        return crs

    @classmethod
    def to_scalar(cls, val: Any) -> int:
        """Maps an arbitrary value to a field scalar in VC_PRIME."""
        if isinstance(val, int):
            return (val % VC_PRIME + VC_PRIME) % VC_PRIME
        str_val = val if isinstance(val, str) else canonicalize_json(val)
        h = sha256_hex(str_val)
        return int(h, 16) % VC_PRIME

    @classmethod
    def commit(cls, vector: List[Any], crs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Commits to an ordered vector of attributes in O(1) constant size."""
        effective_crs = crs or cls.generate_crs(max(len(vector), 16))
        if len(vector) > effective_crs["maxVectorLength"]:
            raise ValueError(f"Vector length {len(vector)} exceeds CRS capacity {effective_crs['maxVectorLength']}")

        commitment_val = 0
        for i, item in enumerate(vector):
            ai = cls.to_scalar(item)
            gi = int(effective_crs["generatorsHex"][i], 16)
            commitment_val = (commitment_val + ai * gi) % VC_PRIME

        commitment_hex = hex(commitment_val)[2:].zfill(64)
        commitment_id = "vcom_" + sha256_hex(f"vc:{commitment_hex}:{time.time()}")[:16]

        state_hash = sha256_hex(canonicalize_json({
            "commitmentId": commitment_id,
            "vectorLength": len(vector),
            "commitmentHex": commitment_hex,
            "crsHash": effective_crs["crsHash"]
        }))

        return {
            "type": "DocuTrustVectorCommitment2026",
            "commitmentId": commitment_id,
            "commitment_id": commitment_id,
            "vectorLength": len(vector),
            "vector_length": len(vector),
            "dimension": len(vector),
            "commitmentHex": commitment_hex,
            "commitment_hex": commitment_hex,
            "crsHash": effective_crs["crsHash"],
            "crs_hash": effective_crs["crsHash"],
            "stateHash": state_hash,
            "state_hash": state_hash
        }

    @classmethod
    def prove_position(cls, vector: List[Any], index: int, crs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generates single-position opening proof."""
        if index < 0 or index >= len(vector):
            raise ValueError(f"Index out of bounds: {index}")

        effective_crs = crs or cls.generate_crs(max(len(vector), 16))
        target_val = cls.to_scalar(vector[index])

        witness_val = 0
        for j, item in enumerate(vector):
            if j == index:
                continue
            aj = cls.to_scalar(item)
            gj = int(effective_crs["generatorsHex"][j], 16)
            witness_val = (witness_val + aj * gj) % VC_PRIME

        commitment = cls.commit(vector, effective_crs)

        return {
            "index": index,
            "valueHex": hex(target_val)[2:].zfill(64),
            "value_hex": hex(target_val)[2:].zfill(64),
            "proofHex": hex(witness_val)[2:].zfill(64),
            "proof_hex": hex(witness_val)[2:].zfill(64),
            "commitmentHex": commitment["commitmentHex"],
            "commitment_hex": commitment["commitment_hex"]
        }

    @classmethod
    def verify_position(
        cls,
        commitment_hex: str,
        proof: Dict[str, Any],
        crs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Verifies position opening proof."""
        idx = proof.get("index", 0)
        effective_crs = crs or cls.generate_crs(max(idx + 1, 16))
        if idx >= effective_crs["maxVectorLength"]:
            return {"valid": False, "error": "Index exceeds CRS capacity"}

        gi = int(effective_crs["generatorsHex"][idx], 16)
        val_str = proof.get("valueHex") or proof.get("value_hex", "0")
        proof_str = proof.get("proofHex") or proof.get("proof_hex", "0")
        ai = int(val_str, 16)
        witness = int(proof_str, 16)
        target = int(commitment_hex, 16)

        reconstructed = (witness + ai * gi) % VC_PRIME
        if reconstructed != target:
            return {"valid": False, "error": "Position opening verification failed"}

        return {"valid": True}

    @classmethod
    def prove_subvector(
        cls,
        vector: List[Any],
        indices: List[int],
        crs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generates aggregated subvector opening proof."""
        effective_crs = crs or cls.generate_crs(max(len(vector), 16))
        sorted_indices = sorted(list(set(indices)))

        for idx in sorted_indices:
            if idx < 0 or idx >= len(vector):
                raise ValueError(f"Index out of bounds: {idx}")

        queried_set = set(sorted_indices)
        witness_val = 0
        values_hex = []

        for i, item in enumerate(vector):
            ai = cls.to_scalar(item)
            if i in queried_set:
                values_hex.append(hex(ai)[2:].zfill(64))
            else:
                gi = int(effective_crs["generatorsHex"][i], 16)
                witness_val = (witness_val + ai * gi) % VC_PRIME

        commitment = cls.commit(vector, effective_crs)
        proof_id = "sub_prf_" + sha256_hex(f"subprf:{commitment['commitmentHex']}:{sorted_indices}")[:16]

        payload = {
            "type": "DocuTrustSubvectorProof2026",
            "proofId": proof_id,
            "proof_id": proof_id,
            "commitmentHex": commitment["commitmentHex"],
            "commitment_hex": commitment["commitment_hex"],
            "indices": sorted_indices,
            "valuesHex": values_hex,
            "values_hex": values_hex,
            "aggregatedProofHex": hex(witness_val)[2:].zfill(64),
            "aggregated_proof_hex": hex(witness_val)[2:].zfill(64),
            "crsHash": effective_crs["crsHash"],
            "crs_hash": effective_crs["crsHash"]
        }
        proof_hash = sha256_hex(canonicalize_json(payload))
        payload["proofHash"] = proof_hash
        payload["proof_hash"] = proof_hash
        return payload

    @classmethod
    def verify_subvector(
        cls,
        commitment_hex: str,
        proof: Dict[str, Any],
        crs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Verifies aggregated subvector opening proof."""
        indices = proof.get("indices", [])
        values_hex = proof.get("valuesHex") or proof.get("values_hex", [])
        if len(indices) != len(values_hex):
            return {"valid": False, "error": "Mismatch between indices and values count"}

        max_idx = max(indices) if indices else 0
        effective_crs = crs or cls.generate_crs(max(max_idx + 1, 16))

        for idx in indices:
            if idx >= effective_crs["maxVectorLength"]:
                return {"valid": False, "error": f"Index {idx} exceeds CRS capacity"}

        queried_sum = 0
        for idx, val_hex in zip(indices, values_hex):
            ai = int(val_hex, 16)
            gi = int(effective_crs["generatorsHex"][idx], 16)
            queried_sum = (queried_sum + ai * gi) % VC_PRIME

        proof_str = proof.get("aggregatedProofHex") or proof.get("aggregated_proof_hex", "0")
        witness = int(proof_str, 16)
        reconstructed = (witness + queried_sum) % VC_PRIME
        target = int(commitment_hex, 16)

        if reconstructed != target:
            return {"valid": False, "error": "Subvector opening verification failed"}

        return {"valid": True}
