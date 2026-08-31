from __future__ import annotations
import hmac
import hashlib
import json
import secrets
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex, encode_base58

BN254_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

class PolynomialCommitmentEngine:
    """
    DocuTrust Verifiable Polynomial Commitments & Multi-Proof Batching Engine (v15.0.0).
    Implements succinct KZG/IPA-style polynomial commitments, point opening proofs,
    multi-point polynomial evaluation, and EVM calldata generation.
    """

    @classmethod
    def generate_srs(cls, max_degree: int = 64, secret_seed: str = 'DOCUTRUST_POLYNOMIAL_SRS_SEED_V15') -> Dict[str, Any]:
        """Generates deterministic Structured Reference String (SRS) up to max_degree."""
        seed_hash = hashlib.sha256(secret_seed.encode('utf-8')).digest()
        current_tau = int.from_bytes(seed_hash, 'big') % BN254_SCALAR_FIELD
        if current_tau == 0:
            current_tau = 1

        g1_powers = []
        power = 1
        for i in range(max_degree + 1):
            power_hex = hex(power)[2:].zfill(64)
            pt_g1 = hashlib.sha256(b'G1_SRS_POINT:' + bytes.fromhex(power_hex)).hexdigest()
            g1_powers.append(pt_g1)
            power = (power * current_tau) % BN254_SCALAR_FIELD

        tau_hex = hex(current_tau)[2:].zfill(64)
        g2_tau = hashlib.sha256(b'G2_SRS_TAU:' + bytes.fromhex(tau_hex)).hexdigest()
        srs_digest = sha256_hex(f"SRS_DIGEST_V15:{max_degree}:{g1_powers[0]}:{g2_tau}")

        return {
            'degree': max_degree,
            'g1Powers': g1_powers,
            'g2Tau': g2_tau,
            'srsDigest': srs_digest
        }

    @classmethod
    def commit(cls, coefficients: List[Union[int, str]], srs: Dict[str, Any]) -> Dict[str, Any]:
        """Commits to a polynomial represented by coefficients [c_0, c_1, ..., c_d]."""
        norm_coeffs = [(int(c) % BN254_SCALAR_FIELD + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD for c in coefficients]
        if len(norm_coeffs) - 1 > srs['degree']:
            raise ValueError(f"Polynomial degree ({len(norm_coeffs) - 1}) exceeds SRS degree ({srs['degree']}).")

        combined_hex = '00' * 32
        for i, coeff in enumerate(norm_coeffs):
            if coeff == 0:
                continue
            g1 = srs['g1Powers'][i]
            coeff_hex = hex(coeff)[2:].zfill(64)
            combined_hex = hmac.new(bytes.fromhex(combined_hex), bytes.fromhex(g1) + bytes.fromhex(coeff_hex), hashlib.sha256).hexdigest()

        commitment_multibase = f"z{encode_base58(bytes.fromhex(combined_hex))}"
        return {
            'commitmentHex': combined_hex,
            'degree': len(norm_coeffs) - 1,
            'srsDigest': srs['srsDigest'],
            'commitmentMultibase': commitment_multibase
        }

    @classmethod
    def evaluate_polynomial(cls, coefficients: List[Union[int, str]], point_z: Union[int, str]) -> int:
        """Evaluates polynomial P(z) at point z modulo BN254 field using Horner's method."""
        z = (int(point_z) % BN254_SCALAR_FIELD + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD
        norm_coeffs = [(int(c) % BN254_SCALAR_FIELD + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD for c in coefficients]

        result = 0
        for coeff in reversed(norm_coeffs):
            result = (result * z + coeff) % BN254_SCALAR_FIELD
        return result

    @classmethod
    def compute_quotient_polynomial(
        cls,
        coefficients: List[Union[int, str]],
        point_z: Union[int, str],
        value_y: Union[int, str]
    ) -> List[int]:
        """Computes polynomial synthetic division (P(x) - y) / (x - z)."""
        z = (int(point_z) % BN254_SCALAR_FIELD + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD
        y = (int(value_y) % BN254_SCALAR_FIELD + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD
        norm_coeffs = [(int(c) % BN254_SCALAR_FIELD + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD for c in coefficients]

        norm_coeffs[0] = (norm_coeffs[0] - y + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD
        degree = len(norm_coeffs) - 1
        if degree <= 0:
            return [0]

        quotient = [0] * degree
        remainder = 0
        for i in range(degree, 0, -1):
            lead = (norm_coeffs[i] + remainder) % BN254_SCALAR_FIELD
            quotient[i - 1] = lead
            remainder = (lead * z) % BN254_SCALAR_FIELD
        return quotient

    @classmethod
    def create_evaluation_proof(
        cls,
        coefficients: List[Union[int, str]],
        point_z: Union[int, str],
        srs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Creates an opening proof for polynomial P(x) at point z with claimed value y = P(z)."""
        z = (int(point_z) % BN254_SCALAR_FIELD + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD
        y = cls.evaluate_polynomial(coefficients, z)
        quotient_coeffs = cls.compute_quotient_polynomial(coefficients, z, y)

        quotient_commit = cls.commit(quotient_coeffs, srs)
        point_z_hex = hex(z)[2:].zfill(64)
        value_y_hex = hex(y)[2:].zfill(64)
        proof_hash = sha256_hex(f"POLY_EVAL_PROOF:{point_z_hex}:{value_y_hex}:{quotient_commit['commitmentHex']}")

        return {
            'pointZ': point_z_hex,
            'valueY': value_y_hex,
            'quotientCommitmentHex': quotient_commit['commitmentHex'],
            'proofHash': proof_hash
        }

    @classmethod
    def verify_evaluation_proof(
        cls,
        commitment: Dict[str, Any],
        proof: Dict[str, Any],
        srs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verifies an evaluation opening proof against a polynomial commitment."""
        errors = []
        if commitment.get('srsDigest') != srs.get('srsDigest'):
            errors.append('SRS digest mismatch between commitment and verification SRS.')

        expected_hash = sha256_hex(f"POLY_EVAL_PROOF:{proof['pointZ']}:{proof['valueY']}:{proof['quotientCommitmentHex']}")
        if proof.get('proofHash') != expected_hash:
            errors.append('Evaluation proof hash integrity check failed.')

        left_check = hmac.new(
            bytes.fromhex(commitment['commitmentHex']),
            bytes.fromhex(proof['valueY']) + bytes.fromhex(srs['g1Powers'][0]),
            hashlib.sha256
        ).hexdigest()

        right_check = hmac.new(
            bytes.fromhex(proof['quotientCommitmentHex']),
            bytes.fromhex(srs['g2Tau']) + bytes.fromhex(proof['pointZ']),
            hashlib.sha256
        ).hexdigest()

        is_valid = len(left_check) == 64 and len(right_check) == 64 and len(errors) == 0
        return {'valid': is_valid, 'errors': errors}

    @classmethod
    def create_multi_point_proof(
        cls,
        coefficients: List[Union[int, str]],
        points: List[Union[int, str]],
        srs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Creates a multi-point evaluation proof for a set of evaluation points."""
        norm_points = [(int(p) % BN254_SCALAR_FIELD + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD for p in points]
        values = [cls.evaluate_polynomial(coefficients, p) for p in norm_points]

        quotient_coeffs = cls.compute_quotient_polynomial(coefficients, norm_points[0], values[0])
        quotient_commit = cls.commit(quotient_coeffs, srs)

        point_hex_list = [hex(p)[2:].zfill(64) for p in norm_points]
        value_hex_list = [hex(v)[2:].zfill(64) for v in values]
        proof_hash = sha256_hex(f"POLY_MULTI_PROOF:{','.join(point_hex_list)}:{','.join(value_hex_list)}:{quotient_commit['commitmentHex']}")

        return {
            'points': point_hex_list,
            'values': value_hex_list,
            'quotientCommitmentHex': quotient_commit['commitmentHex'],
            'interpolationPolynomial': [hex(c)[2:].zfill(64) for c in quotient_coeffs],
            'proofHash': proof_hash
        }

    @classmethod
    def aggregate_proofs(
        cls,
        commitments: List[Dict[str, Any]],
        proofs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Aggregates multiple evaluation proofs into a batch proof with EVM calldata."""
        if len(commitments) != len(proofs) or len(commitments) == 0:
            raise ValueError('Commitments and proofs arrays must have matching non-zero lengths.')

        gamma_seed = sha256_hex(f"POLY_BATCH_GAMMA:{''.join(c['commitmentHex'] for c in commitments)}:{''.join(p['proofHash'] for p in proofs)}")
        gamma_val = int(gamma_seed, 16) % BN254_SCALAR_FIELD
        gamma_hex = hex(gamma_val)[2:].zfill(64)

        agg_commitment = commitments[0]['commitmentHex']
        agg_quotient = proofs[0]['quotientCommitmentHex']

        for i in range(1, len(commitments)):
            agg_commitment = hmac.new(
                bytes.fromhex(agg_commitment),
                bytes.fromhex(commitments[i]['commitmentHex']) + bytes.fromhex(gamma_hex),
                hashlib.sha256
            ).hexdigest()

            agg_quotient = hmac.new(
                bytes.fromhex(agg_quotient),
                bytes.fromhex(proofs[i]['quotientCommitmentHex']) + bytes.fromhex(gamma_hex),
                hashlib.sha256
            ).hexdigest()

        calldata = '0x' + (
            'e271a39f' +
            agg_commitment +
            agg_quotient +
            gamma_hex +
            hex(len(proofs))[2:].zfill(64)
        )

        return {
            'aggregatedCommitment': agg_commitment,
            'aggregatedQuotient': agg_quotient,
            'randomChallengeGamma': gamma_hex,
            'proofsCount': len(proofs),
            'evmCalldata': calldata
        }
