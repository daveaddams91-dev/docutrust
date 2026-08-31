from __future__ import annotations
import hmac
import hashlib
import secrets
import time
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex, generate_key_pair, sign_message, verify_signature

class VRFOracleEngine:
    """
    DocuTrust VRF & Multi-Oracle Consensus Mesh Engine (v14.0.0).
    Provides verifiable deterministic randomness, epoch beacons, and multi-oracle threshold consensus.
    """

    @staticmethod
    def generate_key_pair() -> Dict[str, Any]:
        kp = generate_key_pair()
        return {
            'publicKeyHex': kp['publicKeyHex'],
            'privateKeyHex': kp.get('privateKeyHex') or kp.get('secretKeyHex'),
            'did': f"did:key:{kp['publicKeyHex']}"
        }

    @staticmethod
    def evaluate(
        input_seed: Union[str, bytes, Dict[str, Any]],
        key_pair: Dict[str, Any]
    ) -> Dict[str, Any]:
        seed_str = input_seed if isinstance(input_seed, str) else (
            input_seed.decode('utf-8') if isinstance(input_seed, bytes) else canonicalize_json(input_seed)
        )
        priv_key = key_pair.get('privateKeyHex') or key_pair.get('secretKeyHex') or ''
        pub_key = key_pair.get('publicKeyHex', '')

        # Deterministic VRF output: HMAC-SHA512(sk, "VRF_EVAL:" + seed)
        h = hmac.new(bytes.fromhex(priv_key) if len(priv_key) == 64 else priv_key.encode('utf-8'), (f"VRF_EVAL:{seed_str}").encode('utf-8'), hashlib.sha512).hexdigest()
        vrf_output = h[:64]
        raw_proof = h[64:]

        # Sign the evaluation
        eval_payload = {
            'seed': seed_str,
            'vrfOutputHex': vrf_output,
            'rawProof': raw_proof,
            'publicKeyHex': pub_key
        }
        sig = sign_message(canonicalize_json(eval_payload), priv_key)

        return {
            'type': 'DocuTrustVRFEvaluation2026',
            'inputSeed': seed_str,
            'vrfOutputHex': vrf_output,
            'proofHex': f"{raw_proof}{sig}",
            'publicKeyHex': pub_key,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

    @staticmethod
    def verify(evaluation: Dict[str, Any]) -> Dict[str, Any]:
        errors = []
        if not isinstance(evaluation, dict):
            return {'valid': False, 'errors': ['Invalid evaluation payload']}

        seed = evaluation.get('inputSeed')
        vrf_output = evaluation.get('vrfOutputHex')
        proof = evaluation.get('proofHex', '')
        pub_key = evaluation.get('publicKeyHex')

        if not seed or not vrf_output or not proof or not pub_key:
            return {'valid': False, 'errors': ['Missing required VRF evaluation fields']}

        if len(proof) < 64:
            return {'valid': False, 'errors': ['Invalid proof length']}

        raw_proof = proof[:64]
        sig = proof[64:]

        eval_payload = {
            'seed': seed,
            'vrfOutputHex': vrf_output,
            'rawProof': raw_proof,
            'publicKeyHex': pub_key
        }
        valid_sig = verify_signature(canonicalize_json(eval_payload), sig, pub_key)
        if not valid_sig:
            errors.append('Invalid VRF evaluation signature')

        return {
            'valid': len(errors) == 0,
            'vrfOutputHex': vrf_output,
            'errors': errors
        }

    @classmethod
    def create_beacon(
        cls,
        epoch: int,
        round_num: int,
        previous_beacon_hash: str,
        oracle_key_pairs: List[Dict[str, Any]],
        threshold_required: Optional[int] = None
    ) -> Dict[str, Any]:
        threshold = threshold_required or max(1, (len(oracle_key_pairs) * 2 // 3) + 1)
        beacon_seed = f"BEACON_EPOCH:{epoch}:ROUND:{round_num}:PREV:{previous_beacon_hash}"

        evaluations = []
        for kp in oracle_key_pairs:
            eval_res = cls.evaluate(beacon_seed, kp)
            evaluations.append(eval_res)

        # Aggregate randomness
        combined_entropy = ":".join(sorted(e['vrfOutputHex'] for e in evaluations))
        randomness_output = sha256_hex(f"BEACON_RANDOMNESS:{epoch}:{round_num}:{combined_entropy}")
        combined_proof = sha256_hex(":".join(e['proofHex'] for e in evaluations))

        return {
            'type': 'DocuTrustVRFBeacon2026',
            'beaconId': f"beacon-ep{epoch}-r{round_num}-{secrets.token_hex(4)}",
            'epoch': epoch,
            'round': round_num,
            'previousBeaconHash': previous_beacon_hash,
            'randomnessOutputHex': randomness_output,
            'combinedProofHex': combined_proof,
            'evaluations': evaluations,
            'evaluationsCount': len(evaluations),
            'thresholdRequired': threshold,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

    @classmethod
    def verify_beacon(
        cls,
        beacon: Dict[str, Any],
        expected_beacon_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        errors = []
        if not isinstance(beacon, dict):
            return {'valid': False, 'errors': ['Invalid beacon object']}

        evaluations = beacon.get('evaluations', [])
        threshold = beacon.get('thresholdRequired', 1)

        valid_count = 0
        outputs = []
        for ev in evaluations:
            v_res = cls.verify(ev)
            if v_res.get('valid'):
                valid_count += 1
                outputs.append(ev['vrfOutputHex'])
            else:
                errors.append(f"Invalid evaluation for key {ev.get('publicKeyHex')}")

        quorum_reached = valid_count >= threshold
        if not quorum_reached:
            errors.append(f"Quorum not reached: {valid_count}/{threshold} valid evaluations")

        # Verify combined randomness
        combined_entropy = ":".join(sorted(outputs))
        expected_randomness = sha256_hex(f"BEACON_RANDOMNESS:{beacon.get('epoch')}:{beacon.get('round')}:{combined_entropy}")
        if expected_randomness != beacon.get('randomnessOutputHex'):
            errors.append('Randomness output mismatch with aggregated evaluations')

        return {
            'valid': len(errors) == 0 and quorum_reached,
            'epoch': beacon.get('epoch'),
            'round': beacon.get('round'),
            'quorumReached': quorum_reached,
            'validEvaluationsCount': valid_count,
            'errors': errors
        }

    @classmethod
    def issue_oracle_feed(
        cls,
        feed_id: str,
        round_num: int,
        data_payload: Any,
        oracle_key_pairs: List[Dict[str, Any]],
        threshold_required: Optional[int] = None
    ) -> Dict[str, Any]:
        threshold = threshold_required or max(1, (len(oracle_key_pairs) * 2 // 3) + 1)
        canonical_data = canonicalize_json(data_payload)
        data_digest = sha256_hex(canonical_data)

        signatures = []
        for kp in oracle_key_pairs:
            priv = kp.get('privateKeyHex') or kp.get('secretKeyHex') or ''
            pub = kp.get('publicKeyHex', '')
            sign_content = f"ORACLE_FEED:{feed_id}:{round_num}:{data_digest}"
            sig = sign_message(sign_content, priv)
            signatures.append({
                'oraclePublicKeyHex': pub,
                'oracleDid': kp.get('did', f"did:key:{pub}"),
                'signatureHex': sig
            })

        return {
            'type': 'DocuTrustOracleFeed2026',
            'feedId': feed_id,
            'round': round_num,
            'dataPayload': data_payload,
            'dataDigestHex': data_digest,
            'signatures': signatures,
            'signaturesCount': len(signatures),
            'thresholdRequired': threshold,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

    @classmethod
    def create_oracle_feed(cls, *args, **kwargs):
        return cls.issue_oracle_feed(*args, **kwargs)

    @classmethod
    def verify_oracle_feed(
        cls,
        feed: Dict[str, Any],
        trusted_oracle_public_keys: Optional[Union[List[str], Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        errors = []
        if not isinstance(feed, dict):
            return {'valid': False, 'errors': ['Invalid oracle feed object']}

        feed_id = feed.get('feedId', '')
        round_num = feed.get('round', 0)
        data_payload = feed.get('dataPayload')
        canonical_data = canonicalize_json(data_payload)
        expected_digest = sha256_hex(canonical_data)

        if expected_digest != feed.get('dataDigestHex'):
            errors.append('Data digest mismatch')

        signatures = feed.get('signatures', [])
        threshold = feed.get('thresholdRequired', 1)

        trusted_set = None
        if trusted_oracle_public_keys is not None:
            if isinstance(trusted_oracle_public_keys, list):
                trusted_set = set(trusted_oracle_public_keys)
            elif isinstance(trusted_oracle_public_keys, dict):
                trusted_set = set(trusted_oracle_public_keys.values())

        valid_count = 0
        sign_content = f"ORACLE_FEED:{feed_id}:{round_num}:{expected_digest}"

        for s in signatures:
            pub = s.get('oraclePublicKeyHex', '')
            sig = s.get('signatureHex', '')
            if trusted_set is not None and pub not in trusted_set:
                continue
            if verify_signature(sign_content, sig, pub):
                valid_count += 1

        quorum_reached = valid_count >= threshold
        if not quorum_reached:
            errors.append(f"Oracle feed threshold not met: {valid_count}/{threshold} valid signatures")

        return {
            'valid': len(errors) == 0 and quorum_reached,
            'quorumReached': quorum_reached,
            'validSignaturesCount': valid_count,
            'errors': errors
        }
