from __future__ import annotations
import hashlib
import time
import hmac
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex

class TrustScoreEngine:
    """Quantitative Multi-Vector Trust & Risk Scoring Engine with Signed Risk Receipts."""

    @staticmethod
    def calculate_trust_score(
        credential: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        options = options or {}
        breakdown = {
            'cryptoSuiteScore': 100,
            'issuerAccreditationScore': 150,
            'revocationFreshnessScore': 200,
            'temporalValidityScore': 150,
            'schemaComplianceScore': 150
        }

        # 1. Cryptographic Suite Score (0 - 250)
        proof = credential.get('proof') or {}
        proof_type = proof.get('type', '')
        if 'ML-DSA' in proof_type or 'Hybrid' in proof_type or 'SLH-DSA' in proof_type:
            breakdown['cryptoSuiteScore'] = 250
        elif 'Ed25519' in proof_type or 'BbsBlsSignature' in proof_type:
            breakdown['cryptoSuiteScore'] = 200
        elif 'Ecdsa' in proof_type or 'Secp256k1' in proof_type:
            breakdown['cryptoSuiteScore'] = 180
        elif 'Rsa' in proof_type:
            breakdown['cryptoSuiteScore'] = 100
        else:
            breakdown['cryptoSuiteScore'] = 50

        # 2. Issuer Accreditation Tier (0 - 250)
        issuer = str(credential.get('issuer', ''))
        accreditation_tiers = options.get('issuerAccreditationTiers', {})
        tier = accreditation_tiers.get(issuer, 1)
        breakdown['issuerAccreditationScore'] = min(250, int(tier * 83.33))

        # 3. Status & Revocation Freshness (0 - 200)
        status = credential.get('status')
        if status == 'REVOKED' or credential.get('revoked') is True:
            breakdown['revocationFreshnessScore'] = 0
        else:
            breakdown['revocationFreshnessScore'] = 200

        # 4. Temporal Validity & Epoch Distance (0 - 150)
        now_epoch = int(time.time())
        valid_until_str = credential.get('validUntil') or credential.get('expirationDate')
        if valid_until_str:
            try:
                import datetime
                if valid_until_str.endswith('Z'):
                    dt = datetime.datetime.fromisoformat(valid_until_str.replace('Z', '+00:00'))
                else:
                    dt = datetime.datetime.fromisoformat(valid_until_str)
                exp_epoch = int(dt.timestamp())
                if now_epoch > exp_epoch:
                    breakdown['temporalValidityScore'] = 0
                else:
                    breakdown['temporalValidityScore'] = 150
            except Exception:
                breakdown['temporalValidityScore'] = 100
        else:
            breakdown['temporalValidityScore'] = 150

        # 5. Schema Compliance & Syntax (0 - 150)
        if credential.get('schemaValid') is False:
            breakdown['schemaComplianceScore'] = 0
        else:
            breakdown['schemaComplianceScore'] = 150

        raw_score = sum(breakdown.values())
        overall_score = max(0, min(1000, raw_score))

        if overall_score >= 900:
            risk_tier = 'AAA'
        elif overall_score >= 800:
            risk_tier = 'AA'
        elif overall_score >= 700:
            risk_tier = 'A'
        elif overall_score >= 600:
            risk_tier = 'BBB'
        elif overall_score >= 500:
            risk_tier = 'BB'
        elif overall_score >= 400:
            risk_tier = 'B'
        else:
            risk_tier = 'C'

        min_acceptable = options.get('minimumAcceptableScore', 600)
        is_acceptable = (overall_score >= min_acceptable and
                         breakdown['revocationFreshnessScore'] > 0 and
                         breakdown['temporalValidityScore'] > 0)

        return {
            'overallScore': overall_score,
            'riskTier': risk_tier,
            'isAcceptable': is_acceptable,
            'minimumAcceptableScore': min_acceptable,
            'breakdown': breakdown,
            'evaluatedAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

    @staticmethod
    def issue_risk_receipt(
        credential: Dict[str, Any],
        evaluator_key_pair: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        eval_result = TrustScoreEngine.calculate_trust_score(credential, options)
        receipt_id = 'urn:docutrust:receipt:' + sha256_hex(canonicalize_json({
            'credId': credential.get('id', 'anonymous'),
            'score': eval_result['overallScore'],
            'timestamp': eval_result['evaluatedAt']
        }))[:32]

        receipt_payload = {
            'type': 'DocuTrustRiskReceipt2026',
            'receiptId': receipt_id,
            'credentialId': credential.get('id', 'urn:uuid:anonymous'),
            'overallScore': eval_result['overallScore'],
            'riskTier': eval_result['riskTier'],
            'isAcceptable': eval_result['isAcceptable'],
            'breakdown': eval_result['breakdown'],
            'evaluatorDid': evaluator_key_pair.get('did', 'did:key:evaluator'),
            'timestamp': eval_result['evaluatedAt']
        }

        canon = canonicalize_json(receipt_payload)
        priv_key = evaluator_key_pair.get('privateKeyHex', '')
        signature_hex = hmac.new(priv_key.encode('utf-8'), canon.encode('utf-8'), hashlib.sha256).hexdigest()

        return {
            **receipt_payload,
            'signatureHex': signature_hex
        }

    @staticmethod
    def verify_risk_receipt(
        receipt: Dict[str, Any],
        evaluator_public_key: str
    ) -> Dict[str, Any]:
        errors = []
        if receipt.get('type') != 'DocuTrustRiskReceipt2026':
            errors.append('Invalid receipt type. Expected DocuTrustRiskReceipt2026')

        receipt_copy = {k: v for k, v in receipt.items() if k != 'signatureHex'}
        canon = canonicalize_json(receipt_copy)
        sig = receipt.get('signatureHex', '')

        if not sig or len(sig) < 32:
            errors.append('Invalid cryptographic receipt signature')

        valid = len(errors) == 0
        return {
            'valid': valid,
            'overallScore': receipt.get('overallScore', 0),
            'riskTier': receipt.get('riskTier', 'C'),
            'isAcceptable': receipt.get('isAcceptable', False),
            'errors': errors
        }
