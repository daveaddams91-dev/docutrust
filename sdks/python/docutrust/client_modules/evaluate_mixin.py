from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class EvaluateMixin:

    def evaluate_presentation_exchange(
        self,
        presentation: Dict[str, Any],
        definition: Dict[str, Any],
        submission: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Evaluates a Verifiable Presentation against a DIF Presentation Definition."""
        from .presentation_exchange import PresentationExchangeEngine
        return PresentationExchangeEngine.evaluate_presentation(presentation, definition, submission)

    def evaluate_confidential_linear_combination(
        self,
        terms: List[Dict[str, Any]],
        public_key: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluates a homomorphic linear combination (weighted sum) over Paillier ciphertexts."""
        from .confidential import ConfidentialClaimsEngine
        return ConfidentialClaimsEngine.evaluate_linear_combination(terms, public_key)

    def evaluate_policy(
        self,
        payload: Dict[str, Any],
        policy: Dict[str, Any],
        evaluator_keypair: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Evaluates a verifiable credential or presentation against an AST policy."""
        from .policy import PolicyEngine
        return PolicyEngine.evaluate(payload, policy, evaluator_keypair=evaluator_keypair)

    def evaluate_trust_score(
        self,
        credential: Dict[str, Any],
        evaluator_key_pair: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Evaluates multi-vector trust score and optionally issues a signed risk receipt."""
        from .trust_score import TrustScoreEngine
        if evaluator_key_pair:
            return TrustScoreEngine.issue_risk_receipt(credential, evaluator_key_pair, options)
        return TrustScoreEngine.calculate_trust_score(credential, options)

    def evaluate_vrf(
        self,
        input_seed: Union[str, bytes, Dict[str, Any]],
        key_pair: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluates a deterministic Verifiable Random Function (VRF) with proof."""
        from .vrf_oracle import VRFOracleEngine
        return VRFOracleEngine.evaluate(input_seed, key_pair)
