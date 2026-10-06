from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class ProveMixin:

    def prove_zk_range(
        self,
        claim_key: str,
        actual_value: float,
        min_val: float,
        max_val: float,
        salt: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates a Zero-Knowledge Range Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/prove"
        payload = {
            "predicateType": "range",
            "claimKey": claim_key,
            "actualValue": actual_value,
            "salt": salt,
            "min": min_val,
            "max": max_val
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def prove_zk_membership(
        self,
        claim_key: str,
        secret_value: str,
        allowed_set: List[str],
        salt: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates a Zero-Knowledge Set Membership Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/prove"
        payload = {
            "predicateType": "membership",
            "claimKey": claim_key,
            "actualValue": secret_value,
            "allowedSet": allowed_set,
            "salt": salt
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def prove_zk_age(
        self,
        birth_date: str,
        minimum_age_years: int = 18,
        claim_key: str = "birthDate",
        salt: Optional[str] = None,
        reference_date: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates a Zero-Knowledge Age Predicate Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/prove-age"
        payload = {
            "claimKey": claim_key,
            "birthDate": birth_date,
            "minimumAgeYears": minimum_age_years,
            "salt": salt,
            "referenceDate": reference_date
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def prove_zk_date(
        self,
        actual_date: str,
        min_date: str,
        max_date: str,
        claim_key: str = "date",
        salt: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates a Zero-Knowledge Date Range Proof."""
        url = f"{self.api_url}/credentials/zk-predicate/prove-date"
        payload = {
            "claimKey": claim_key,
            "actualDate": actual_date,
            "minDate": min_date,
            "maxDate": max_date,
            "salt": salt
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()

    def prove_set_non_membership(
        self,
        claim_key: str,
        secret_value: str,
        salt: str,
        restricted_set: List[str]
    ) -> Dict[str, Any]:
        """Generates ZK proof that secret_value is NOT in restricted set."""
        from .zk_predicates import prove_set_non_membership
        return prove_set_non_membership(claim_key, secret_value, salt, restricted_set)

    def prove_composite_predicate(self, proofs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Combines multiple ZK predicate proofs into a single composite proof."""
        from .zk_predicates import prove_composite_predicate
        return prove_composite_predicate(proofs)

    def prove_set_intersection(
        self,
        claim_key: str,
        secret_value: str,
        salt: str,
        target_set: List[str]
    ) -> Dict[str, Any]:
        """Generates ZK Set Intersection Proof."""
        from .zk_predicates import prove_set_intersection
        return prove_set_intersection(claim_key, secret_value, salt, target_set)

    def prove_zk_predicate_graph(
        self,
        graph_id: str,
        root_node: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generates a recursive Zero-Knowledge Predicate Graph Proof."""
        from .zk_predicates import prove_predicate_graph
        return prove_predicate_graph(graph_id, root_node)

    def prove_confidential_threshold(
        self,
        claim_key: str,
        actual_value: int,
        threshold: int,
        operator: str,
        public_key: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generates a confidential zero-knowledge threshold proof."""
        from .confidential import ConfidentialClaimsEngine
        return ConfidentialClaimsEngine.prove_threshold(claim_key, actual_value, threshold, operator, public_key)

    def prove_groth16(self, circuit_name: str, public_inputs: List[Any], witness_secret: Optional[Any] = None) -> Dict[str, Any]:
        """Generates a BN254 Groth16 Zero-Knowledge proof."""
        from .groth16 import Groth16Engine
        return Groth16Engine.create_proof(circuit_name, public_inputs, witness_secret)

    def prove_zk_dsl(
        self,
        expression: str,
        attributes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Synthesizes a non-interactive zero-knowledge proof for a predicate DSL."""
        from .zk_dsl import ZKDSLEngine
        return ZKDSLEngine.generate_proof(expression, attributes)
