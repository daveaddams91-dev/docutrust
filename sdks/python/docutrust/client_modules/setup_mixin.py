from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class SetupMixin:

    def setup_social_recovery(
        self,
        owner_did: str,
        secret: str,
        guardians: List[Dict[str, str]],
        threshold: int = 3,
        challenge_period_hours: int = 48
    ) -> Dict[str, Any]:
        """Sets up decentralized social recovery with guardian DIDs."""
        from .social_recovery import SocialRecoveryEngine
        return SocialRecoveryEngine.setup_recovery(owner_did, secret, guardians, threshold, challenge_period_hours)

    def setup_groth16_circuit(self, circuit_name: str, public_input_count: int = 2) -> Dict[str, Any]:
        """Generates a Groth16 circuit verification key."""
        from .groth16 import Groth16Engine
        return Groth16Engine.generate_verification_key(circuit_name, public_input_count)
