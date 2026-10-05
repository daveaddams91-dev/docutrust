from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class TimelockMixin:

    def timelock_generate_vdf_parameters(
        self,
        difficulty_t: int = 2000
    ) -> Dict[str, Any]:
        """Generates publicly auditable VDF parameters."""
        from .timelock_encryption import TimelockEncryptionEngine
        return TimelockEncryptionEngine.generate_vdf_parameters(difficulty_t)

    def timelock_evaluate_vdf(
        self,
        params: Dict[str, Any],
        input_seed: Optional[str] = None
    ) -> Dict[str, Any]:
        """Evaluates the sequential squaring VDF loop."""
        from .timelock_encryption import TimelockEncryptionEngine
        return TimelockEncryptionEngine.evaluate_vdf(params, input_seed)

    def timelock_verify_vdf_proof(
        self,
        proof: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verifies a Wesolowski VDF proof in O(1) group multiplications."""
        from .timelock_encryption import TimelockEncryptionEngine
        return TimelockEncryptionEngine.verify_vdf_proof(proof)

    def timelock_seal_credential(
        self,
        payload: Any,
        delay_seconds: int = 10,
        difficulty_t: int = 1000
    ) -> Dict[str, Any]:
        """Locks a credential payload until the required VDF work or unlock time is elapsed."""
        from .timelock_encryption import TimelockEncryptionEngine
        return TimelockEncryptionEngine.seal_timelock_credential(payload, delay_seconds, difficulty_t)

    def timelock_unseal_credential(
        self,
        envelope: Dict[str, Any],
        vdf_proof: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Unlocks and decrypts a timelocked credential using a valid VDF proof."""
        from .timelock_encryption import TimelockEncryptionEngine
        return TimelockEncryptionEngine.unseal_timelock_credential(envelope, vdf_proof)
