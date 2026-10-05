from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class SealMixin:

    def seal_credential_with_quantum_armor(
        self,
        payload: Dict[str, Any],
        recipient_hybrid_pub: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Seals a credential payload in a quantum-armored envelope."""
        from .quantum_armor import DualHybridKEMEngine
        return DualHybridKEMEngine.seal_credential(payload, recipient_hybrid_pub)
