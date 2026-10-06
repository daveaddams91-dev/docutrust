from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class UnsealMixin:

    def unseal_credential_with_quantum_armor(
        self,
        envelope: Dict[str, Any],
        recipient_hybrid_priv: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Unseals a quantum-armored envelope."""
        from .quantum_armor import DualHybridKEMEngine
        return DualHybridKEMEngine.unseal_credential(envelope, recipient_hybrid_priv)
