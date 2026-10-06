from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class UnblindMixin:

    def unblind_anoncreds_credential(
        self,
        blind_credential: Dict[str, Any],
        master_secret: str,
        blinding_factor: str
    ) -> Dict[str, Any]:
        """Holder unblinds the blind credential and stores it with their master secret."""
        from .anoncreds import AnonCredsEngine
        return AnonCredsEngine.unblind_credential(blind_credential, master_secret, blinding_factor)
