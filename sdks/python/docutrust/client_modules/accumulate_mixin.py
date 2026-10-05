from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class AccumulateMixin:

    def accumulate_revocation_lattice(
        self,
        state: Dict[str, Any],
        revoked_credential_ids: List[str],
        advance_epoch: bool = False
    ) -> Dict[str, Any]:
        """Accumulates credential revocations into lattice slices and advances epochs."""
        from .revocation_lattice import RevocationLatticeEngine
        return RevocationLatticeEngine.accumulate_revocations(state, revoked_credential_ids, advance_epoch)
