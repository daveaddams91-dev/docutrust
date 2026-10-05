from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class InitializeMixin:

    def initialize_revocation_lattice(
        self,
        lattice_id: str,
        issuer_did: str,
        shards_count: int = 4
    ) -> Dict[str, Any]:
        """Initializes a 2D multi-epoch temporal-spatial revocation lattice."""
        from .revocation_lattice import RevocationLatticeEngine
        return RevocationLatticeEngine.initialize_lattice(lattice_id, issuer_did, shards_count)
