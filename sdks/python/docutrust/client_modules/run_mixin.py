from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class RunMixin:

    def run_dkg_ceremony(
        self,
        participants: List[Dict[str, Any]],
        threshold: int
    ) -> Dict[str, Any]:
        """Runs a complete Distributed Key Generation (DKG) setup ceremony."""
        from .dkg import DKGEngine
        return DKGEngine.run_dkg_ceremony(participants, threshold)
