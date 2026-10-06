from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class InitiateMixin:

    def initiate_social_recovery(
        self,
        owner_did: str,
        requester_did: str,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Initiates a timelocked social recovery session."""
        from .social_recovery import SocialRecoveryEngine
        return SocialRecoveryEngine.initiate_recovery(owner_did, requester_did, config)
