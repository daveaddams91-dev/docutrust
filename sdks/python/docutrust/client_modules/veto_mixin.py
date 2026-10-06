from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class VetoMixin:

    def veto_social_recovery(
        self,
        session: Dict[str, Any],
        reason: str = "Unauthorized recovery attempt"
    ) -> Dict[str, Any]:
        """Genuine owner vetoes fraudulent recovery session."""
        from .social_recovery import SocialRecoveryEngine
        return SocialRecoveryEngine.veto_recovery(session, reason)
