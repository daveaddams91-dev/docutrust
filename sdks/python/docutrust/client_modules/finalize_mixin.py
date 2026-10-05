from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class FinalizeMixin:

    def finalize_social_recovery(
        self,
        session: Dict[str, Any],
        force_timelock_override: bool = False
    ) -> Dict[str, Any]:
        """Finalizes social recovery session and reconstructs root secret."""
        from .social_recovery import SocialRecoveryEngine
        return SocialRecoveryEngine.finalize_recovery(session, force_timelock_override)
