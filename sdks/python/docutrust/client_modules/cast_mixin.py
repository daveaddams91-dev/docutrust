from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class CastMixin:

    def cast_social_recovery_vote(
        self,
        session: Dict[str, Any],
        guardian_did: str,
        share_index: int,
        raw_share_hex: str
    ) -> Dict[str, Any]:
        """Guardian casts vote with decrypted secret share."""
        from .social_recovery import SocialRecoveryEngine
        return SocialRecoveryEngine.cast_vote(session, guardian_did, share_index, raw_share_hex)
