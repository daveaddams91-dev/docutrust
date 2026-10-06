from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class RenderMixin:

    def render_badge_svg(
        self,
        credential: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Renders a tamper-evident SVG digital badge containing embedded credential metadata."""
        from .badge import BadgeEngine
        return BadgeEngine.render_badge_svg(credential, options)
