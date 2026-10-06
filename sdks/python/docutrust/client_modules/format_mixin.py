from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class FormatMixin:

    def format_multichain_anchor(
        self,
        chain: str,
        merkle_root: str,
        batch_count: int,
        memo: str = "DocuTrust Merkle Batch Anchor"
    ) -> Dict[str, Any]:
        """Generates standardized calldata or payload for multi-chain anchoring."""
        from .multichain import MultiChainLedgerAnchor
        return MultiChainLedgerAnchor.format_anchor(chain, merkle_root, batch_count, memo)
