from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class EncodeMixin:

    def encode_solidity_calldata(
        self,
        credential_hash: str,
        merkle_proof: List[Union[str, Dict[str, Any]]],
        root_hash: str
    ) -> Dict[str, Any]:
        """Encodes ABI calldata for calling on-chain verifyCredentialOnChain."""
        from .solidity import SolidityEngine
        return SolidityEngine.encode_verification_calldata(credential_hash, merkle_proof, root_hash)
