from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class AssembleMixin:

    def assemble_multisig_credential(
        self,
        credential: Dict[str, Any],
        policy: Dict[str, Any],
        signatures: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Assembles a finalized M-of-N MultiSig Verifiable Credential from collected signatures."""
        from .multisig import MultiSigEngine
        return MultiSigEngine.assemble_multisig_credential(credential, policy, signatures)

    def assemble_crosschain_attestation(self, message: Dict[str, Any], signatures: List[Dict[str, Any]], quorum_threshold: int = 1) -> Dict[str, Any]:
        """Assembles relayer signatures into a cross-chain attestation."""
        from .crosschain import CrossChainBridgeEngine
        return CrossChainBridgeEngine.assemble_attestation(message, signatures, quorum_threshold)
