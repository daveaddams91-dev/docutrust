from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class SignMixin:

    def sign_vc_eip712(
        self,
        unsigned_vc: Dict[str, Any],
        key_pair: Dict[str, str],
        domain: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Signs W3C Verifiable Credential using EIP-712 structured typing."""
        from .eip712 import sign_vc_eip712
        return sign_vc_eip712(unsigned_vc, key_pair, domain)

    def sign_multisig_as_authority(
        self,
        canonical_hash: str,
        signer_did: str,
        signer_role: str,
        private_key_hex: str
    ) -> Dict[str, Any]:
        """Signs a canonical hash as an authorized institutional authority."""
        from .multisig import MultiSigEngine
        return MultiSigEngine.sign_as_authority(canonical_hash, signer_did, signer_role, private_key_hex)

    def sign_dkg_share(
        self,
        participant_index: int,
        private_share_hex: str,
        signer_did: str,
        message: Union[str, bytes]
    ) -> Dict[str, Any]:
        """Generates a partial signature share for a message using participant private share."""
        from .dkg import DKGEngine
        return DKGEngine.sign_share(participant_index, private_share_hex, signer_did, message)

    def sign_jsonld(
        self,
        doc: Dict[str, Any],
        key_pair: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Signs a JSON-LD document with Linked Data Signatures."""
        from .jsonld import JsonLdCanonicalizationEngine
        return JsonLdCanonicalizationEngine.sign_jsonld(doc, key_pair, options)

    def sign_ring_signature(
        self,
        message: Union[str, bytes, Dict[str, Any]],
        ring: List[str],
        signer_private_key_hex: str,
        signer_public_key_hex: str
    ) -> Dict[str, Any]:
        """Signs a message anonymously using a 1-of-N Linkable Ring Signature."""
        from .ringsig import RingSignatureEngine
        return RingSignatureEngine.sign(
            message=message,
            ring=ring,
            signer_private_key_hex=signer_private_key_hex,
            signer_public_key_hex=signer_public_key_hex
        )

    def sign_slhdsa(self, message: Any, key_pair: Dict[str, Any]) -> Dict[str, Any]:
        """Signs a message with SLH-DSA."""
        from .slhdsa import SLHDSAEngine
        return SLHDSAEngine.sign(message, key_pair)

    def sign_crosschain_message(self, message: Dict[str, Any], relayer_key_pair: Dict[str, Any]) -> Dict[str, Any]:
        """Signs a cross-chain packet as an authorized relayer."""
        from .crosschain import CrossChainBridgeEngine
        return CrossChainBridgeEngine.sign_message(message, relayer_key_pair)

    def sign_falcon(
        self,
        message: Any,
        private_key_hex: str,
        mode: str = 'Falcon-512'
    ) -> Dict[str, Any]:
        """Signs a payload using post-quantum Falcon lattice signature."""
        from .pqc_falcon import PQCFalconEngine
        return PQCFalconEngine.sign(message, private_key_hex, mode)
