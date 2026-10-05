from __future__ import annotations
import requests
import base64
import json
from typing import Dict, Any, List, Optional, Union
from .crypto import canonicalize_json, sha256_hex, MerkleTree
from .client_modules import (
    IssueMixin,
    BatchMixin,
    VerifyMixin,
    GenerateMixin,
    EncryptMixin,
    DecryptMixin,
    ProveMixin,
    KemMixin,
    CreateMixin,
    ShamirMixin,
    CheckMixin,
    BbsMixin,
    DidcommMixin,
    MmrMixin,
    GetMixin,
    AutoMixin,
    SignMixin,
    SetupMixin,
    InitiateMixin,
    CastMixin,
    VetoMixin,
    FinalizeMixin,
    FormatMixin,
    ValidateMixin,
    ComputeMixin,
    UpdateMixin,
    EvaluateMixin,
    AssembleMixin,
    ResolveMixin,
    UnblindMixin,
    RunMixin,
    AggregateMixin,
    EncodeMixin,
    HomomorphicMixin,
    CanonicalizeMixin,
    SealMixin,
    UnsealMixin,
    RenderMixin,
    SetMixin,
    ExecuteMixin,
    InitializeMixin,
    AccumulateMixin,
    CompileMixin,
    PqMixin,
    PolyMixin,
    TeeMixin,
    IbcMixin,
    FheMixin,
    FrostMixin,
    PlonkMixin,
    CapabilityMixin,
    StarkMixin,
    AgentMixin,
    PsiMixin,
    ZkmlMixin,
    MpcMixin,
    SwarmMixin,
    TimelockMixin,
    PssMixin,
    VectorMixin,
    ZkMixin,
    MemoryMixin,
    ConfidentialMixin,
    RagMixin
)

class DocuTrustClient(IssueMixin, BatchMixin, VerifyMixin, GenerateMixin, EncryptMixin, DecryptMixin, ProveMixin, KemMixin, CreateMixin, ShamirMixin, CheckMixin, BbsMixin, DidcommMixin, MmrMixin, GetMixin, AutoMixin, SignMixin, SetupMixin, InitiateMixin, CastMixin, VetoMixin, FinalizeMixin, FormatMixin, ValidateMixin, ComputeMixin, UpdateMixin, EvaluateMixin, AssembleMixin, ResolveMixin, UnblindMixin, RunMixin, AggregateMixin, EncodeMixin, HomomorphicMixin, CanonicalizeMixin, SealMixin, UnsealMixin, RenderMixin, SetMixin, ExecuteMixin, InitializeMixin, AccumulateMixin, CompileMixin, PqMixin, PolyMixin, TeeMixin, IbcMixin, FheMixin, FrostMixin, PlonkMixin, CapabilityMixin, StarkMixin, AgentMixin, PsiMixin, ZkmlMixin, MpcMixin, SwarmMixin, TimelockMixin, PssMixin, VectorMixin, ZkMixin, MemoryMixin, ConfidentialMixin, RagMixin):
    """Client for DocuTrust Sovereign Trust API v19.0.0."""

    def __init__(self, api_url: str = "https://api.docutrust.org/api/v1", api_key: Optional[str] = None):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"Authorization": f"Bearer {api_key}"})

    def _request(self, endpoint: str, method: str = "GET", json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Internal helper for executing REST requests."""
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        method = method.upper()
        if method == "GET":
            res = self.session.get(url)
        elif method == "POST":
            res = self.session.post(url, json=json_data or {})
        elif method == "PUT":
            res = self.session.put(url, json=json_data or {})
        elif method == "DELETE":
            res = self.session.delete(url)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        res.raise_for_status()
        return res.json()
