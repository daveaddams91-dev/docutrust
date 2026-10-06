from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class GetMixin:

    def get_hashchain(self) -> Dict[str, Any]:
        """Retrieves tamper-evident hashchain and verifies audit integrity."""
        url = f"{self.api_url}/ledger/hashchain"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def get_vault_metrics(self) -> Dict[str, Any]:
        """Gets credential vault metrics and telemetry."""
        url = f"{self.api_url}/vault/metrics"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def get_trust_registry_issuers(self) -> Dict[str, Any]:
        """Retrieves all accredited issuers from the trust registry via API."""
        return self._request("/trust/registry", "GET")

    def get_vault_credentials(
        self,
        search: Optional[str] = None,
        type_filter: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None
    ) -> Dict[str, Any]:
        """Queries stored credentials from the institutional vault."""
        params = []
        if search:
            params.append(f"search={search}")
        if type_filter:
            params.append(f"type={type_filter}")
        if limit is not None:
            params.append(f"limit={limit}")
        if offset is not None:
            params.append(f"offset={offset}")
        qs = f"?{'&'.join(params)}" if params else ""
        return self._request(f"/vault/credentials{qs}", "GET")

    def get_audit_bundle_compliance_report(
        self,
        bundle: Dict[str, Any],
        expected_signer_public_key_hex: Optional[str] = None
    ) -> str:
        """Verifies an audit bundle and generates a formal Markdown compliance report."""
        from .bundle import AuditBundleEngine
        result = AuditBundleEngine.verify_audit_bundle(bundle, expected_signer_public_key_hex)
        return AuditBundleEngine.generate_compliance_report(bundle, result)
