from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class BatchMixin:

    def batch_issue(
        self,
        records: List[Dict[str, Any]],
        credential_type: str = "UniversityDegreeCredential",
        anchor_to_ledger: bool = True
    ) -> Dict[str, Any]:
        url = f"{self.api_url}/credentials/issue-batch"
        payload = {
            "records": [{"credentialSubject": r} for r in records],
            "type": ["VerifiableCredential", credential_type],
            "anchorToLedger": anchor_to_ledger
        }
        res = self.session.post(url, json=payload)
        res.raise_for_status()
        return res.json()
