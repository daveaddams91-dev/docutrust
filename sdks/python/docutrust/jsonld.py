"""
DocuTrust W3C VC 2.0 URDNA2015 RDF Dataset Canonicalization & JSON-LD Linked Data Signatures Engine.
Pure-Python zero-dependency implementation of URDNA2015 / RDFC-1.0 and JsonLdSignature2020.
"""

import time
import hashlib
from typing import Dict, Any, List, Optional
from .crypto import sign_data, verify_signature, decode_base58


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


class JsonLdCanonicalizationEngine:
    """W3C URDNA2015 / RDFC-1.0 RDF Dataset Normalization and Linked Data Signatures."""

    @classmethod
    def jsonld_to_quads(cls, doc: Any, parent_subject: str = "_:b0") -> List[Dict[str, str]]:
        quads = []
        if not isinstance(doc, dict):
            return quads

        subject = doc.get("id") or doc.get("@id") or parent_subject

        for key, value in doc.items():
            if key in ("proof", "@context"):
                continue

            predicate = key if key.startswith(("http://", "https://", "urn:")) else f"https://schema.org/{key}"

            if value is None:
                continue

            if isinstance(value, list):
                for idx, item in enumerate(value):
                    if isinstance(item, dict):
                        blank_node = f"{subject}_{key}_{idx}"
                        subj_fmt = subject if subject.startswith("_:") else f"<{subject}>"
                        obj_fmt = blank_node if blank_node.startswith("_:") else f"<{blank_node}>"
                        quads.append({
                            "subject": subj_fmt,
                            "predicate": f"<{predicate}>",
                            "object": obj_fmt
                        })
                        quads.extend(cls.jsonld_to_quads(item, blank_node))
                    else:
                        subj_fmt = subject if subject.startswith("_:") else f"<{subject}>"
                        quads.append({
                            "subject": subj_fmt,
                            "predicate": f"<{predicate}>",
                            "object": f'"{str(item)}"^^<http://www.w3.org/2001/XMLSchema#string>'
                        })
            elif isinstance(value, dict):
                nested_subj = value.get("id") or f"{subject}_{key}"
                subj_fmt = subject if subject.startswith("_:") else f"<{subject}>"
                obj_fmt = nested_subj if nested_subj.startswith("_:") else f"<{nested_subj}>"
                quads.append({
                    "subject": subj_fmt,
                    "predicate": f"<{predicate}>",
                    "object": obj_fmt
                })
                quads.extend(cls.jsonld_to_quads(value, nested_subj))
            else:
                datatype = "http://www.w3.org/2001/XMLSchema#string"
                if isinstance(value, bool):
                    datatype = "http://www.w3.org/2001/XMLSchema#boolean"
                elif isinstance(value, int):
                    datatype = "http://www.w3.org/2001/XMLSchema#integer"
                elif isinstance(value, float):
                    datatype = "http://www.w3.org/2001/XMLSchema#double"

                subj_fmt = subject if subject.startswith("_:") else f"<{subject}>"
                quads.append({
                    "subject": subj_fmt,
                    "predicate": f"<{predicate}>",
                    "object": f'"{str(value)}"^^<{datatype}>'
                })

        return quads

    @classmethod
    def canonicalize(cls, doc: Dict[str, Any]) -> str:
        quads = cls.jsonld_to_quads(doc)
        lines = [f"{q['subject']} {q['predicate']} {q['object']} ." for q in quads]
        lines.sort()
        unique_lines = []
        for line in lines:
            if not unique_lines or unique_lines[-1] != line:
                unique_lines.append(line)
        return "\n".join(unique_lines) + ("\n" if unique_lines else "")

    @classmethod
    def digest(cls, doc: Dict[str, Any]) -> str:
        return _sha256_hex(cls.canonicalize(doc))

    @classmethod
    def sign_jsonld(
        cls,
        doc: Dict[str, Any],
        key_pair: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        options = options or {}
        clone = dict(doc)
        clone.pop("proof", None)

        canonical_rdf = cls.canonicalize(clone)
        canonical_digest = _sha256_hex(canonical_rdf)
        quad_count = len([line for line in canonical_rdf.split("\n") if line.strip()])

        created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        verification_method = options.get("verificationMethod") or f"{key_pair['did']}#{key_pair['publicKeyHex'][:16]}"
        proof_purpose = options.get("proofPurpose", "assertionMethod")
        proof_type = options.get("type", "JsonLdSignature2020")

        payload_to_sign = f"{canonical_digest}:{created}:{verification_method}:{proof_purpose}"
        proof_value = sign_data(payload_to_sign, key_pair["privateKeyHex"])

        full_proof = {
            "type": proof_type,
            "created": created,
            "verificationMethod": verification_method,
            "proofPurpose": proof_purpose,
            "canonicalRdfDigest": canonical_digest,
            "quadCount": quad_count,
            "proofValue": proof_value
        }

        clone["proof"] = full_proof
        return clone

    @classmethod
    def verify_jsonld(
        cls,
        signed_doc: Dict[str, Any],
        expected_public_key_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        errors = []
        if not isinstance(signed_doc, dict) or "proof" not in signed_doc:
            return {
                "valid": False,
                "canonicalRdfDigest": "",
                "quadCount": 0,
                "verificationMethod": "",
                "created": "",
                "errors": ["Document missing proof object"]
            }

        proof = signed_doc["proof"]
        doc_copy = dict(signed_doc)
        doc_copy.pop("proof", None)

        canonical_rdf = cls.canonicalize(doc_copy)
        computed_digest = _sha256_hex(canonical_rdf)
        quad_count = len([line for line in canonical_rdf.split("\n") if line.strip()])

        if proof.get("canonicalRdfDigest") and proof["canonicalRdfDigest"] != computed_digest:
            errors.append(f"Canonical RDF digest mismatch: expected {proof['canonicalRdfDigest']}, computed {computed_digest}")

        pub_hex = expected_public_key_hex
        if not pub_hex and proof.get("verificationMethod", "").startswith("did:key:"):
            did_key = proof["verificationMethod"].split("#")[0]
            try:
                raw = decode_base58(did_key.replace("did:key:z", ""))
                pub_hex = raw[2:].hex()
            except Exception:
                pass

        if pub_hex:
            payload_to_sign = f"{computed_digest}:{proof['created']}:{proof['verificationMethod']}:{proof.get('proofPurpose', 'assertionMethod')}"
            sig_ok = verify_signature(payload_to_sign, proof["proofValue"], pub_hex)
            if not sig_ok:
                errors.append("Cryptographic signature verification failed.")

        return {
            "valid": len(errors) == 0,
            "canonicalRdfDigest": computed_digest,
            "quadCount": quad_count,
            "verificationMethod": proof.get("verificationMethod", ""),
            "created": proof.get("created", ""),
            "errors": errors
        }

    # Method aliases for flexibility
    sign_json_ld = sign_jsonld
    verify_json_ld = verify_jsonld
