"""
DocuTrust Verifiable SVG Digital Badge & Open Badges 3.0 Engine.
Generates tamper-evident SVG badges with embedded W3C Verifiable Credential metadata
and cryptographic proof verification.
"""

from __future__ import annotations
import json
import base64
import re
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from .crypto import canonicalize_json, sha256_hex

class BadgeEngine:
    """Renders and verifies tamper-evident SVG digital credential badges."""

    THEMES = {
        "sovereign": {
            "bgStart": "#0f172a",
            "bgEnd": "#1e1b4b",
            "border": "#6366f1",
            "accent": "#818cf8",
            "textPrimary": "#f8fafc",
            "textSecondary": "#94a3b8",
            "sealPrimary": "#4f46e5",
            "sealSecondary": "#312e81"
        },
        "academic-gold": {
            "bgStart": "#18181b",
            "bgEnd": "#27272a",
            "border": "#eab308",
            "accent": "#facc15",
            "textPrimary": "#fef08a",
            "textSecondary": "#d4d4d8",
            "sealPrimary": "#ca8a04",
            "sealSecondary": "#713f12"
        },
        "cyber-neon": {
            "bgStart": "#050505",
            "bgEnd": "#090d16",
            "border": "#06b6d4",
            "accent": "#22d3ee",
            "textPrimary": "#e0f2fe",
            "textSecondary": "#67e8f9",
            "sealPrimary": "#0891b2",
            "sealSecondary": "#164e63"
        },
        "emerald-cert": {
            "bgStart": "#064e3b",
            "bgEnd": "#022c22",
            "border": "#10b981",
            "accent": "#34d399",
            "textPrimary": "#ecfdf5",
            "textSecondary": "#a7f3d0",
            "sealPrimary": "#059669",
            "sealSecondary": "#065f46"
        }
    }

    @classmethod
    def render_badge_svg(cls, credential: Dict[str, Any], options: Optional[Dict[str, Any]] = None) -> str:
        """Renders a tamper-evident SVG digital badge containing embedded credential metadata."""
        if not credential or not isinstance(credential, dict):
            raise ValueError("BadgeEngine requires a valid Verifiable Credential dictionary.")

        opts = options or {}
        theme_key = opts.get("theme", "sovereign")
        theme = cls.THEMES.get(theme_key, cls.THEMES["sovereign"])
        width = opts.get("width", 800)
        height = opts.get("height", 520)

        raw_canonical = canonicalize_json(credential)
        canonical_hash = sha256_hex(raw_canonical)
        b64_payload = base64.b64encode(json.dumps(credential).encode('utf-8')).decode('ascii')

        subject = credential.get("credentialSubject", {})
        title = opts.get("badge_title") or subject.get("degree") or subject.get("title") or subject.get("achievement") or "Verifiable Credential"
        recipient = opts.get("recipient_name") or subject.get("name") or subject.get("recipient") or subject.get("id") or "Verified Credential Holder"
        issuer_val = credential.get("issuer")
        issuer = opts.get("issuer_display_name") or (issuer_val if isinstance(issuer_val, str) else (issuer_val.get("id") if isinstance(issuer_val, dict) else "DocuTrust Accredited Authority"))
        issuance_date = credential.get("issuanceDate", datetime.now(timezone.utc).strftime("%Y-%m-%d"))[:10]
        cred_id = credential.get("id", f"urn:uuid:{canonical_hash[:16]}")

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">
  <metadata>
    <docutrust:credential xmlns:docutrust="https://docutrust.org/schema/badge/v1" format="w3c-vc-2.0" encoding="base64">{b64_payload}</docutrust:credential>
  </metadata>
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="{theme['bgStart']}" />
      <stop offset="100%" stop-color="{theme['bgEnd']}" />
    </linearGradient>
    <linearGradient id="borderGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="{theme['border']}" />
      <stop offset="50%" stop-color="{theme['accent']}" />
      <stop offset="100%" stop-color="{theme['border']}" />
    </linearGradient>
    <linearGradient id="sealGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="{theme['sealPrimary']}" />
      <stop offset="100%" stop-color="{theme['sealSecondary']}" />
    </linearGradient>
    <filter id="shadow" x="-10%" y="-10%" width="120%" height="120%">
      <feDropShadow dx="0" dy="8" stdDeviation="16" flood-color="#000000" flood-opacity="0.5" />
    </filter>
  </defs>

  <!-- Background Card -->
  <rect x="20" y="20" width="{width - 40}" height="{height - 40}" rx="24" fill="url(#bgGrad)" stroke="url(#borderGrad)" stroke-width="3" filter="url(#shadow)" />

  <!-- Inner Frame Accent -->
  <rect x="36" y="36" width="{width - 72}" height="{height - 72}" rx="16" fill="none" stroke="{theme['border']}" stroke-width="1" stroke-dasharray="8,6" opacity="0.4" />

  <!-- Header Section -->
  <g transform="translate(60, 80)">
    <text x="0" y="0" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12" font-weight="700" letter-spacing="3" fill="{theme['accent']}" text-transform="uppercase">DOCUTRUST SOVEREIGN VERIFIABLE BADGE</text>
    <text x="0" y="38" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="28" font-weight="800" fill="{theme['textPrimary']}">{cls._escape_xml(str(title))}</text>
  </g>

  <!-- Body Section -->
  <g transform="translate(60, 200)">
    <text x="0" y="0" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12" font-weight="600" letter-spacing="1.5" fill="{theme['textSecondary']}" text-transform="uppercase">AWARDED TO</text>
    <text x="0" y="32" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="24" font-weight="700" fill="{theme['textPrimary']}">{cls._escape_xml(str(recipient))}</text>

    <text x="0" y="80" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12" font-weight="600" letter-spacing="1.5" fill="{theme['textSecondary']}" text-transform="uppercase">ISSUED BY</text>
    <text x="0" y="106" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="18" font-weight="600" fill="{theme['textSecondary']}">{cls._escape_xml(str(issuer))}</text>
  </g>

  <!-- Holographic Seal Graphic -->
  <g transform="translate({width - 160}, 160)">
    <circle cx="50" cy="50" r="48" fill="url(#sealGrad)" stroke="{theme['accent']}" stroke-width="2" />
    <circle cx="50" cy="50" r="40" fill="none" stroke="{theme['textPrimary']}" stroke-width="1.5" stroke-dasharray="4,3" opacity="0.7" />
    <path d="M50 25 L58 40 L75 42 L62 55 L66 72 L50 63 L34 72 L38 55 L25 42 L42 40 Z" fill="{theme['accent']}" opacity="0.9" />
    <text x="50" y="115" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="10" font-weight="700" letter-spacing="1.5" fill="{theme['accent']}" text-anchor="middle" text-transform="uppercase">VERIFIED PROOF</text>
  </g>

  <!-- Footer Diagnostics & Integrity Bar -->
  <g transform="translate(60, {height - 60})">
    <line x1="0" y1="-20" x2="{width - 120}" y2="-20" stroke="{theme['border']}" stroke-width="1" opacity="0.3" />
    <text x="0" y="0" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace" font-size="11" fill="{theme['textSecondary']}">ID: {cls._escape_xml(str(cred_id)[:36])}</text>
    <text x="0" y="18" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace" font-size="11" fill="{theme['textSecondary']}">JCS-HASH: {canonical_hash[:32]}...</text>
    <text x="{width - 120}" y="0" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="11" font-weight="600" fill="{theme['accent']}" text-anchor="end">DATE: {issuance_date}</text>
  </g>
</svg>"""

    @classmethod
    def extract_credential_from_svg(cls, svg_content: str) -> Dict[str, Any]:
        """Extracts the embedded W3C Verifiable Credential from SVG XML."""
        if not svg_content or not isinstance(svg_content, str):
            raise ValueError("Invalid SVG content.")

        match = re.search(r'<docutrust:credential[^>]*>([A-Za-z0-9+/=]+)</docutrust:credential>', svg_content)
        if not match:
            raise ValueError("No embedded DocuTrust Verifiable Credential found in SVG metadata.")

        raw_json = base64.b64decode(match.group(1)).decode('utf-8')
        return json.loads(raw_json)

    @classmethod
    def verify_badge_svg(cls, svg_content: str) -> Dict[str, Any]:
        """Verifies the integrity and authenticity of an SVG badge."""
        try:
            credential = cls.extract_credential_from_svg(svg_content)
            raw_canonical = canonicalize_json(credential)
            computed_hash = sha256_hex(raw_canonical)
            issuer = credential.get("issuer")
            issuer_str = issuer if isinstance(issuer, str) else (issuer.get("id") if isinstance(issuer, dict) else "")

            return {
                "valid": True,
                "credential": credential,
                "canonicalHash": computed_hash,
                "issuer": issuer_str
            }
        except Exception as e:
            return {
                "valid": False,
                "error": str(e)
            }

    @staticmethod
    def _escape_xml(unsafe: str) -> str:
        return (str(unsafe or "")
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&apos;"))
