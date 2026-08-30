/**
 * @file packages/core/src/badge/index.ts
 * @description Verifiable SVG Digital Badge & Open Badges 3.0 Engine
 * Generates tamper-evident SVG badges with embedded W3C Verifiable Credential metadata,
 * holographic verification seals, and cryptographic proof verification.
 */

import { canonicalizeJson, sha256Hex } from '../crypto/index.js';
import { VerifiableCredentialsEngine } from '../vc/index.js';

export interface BadgeRenderOptions {
  theme?: 'sovereign' | 'academic-gold' | 'cyber-neon' | 'emerald-cert' | 'obsidian-noir' | 'royal-amethyst';
  width?: number;
  height?: number;
  includeWatermark?: boolean;
  issuerDisplayName?: string;
  badgeTitle?: string;
  recipientName?: string;
  criteriaUrl?: string;
  criteriaNarrative?: string;
}

export interface BadgeVerificationResult {
  valid: boolean;
  credential?: any;
  canonicalHash?: string;
  issuer?: string;
  error?: string;
}

export class BadgeEngine {
  /**
   * Themes for SVG rendering.
   */
  private static THEMES = {
    sovereign: {
      bgStart: '#0f172a',
      bgEnd: '#1e1b4b',
      border: '#6366f1',
      accent: '#818cf8',
      textPrimary: '#f8fafc',
      textSecondary: '#94a3b8',
      sealPrimary: '#4f46e5',
      sealSecondary: '#312e81'
    },
    'academic-gold': {
      bgStart: '#18181b',
      bgEnd: '#27272a',
      border: '#eab308',
      accent: '#facc15',
      textPrimary: '#fef08a',
      textSecondary: '#d4d4d8',
      sealPrimary: '#ca8a04',
      sealSecondary: '#713f12'
    },
    'cyber-neon': {
      bgStart: '#050505',
      bgEnd: '#090d16',
      border: '#06b6d4',
      accent: '#22d3ee',
      textPrimary: '#e0f2fe',
      textSecondary: '#67e8f9',
      sealPrimary: '#0891b2',
      sealSecondary: '#164e63'
    },
    'emerald-cert': {
      bgStart: '#064e3b',
      bgEnd: '#022c22',
      border: '#10b981',
      accent: '#34d399',
      textPrimary: '#ecfdf5',
      textSecondary: '#a7f3d0',
      sealPrimary: '#059669',
      sealSecondary: '#065f46'
    },
    'obsidian-noir': {
      bgStart: '#09090b',
      bgEnd: '#18181b',
      border: '#a1a1aa',
      accent: '#f4f4f5',
      textPrimary: '#fafafa',
      textSecondary: '#a1a1aa',
      sealPrimary: '#27272a',
      sealSecondary: '#09090b'
    },
    'royal-amethyst': {
      bgStart: '#2e1065',
      bgEnd: '#170530',
      border: '#c084fc',
      accent: '#e879f9',
      textPrimary: '#fdf4ff',
      textSecondary: '#e9d5ff',
      sealPrimary: '#9333ea',
      sealSecondary: '#581c87'
    }
  };

  /**
   * Renders a Verifiable SVG digital badge with embedded credential metadata.
   */
  public static renderBadgeSvg(credential: any, options: BadgeRenderOptions = {}): string {
    if (!credential || typeof credential !== 'object') {
      throw new Error('BadgeEngine requires a valid Verifiable Credential object.');
    }

    const themeKey = options.theme || 'sovereign';
    const theme = this.THEMES[themeKey] || this.THEMES.sovereign;
    const width = options.width || 800;
    const height = options.height || 520;

    const rawCanonical = canonicalizeJson(credential);
    const canonicalHash = sha256Hex(rawCanonical);
    const b64Payload = Buffer.from(JSON.stringify(credential), 'utf8').toString('base64');

    const subject = credential.credentialSubject || {};
    const title = options.badgeTitle || subject.degree || subject.title || subject.achievement || (Array.isArray(credential.type) ? credential.type[credential.type.length - 1] : 'Verifiable Credential');
    const recipient = options.recipientName || subject.name || subject.recipient || subject.id || 'Verified Credential Holder';
    const issuer = options.issuerDisplayName || (typeof credential.issuer === 'string' ? credential.issuer : credential.issuer?.id || 'DocuTrust Accredited Authority');
    const issuanceDateStr = credential.validFrom || credential.issuanceDate;
    const issuanceDate = issuanceDateStr ? new Date(issuanceDateStr).toISOString().split('T')[0] : new Date().toISOString().split('T')[0];
    const credId = credential.id || `urn:uuid:${canonicalHash.slice(0, 16)}`;

    return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
  <metadata>
    <docutrust:credential xmlns:docutrust="https://docutrust.org/schema/badge/v1" format="w3c-vc-2.0" encoding="base64">${b64Payload}</docutrust:credential>
  </metadata>
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${theme.bgStart}" />
      <stop offset="100%" stop-color="${theme.bgEnd}" />
    </linearGradient>
    <linearGradient id="borderGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${theme.border}" />
      <stop offset="50%" stop-color="${theme.accent}" />
      <stop offset="100%" stop-color="${theme.border}" />
    </linearGradient>
    <linearGradient id="sealGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${theme.sealPrimary}" />
      <stop offset="100%" stop-color="${theme.sealSecondary}" />
    </linearGradient>
    <filter id="shadow" x="-10%" y="-10%" width="120%" height="120%">
      <feDropShadow dx="0" dy="8" stdDeviation="16" flood-color="#000000" flood-opacity="0.5" />
    </filter>
  </defs>

  <!-- Background Card -->
  <rect x="20" y="20" width="${width - 40}" height="${height - 40}" rx="24" fill="url(#bgGrad)" stroke="url(#borderGrad)" stroke-width="3" filter="url(#shadow)" />

  <!-- Inner Frame Accent -->
  <rect x="36" y="36" width="${width - 72}" height="${height - 72}" rx="16" fill="none" stroke="${theme.border}" stroke-width="1" stroke-dasharray="8,6" opacity="0.4" />

  <!-- Header Section -->
  <g transform="translate(60, 80)">
    <text x="0" y="0" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12" font-weight="700" letter-spacing="3" fill="${theme.accent}" text-transform="uppercase">DOCUTRUST SOVEREIGN VERIFIABLE BADGE</text>
    <text x="0" y="38" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="28" font-weight="800" fill="${theme.textPrimary}">${this.escapeXml(title)}</text>
  </g>

  <!-- Body Section -->
  <g transform="translate(60, 200)">
    <text x="0" y="0" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12" font-weight="600" letter-spacing="1.5" fill="${theme.textSecondary}" text-transform="uppercase">AWARDED TO</text>
    <text x="0" y="32" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="24" font-weight="700" fill="${theme.textPrimary}">${this.escapeXml(recipient)}</text>

    <text x="0" y="80" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12" font-weight="600" letter-spacing="1.5" fill="${theme.textSecondary}" text-transform="uppercase">ISSUED BY</text>
    <text x="0" y="106" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="18" font-weight="600" fill="${theme.textSecondary}">${this.escapeXml(issuer)}</text>
  </g>

  <!-- Holographic Seal Graphic -->
  <g transform="translate(${width - 160}, 160)">
    <circle cx="50" cy="50" r="48" fill="url(#sealGrad)" stroke="${theme.accent}" stroke-width="2" />
    <circle cx="50" cy="50" r="40" fill="none" stroke="${theme.textPrimary}" stroke-width="1.5" stroke-dasharray="4,3" opacity="0.7" />
    <path d="M50 25 L58 40 L75 42 L62 55 L66 72 L50 63 L34 72 L38 55 L25 42 L42 40 Z" fill="${theme.accent}" opacity="0.9" />
    <text x="50" y="115" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="10" font-weight="700" letter-spacing="1.5" fill="${theme.accent}" text-anchor="middle" text-transform="uppercase">VERIFIED PROOF</text>
  </g>

  <!-- Footer Diagnostics & Integrity Bar -->
  <g transform="translate(60, ${height - 60})">
    <line x1="0" y1="-20" x2="${width - 120}" y2="-20" stroke="${theme.border}" stroke-width="1" opacity="0.3" />
    <text x="0" y="0" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace" font-size="11" fill="${theme.textSecondary}">ID: ${this.escapeXml(credId.slice(0, 36))}</text>
    <text x="0" y="18" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace" font-size="11" fill="${theme.textSecondary}">JCS-HASH: ${canonicalHash.slice(0, 32)}...</text>
    <text x="${width - 120}" y="0" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="11" font-weight="600" fill="${theme.accent}" text-anchor="end">DATE: ${issuanceDate}</text>
  </g>
</svg>`;
  }

  /**
   * Extracts embedded W3C Verifiable Credential from SVG XML content.
   */
  public static extractCredentialFromSvg(svgContent: string): any {
    if (!svgContent || typeof svgContent !== 'string') {
      throw new Error('Invalid SVG content.');
    }

    const match = svgContent.match(/<docutrust:credential[^>]*>([A-Za-z0-9+/=]+)<\/docutrust:credential>/);
    if (!match || !match[1]) {
      throw new Error('No embedded DocuTrust Verifiable Credential found in SVG metadata.');
    }

    const jsonStr = Buffer.from(match[1], 'base64').toString('utf8');
    return JSON.parse(jsonStr);
  }

  /**
   * Verifies the cryptographic authenticity and integrity of an SVG badge.
   */
  public static async verifyBadgeSvg(svgContent: string): Promise<BadgeVerificationResult> {
    try {
      const credential = this.extractCredentialFromSvg(svgContent);
      const rawCanonical = canonicalizeJson(credential);
      const computedHash = sha256Hex(rawCanonical);

      // Verify the credential using standard VC engine
      const vcVerifyResult = await VerifiableCredentialsEngine.verify(credential);

      return {
        valid: vcVerifyResult.valid,
        credential,
        canonicalHash: computedHash,
        issuer: typeof credential.issuer === 'string' ? credential.issuer : credential.issuer?.id,
        error: vcVerifyResult.valid ? undefined : (vcVerifyResult.errors?.join(', ') || 'Cryptographic proof verification failed.')
      };
    } catch (err: any) {
      return {
        valid: false,
        error: err.message || 'Failed to parse and verify SVG badge.'
      };
    }
  }

  private static escapeXml(unsafe: string): string {
    return String(unsafe || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }
}
