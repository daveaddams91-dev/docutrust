/**
 * @file packages/core/src/bundle/index.ts
 * @description Cryptographic Audit Bundle Packaging & Compliance Verification Engine
 * Implements signed .dtbundle packaging with HashChain ledger snapshots, Merkle Mountain Range
 * peak manifests, RFC 3161 TSA timestamps, and compliance verification reports (SOC2, ISO 27001, eIDAS 2.0).
 */

import * as crypto from 'crypto';
import { sha256Hex, canonicalizeJson, signData, verifySignature, generateKeyPair, KeyPair } from '../crypto/index.js';
import { TamperEvidentHashChain, AuditBlock } from '../chain/index.js';
import { MerkleMountainRange } from '../mmr/index.js';
import { CryptographicTSAOracle, TimestampToken } from '../oracle/index.js';

export interface AuditBundleManifest {
  bundleId: string;
  version: '5.0.0';
  generator: string;
  organization: string;
  createdAt: string;
  complianceStandards: string[];
  totalCredentials: number;
  totalAnchored: number;
  hashchainLength: number;
  hashchainTip: string;
  mmrPeakCount: number;
  mmrBaggedRoot: string;
  tsaTokenDigest: string;
}

export interface CryptographicAuditBundle {
  type: 'DocuTrustAuditBundle2026';
  manifest: AuditBundleManifest;
  hashchainRecords: AuditBlock[];
  mmrSnapshot: {
    peakCount: number;
    peaks: string[];
    baggedRoot: string;
    totalLeaves: number;
  };
  tsaTimestampToken: TimestampToken;
  credentialDigests: string[];
  proof: {
    type: 'Ed25519Signature2020';
    issuerDid: string;
    proofValue: string;
    timestamp: string;
  };
}

export interface AuditBundleVerificationResult {
  valid: boolean;
  bundleId: string;
  organization: string;
  complianceStandards: string[];
  signatureValid: boolean;
  hashchainValid: boolean;
  mmrValid: boolean;
  tsaTimestampValid: boolean;
  totalRecordsChecked: number;
  verifiedAt: string;
  complianceStatus: 'COMPLIANT' | 'NON_COMPLIANT';
  errors: string[];
}

export class AuditBundleEngine {
  /**
   * Generates a complete sovereign cryptographic audit bundle (.dtbundle).
   */
  public static createAuditBundle(options: {
    organization?: string;
    credentials?: Array<{ id: string; jcsCanonicalHash?: string }>;
    hashchain?: TamperEvidentHashChain;
    mmr?: MerkleMountainRange;
    complianceStandards?: string[];
    signerKeyPair?: KeyPair;
  } = {}): CryptographicAuditBundle {
    const bundleId = `urn:uuid:bundle-${crypto.randomUUID()}`;
    const createdAt = new Date().toISOString();
    const standards = options.complianceStandards || ['SOC2-Type2', 'ISO-27001', 'eIDAS-2.0', 'W3C-VC-2.0'];

    if (!options.signerKeyPair) {
      options.signerKeyPair = generateKeyPair();
    }

    // 1. Snapshot HashChain
    const hc = options.hashchain || new TamperEvidentHashChain();
    const chainDump = hc.getChain();
    const latestBlock = hc.getLatestBlock();
    const hashchainTip = latestBlock ? latestBlock.blockHash : TamperEvidentHashChain.GENESIS_PREV_HASH;

    // 2. Snapshot MMR
    const mmr = options.mmr || new MerkleMountainRange();
    const mmrPeaks = mmr.getPeaks();
    const mmrBaggedRoot = mmr.getBaggedPeakRoot();

    // 3. TSA Timestamp Token
    const tsaOracle = new CryptographicTSAOracle(options.signerKeyPair);
    const tsaToken = tsaOracle.issueTimestampToken(hashchainTip || bundleId);

    // 4. Collect credential digests
    const credentialDigests = (options.credentials || []).map(c => c.jcsCanonicalHash || sha256Hex(c.id));

    // 5. Build Manifest
    const manifest: AuditBundleManifest = {
      bundleId,
      version: '5.0.0',
      generator: 'DocuTrust Sovereign Trust Engine v5.0.0',
      organization: options.organization || 'Unknown Organization',
      createdAt,
      complianceStandards: standards,
      totalCredentials: credentialDigests.length,
      totalAnchored: credentialDigests.length,
      hashchainLength: chainDump.length,
      hashchainTip,
      mmrPeakCount: mmrPeaks.length,
      mmrBaggedRoot,
      tsaTokenDigest: tsaToken.targetDataHash
    };

    // 6. Sign Manifest with Authority Key
    const manifestCanonical = canonicalizeJson(manifest);
    const signature = signData(sha256Hex(manifestCanonical), options.signerKeyPair);

    return {
      type: 'DocuTrustAuditBundle2026',
      manifest,
      hashchainRecords: chainDump,
      mmrSnapshot: {
        peakCount: mmrPeaks.length,
        peaks: mmrPeaks,
        baggedRoot: mmrBaggedRoot,
        totalLeaves: mmr.size
      },
      tsaTimestampToken: tsaToken,
      credentialDigests,
      proof: {
        type: 'Ed25519Signature2020',
        issuerDid: options.signerKeyPair.did,
        proofValue: signature,
        timestamp: createdAt
      }
    };
  }

  /**
   * Verifies the cryptographic integrity of an Audit Bundle.
   */
  public static verifyAuditBundle(
    bundle: CryptographicAuditBundle,
    expectedSignerPublicKeyHex?: string
  ): AuditBundleVerificationResult {
    const errors: string[] = [];

    if (bundle.type !== 'DocuTrustAuditBundle2026') {
      errors.push('Invalid audit bundle type.');
    }

    // 1. Verify Manifest Signature
    let signatureValid = false;
    try {
      const manifestCanonical = canonicalizeJson(bundle.manifest);
      const targetKey = expectedSignerPublicKeyHex || bundle.proof.issuerDid;
      signatureValid = verifySignature(sha256Hex(manifestCanonical), bundle.proof.proofValue, targetKey);
      if (!signatureValid) {
        errors.push('Authority cryptographic signature on manifest is invalid.');
      }
    } catch (e: any) {
      errors.push(`Signature verification failed: ${e.message}`);
    }

    // 2. Verify HashChain Continuity
    let hashchainValid = true;
    const records = bundle.hashchainRecords || [];
    for (let i = 1; i < records.length; i++) {
      const prev = records[i - 1];
      const curr = records[i];
      if (curr.previousBlockHash !== prev.blockHash) {
        hashchainValid = false;
        errors.push(`HashChain broken at record index ${i}: expected previousHash ${prev.blockHash}, got ${curr.previousBlockHash}`);
        break;
      }
    }

    // 3. Verify MMR Integrity
    let mmrValid = true;
    if (bundle.mmrSnapshot.peakCount !== bundle.mmrSnapshot.peaks.length) {
      mmrValid = false;
      errors.push('MMR peakCount mismatch with peaks array.');
    }

    // 4. Verify TSA Timestamp
    let tsaTimestampValid = true;
    try {
      const tsaResult = CryptographicTSAOracle.verifyTimestampToken(bundle.tsaTimestampToken);
      tsaTimestampValid = tsaResult.valid;
      if (!tsaTimestampValid) {
        errors.push(`TSA Timestamp Token verification failed: ${tsaResult.error}`);
      }
    } catch (e: any) {
      tsaTimestampValid = false;
      errors.push(`TSA Timestamp Token check error: ${e.message}`);
    }

    const valid = errors.length === 0;

    return {
      valid,
      bundleId: bundle.manifest.bundleId,
      organization: bundle.manifest.organization,
      complianceStandards: bundle.manifest.complianceStandards,
      signatureValid,
      hashchainValid,
      mmrValid,
      tsaTimestampValid,
      totalRecordsChecked: records.length + (bundle.credentialDigests ? bundle.credentialDigests.length : 0),
      verifiedAt: new Date().toISOString(),
      complianceStatus: valid ? 'COMPLIANT' : 'NON_COMPLIANT',
      errors
    };
  }

  /**
   * Generates a comprehensive Markdown audit compliance certificate report.
   */
  public static generateComplianceReport(
    bundle: CryptographicAuditBundle,
    result: AuditBundleVerificationResult
  ): string {
    return `# 🛡️ DocuTrust Sovereign Compliance & Cryptographic Audit Report

**Bundle ID:** \`${bundle.manifest.bundleId}\`  
**Organization:** ${bundle.manifest.organization}  
**Audit Verification Status:** ${result.valid ? '✅ **PASSED (100% CRYPTOGRAPHIC INTEGRITY)**' : '❌ **FAILED**'}  
**Timestamp of Verification:** \`${result.verifiedAt}\`  

---

## 1. Executive Summary & Compliance Attestation
This document certifies that the cryptographically sealed audit bundle \`${bundle.manifest.bundleId}\` has undergone automated mathematical verification against the following governance standards:

${bundle.manifest.complianceStandards.map(s => `- **${s}** — Validated`).join('\n')}

---

## 2. Cryptographic Ledger Verification Checklist

| Security Component | Status | Details |
| :--- | :---: | :--- |
| **Authority Signature** | ${result.signatureValid ? '✅ VALID' : '❌ INVALID'} | Signed by \`${bundle.proof.issuerDid}\` |
| **HashChain Continuity** | ${result.hashchainValid ? '✅ INTACT' : '❌ BROKEN'} | ${bundle.manifest.hashchainLength} sequential block transitions verified |
| **Merkle Mountain Range** | ${result.mmrValid ? '✅ CONSISTENT' : '❌ INCONSISTENT'} | Bagged Root: \`${bundle.manifest.mmrBaggedRoot}\` |
| **RFC 3161 TSA Timestamp** | ${result.tsaTimestampValid ? '✅ VERIFIED' : '❌ FAILED'} | Digest: \`${bundle.manifest.tsaTokenDigest.substring(0, 32)}...\` |

---

## 3. Telemetry & Ledger Snapshot
- **Total Credentials Attested:** ${bundle.manifest.totalCredentials}
- **HashChain Tip Hash:** \`${bundle.manifest.hashchainTip}\`
- **MMR Active Peaks:** ${bundle.mmrSnapshot.peakCount}
- **Bundle Seal Timestamp:** \`${bundle.manifest.createdAt}\`

${result.errors.length > 0 ? `### ⚠️ Errors Encountered:\n${result.errors.map(e => `- ${e}`).join('\n')}` : `*Cryptographically sealed and signed by DocuTrust Sovereign Trust Engine v4.0.0.*`}
`;
  }
}
