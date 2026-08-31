/**
 * @file packages/core/src/agent-provenance/index.ts
 * @description Autonomous AI Agent Action Attestation & Policy Guardrail Engine (DocuTrust v13.0.0)
 * Generates and cryptographically verifies immutable AI Agent Action Attestations (DocuTrustAgentAttestation2026)
 * binding Agent DIDs, Model Card Fingerprints, Prompt/Context Digests, Tool Execution Traces,
 * Policy Compliance Receipts, and Final Artifact Commitments.
 */

import * as crypto from 'crypto';
import { sha256Hex, signMessage, verifySignature, canonicalizeJson, KeyPair } from '../crypto/index.js';

export interface AgentModelCard {
  modelName: string;
  modelVersion: string;
  provider: string;
  weightsFingerprintHex?: string;
  quantization?: string;
  systemPromptHash?: string;
}

export interface AgentExecutionStep {
  stepIndex: number;
  toolName: string;
  toolArguments: Record<string, any>;
  observationDigest: string;
  stepHash: string;
}

export interface AgentAttestationPayload {
  agentDid: string;
  modelCard: AgentModelCard;
  contextDigest: string;
  promptText?: string;
  executionTrace: AgentExecutionStep[];
  outputArtifact: Record<string, any> | string;
  guardrailPolicyId?: string;
  guardrailPolicyHash?: string;
  guardrailPassed?: boolean;
}

export interface DocuTrustAgentAttestation {
  type: 'DocuTrustAgentAttestation2026';
  attestationId: string;
  agentDid: string;
  modelFingerprint: string;
  contextDigest: string;
  executionTraceHash: string;
  stepCount: number;
  outputCommitment: string;
  guardrailPolicyId?: string;
  guardrailPassed: boolean;
  modelCard: AgentModelCard;
  outputArtifact: Record<string, any> | string;
  signatureHex: string;
  timestamp: string;
}

export interface AgentAttestationVerificationResult {
  valid: boolean;
  attestationId: string;
  agentDid: string;
  modelFingerprint: string;
  stepCount: number;
  guardrailPassed: boolean;
  outputCommitment: string;
  errors: string[];
}

export class AgentProvenanceEngine {
  /**
   * Computes a deterministic model card fingerprint.
   */
  public static computeModelFingerprint(modelCard: AgentModelCard): string {
    const canonical = canonicalizeJson({
      modelName: modelCard.modelName,
      modelVersion: modelCard.modelVersion,
      provider: modelCard.provider,
      weightsFingerprintHex: modelCard.weightsFingerprintHex || 'unspecified',
      quantization: modelCard.quantization || 'float16',
      systemPromptHash: modelCard.systemPromptHash || 'none'
    });
    return sha256Hex(`MODEL_CARD:${canonical}`);
  }

  /**
   * Computes context digest from system prompt, input messages, and environment schemas.
   */
  public static computeContextDigest(contextPayload: Record<string, any> | string): string {
    const canonical = typeof contextPayload === 'string' ? contextPayload : canonicalizeJson(contextPayload);
    return sha256Hex(`AGENT_CONTEXT:${canonical}`);
  }

  /**
   * Issues a signed DocuTrustAgentAttestation2026 for an AI agent's action and output.
   */
  public static issueAttestation(
    payload: AgentAttestationPayload,
    agentKeyPair: KeyPair
  ): DocuTrustAgentAttestation {
    const attestationId = `agent-att-${crypto.randomBytes(8).toString('hex')}`;
    const timestamp = new Date().toISOString();

    const modelFingerprint = this.computeModelFingerprint(payload.modelCard);
    const contextDigest = payload.contextDigest || (payload.promptText ? this.computeContextDigest(payload.promptText) : sha256Hex('EMPTY_CONTEXT'));

    // Process and hash execution trace steps
    const trace = (payload.executionTrace || []).map((step, idx) => {
      const stepHash = sha256Hex(canonicalizeJson({
        stepIndex: idx + 1,
        toolName: step.toolName,
        toolArguments: step.toolArguments,
        observationDigest: step.observationDigest
      }));
      return {
        stepIndex: idx + 1,
        toolName: step.toolName,
        toolArguments: step.toolArguments,
        observationDigest: step.observationDigest,
        stepHash
      };
    });

    const executionTraceHash = sha256Hex(canonicalizeJson(trace));
    const outputCanonical = typeof payload.outputArtifact === 'string' ? payload.outputArtifact : canonicalizeJson(payload.outputArtifact);
    const outputCommitment = sha256Hex(outputCanonical);
    const guardrailPassed = payload.guardrailPassed !== undefined ? payload.guardrailPassed : true;

    const signPayload = {
      attestationId,
      agentDid: agentKeyPair.did,
      modelFingerprint,
      contextDigest,
      executionTraceHash,
      stepCount: trace.length,
      outputCommitment,
      guardrailPolicyId: payload.guardrailPolicyId || 'default-safety-guardrail',
      guardrailPassed,
      timestamp
    };

    const signatureHex = signMessage(canonicalizeJson(signPayload), agentKeyPair.privateKeyHex);

    return {
      type: 'DocuTrustAgentAttestation2026',
      attestationId,
      agentDid: agentKeyPair.did,
      modelFingerprint,
      contextDigest,
      executionTraceHash,
      stepCount: trace.length,
      outputCommitment,
      guardrailPolicyId: payload.guardrailPolicyId || 'default-safety-guardrail',
      guardrailPassed,
      modelCard: payload.modelCard,
      outputArtifact: payload.outputArtifact,
      signatureHex,
      timestamp
    };
  }

  /**
   * Cryptographically verifies an AI Agent Action Attestation.
   */
  public static verifyAttestation(
    attestation: DocuTrustAgentAttestation,
    agentPublicKeyHex: string,
    expectedOutput?: Record<string, any> | string
  ): AgentAttestationVerificationResult {
    const errors: string[] = [];

    if (!attestation || attestation.type !== 'DocuTrustAgentAttestation2026') {
      return {
        valid: false,
        attestationId: attestation?.attestationId || 'unknown',
        agentDid: attestation?.agentDid || 'unknown',
        modelFingerprint: '',
        stepCount: attestation?.stepCount || 0,
        guardrailPassed: false,
        outputCommitment: '',
        errors: ['Invalid attestation structure or type mismatch.']
      };
    }

    // 1. Verify model fingerprint
    const computedFingerprint = this.computeModelFingerprint(attestation.modelCard);
    if (computedFingerprint.toLowerCase() !== attestation.modelFingerprint.toLowerCase()) {
      errors.push('Model card fingerprint mismatch in attestation.');
    }

    // 2. Verify output commitment
    const actualOutputCanonical = typeof attestation.outputArtifact === 'string'
      ? attestation.outputArtifact
      : canonicalizeJson(attestation.outputArtifact);
    const computedCommitment = sha256Hex(actualOutputCanonical);
    if (computedCommitment.toLowerCase() !== attestation.outputCommitment.toLowerCase()) {
      errors.push('Output artifact commitment mismatch.');
    }

    // 3. Verify against expected output if supplied
    if (expectedOutput !== undefined) {
      const expCanonical = typeof expectedOutput === 'string' ? expectedOutput : canonicalizeJson(expectedOutput);
      const expCommitment = sha256Hex(expCanonical);
      if (expCommitment.toLowerCase() !== attestation.outputCommitment.toLowerCase()) {
        errors.push(`Expected output commitment mismatch: expected ${expCommitment}, got ${attestation.outputCommitment}`);
      }
    }

    // 4. Verify agent signature
    const signPayload = {
      attestationId: attestation.attestationId,
      agentDid: attestation.agentDid,
      modelFingerprint: attestation.modelFingerprint,
      contextDigest: attestation.contextDigest,
      executionTraceHash: attestation.executionTraceHash,
      stepCount: attestation.stepCount,
      outputCommitment: attestation.outputCommitment,
      guardrailPolicyId: attestation.guardrailPolicyId,
      guardrailPassed: attestation.guardrailPassed,
      timestamp: attestation.timestamp
    };

    const isSigValid = verifySignature(canonicalizeJson(signPayload), attestation.signatureHex, agentPublicKeyHex);
    if (!isSigValid) {
      errors.push('Agent cryptographic signature verification failed on action attestation.');
    }

    // 5. Check guardrail status
    if (!attestation.guardrailPassed) {
      errors.push('Agent action attestation reports safety/policy guardrail violation.');
    }

    return {
      valid: errors.length === 0,
      attestationId: attestation.attestationId,
      agentDid: attestation.agentDid,
      modelFingerprint: attestation.modelFingerprint,
      stepCount: attestation.stepCount,
      guardrailPassed: attestation.guardrailPassed,
      outputCommitment: attestation.outputCommitment,
      errors
    };
  }
}
