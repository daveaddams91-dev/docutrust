/**
 * @file packages/core/src/policy/index.ts
 * @description Sovereign Policy-as-Proof & Governance Rule Engine (DocuTrust v10.0.0)
 * Evaluates verifiable presentation claims, credential subjects, and zero-knowledge assertions
 * against AST-based logical constraint trees (AND, OR, NOT, GTE, LTE, EQ, NEQ, IN, CONTAINS, REGEX,
 * VALID_BETWEEN, EPOCH_WITHIN, ALL_OF, ANY_OF, NONE_OF, TYPE_IS), emitting cryptographically signed execution receipts.
 */

import * as crypto from 'crypto';
import { sha256Hex, canonicalizeJson, signData, verifySignature, KeyPair, decodeBase58 } from '../crypto/index.js';
import { DIDResolver } from '../did/index.js';

export type PolicyOperator =
  | 'and'
  | 'or'
  | 'not'
  | 'eq'
  | 'neq'
  | 'gt'
  | 'gte'
  | 'lt'
  | 'lte'
  | 'in'
  | 'not_in'
  | 'contains'
  | 'regex'
  | 'exists'
  | 'not_exists'
  | 'valid_between'
  | 'epoch_within'
  | 'all_of'
  | 'any_of'
  | 'none_of'
  | 'type_is';

export interface PolicyRuleCondition {
  field?: string; // Dot-separated path in credential, e.g. "credentialSubject.age" or "issuer.id"
  operator: PolicyOperator;
  value?: any; // Expected value, range [min, max], or threshold
  conditions?: PolicyRuleCondition[]; // Child conditions for composite operators (and, or, not, all_of, any_of)
  itemCondition?: PolicyRuleCondition; // For all_of, any_of array item evaluations
  description?: string;
}

export interface GovernancePolicy {
  id: string;
  name: string;
  version: string;
  description?: string;
  authorityDid?: string;
  allowedIssuers?: string[];
  requiredCredentialTypes?: string[];
  maxCredentialAgeSeconds?: number;
  condition: PolicyRuleCondition;
}

export interface ConditionEvaluationTrace {
  condition: PolicyRuleCondition;
  actualValue?: any;
  passed: boolean;
  reason?: string;
  childrenTraces?: ConditionEvaluationTrace[];
}

export interface PolicyEvaluationResult {
  passed: boolean;
  policyId: string;
  policyName: string;
  evaluatedAt: string;
  errors: string[];
  traces: ConditionEvaluationTrace;
  receipt?: PolicyEvaluationReceipt;
}

export interface PolicyEvaluationReceipt {
  type: 'DocuTrustPolicyReceipt2026';
  policyId: string;
  policyHash: string;
  targetCredentialId: string;
  passed: boolean;
  evaluatedAt: string;
  evaluatorDid: string;
  executionTraceHash: string;
  proof: {
    type: 'Ed25519Signature2020';
    created: string;
    verificationMethod: string;
    proofValue: string;
  };
}

export class PolicyEngine {
  /**
   * Evaluates a Verifiable Credential or Presentation payload against a Governance Policy.
   */
  public static evaluate(
    payload: Record<string, any>,
    policy: GovernancePolicy,
    options: {
      evaluatorKeyPair?: KeyPair;
      evaluationTime?: Date;
    } = {}
  ): PolicyEvaluationResult {
    const errors: string[] = [];
    const evaluationTime = options.evaluationTime || new Date();
    const evaluatedAt = evaluationTime.toISOString();

    if (!payload || typeof payload !== 'object') {
      return {
        passed: false,
        policyId: policy?.id || 'unknown',
        policyName: policy?.name || 'Unknown Policy',
        evaluatedAt,
        errors: ['Invalid credential/presentation payload provided.'],
        traces: {
          condition: policy?.condition || { operator: 'and' },
          passed: false,
          reason: 'Payload is null or not an object.'
        }
      };
    }

    // 1. Check required credential types if specified
    if (policy.requiredCredentialTypes && policy.requiredCredentialTypes.length > 0) {
      const payloadTypes = Array.isArray(payload.type)
        ? payload.type
        : payload.type ? [payload.type] : [];
      const hasAllRequired = policy.requiredCredentialTypes.every(reqType => payloadTypes.includes(reqType));
      if (!hasAllRequired) {
        errors.push(`Payload missing required credential types: ${policy.requiredCredentialTypes.filter(t => !payloadTypes.includes(t)).join(', ')}`);
      }
    }

    // 2. Check allowed issuers if specified
    if (policy.allowedIssuers && policy.allowedIssuers.length > 0) {
      const issuerVal = payload.issuer;
      const issuerDid = typeof issuerVal === 'string' ? issuerVal : issuerVal?.id;
      const cleanIssuer = issuerDid ? issuerDid.split('#')[0] : '';
      const isAllowed = policy.allowedIssuers.some(allowed => allowed.split('#')[0] === cleanIssuer);
      if (!isAllowed) {
        errors.push(`Issuer ${issuerDid || 'unknown'} is not in the policy allowed issuers list.`);
      }
    }

    // 3. Check maximum credential age if specified
    if (policy.maxCredentialAgeSeconds !== undefined && policy.maxCredentialAgeSeconds > 0) {
      const issuanceStr = payload.validFrom || payload.issuanceDate;
      if (issuanceStr) {
        const issueTime = new Date(issuanceStr).getTime();
        const ageSeconds = (evaluationTime.getTime() - issueTime) / 1000;
        if (ageSeconds > policy.maxCredentialAgeSeconds) {
          errors.push(`Credential age (${Math.round(ageSeconds)}s) exceeds max allowed age (${policy.maxCredentialAgeSeconds}s).`);
        }
      }
    }

    // 4. Recursively evaluate condition AST
    const traces = this.evaluateCondition(payload, policy.condition, evaluationTime);
    if (!traces.passed) {
      if (traces.reason) errors.push(traces.reason);
    }

    const passed = errors.length === 0 && traces.passed;

    // 5. Generate signed receipt if evaluator keypair is provided
    let receipt: PolicyEvaluationReceipt | undefined;
    if (options.evaluatorKeyPair) {
      const policyCanonical = canonicalizeJson(policy);
      const policyHash = sha256Hex(policyCanonical);
      const traceCanonical = canonicalizeJson(traces);
      const executionTraceHash = sha256Hex(traceCanonical);
      const targetCredentialId = payload.id || `urn:uuid:${sha256Hex(canonicalizeJson(payload)).slice(0, 16)}`;
      const evaluatorDid = options.evaluatorKeyPair.did;
      const created = evaluatedAt;

      const unsignedReceipt = {
        type: 'DocuTrustPolicyReceipt2026' as const,
        policyId: policy.id,
        policyHash,
        targetCredentialId,
        passed,
        evaluatedAt,
        evaluatorDid,
        executionTraceHash
      };

      const digest = sha256Hex(canonicalizeJson(unsignedReceipt));
      const proofValue = signData(`${digest}:${created}`, options.evaluatorKeyPair.privateKeyHex);

      receipt = {
        ...unsignedReceipt,
        proof: {
          type: 'Ed25519Signature2020',
          created,
          verificationMethod: `${evaluatorDid}#key-1`,
          proofValue
        }
      };
    }

    return {
      passed,
      policyId: policy.id,
      policyName: policy.name,
      evaluatedAt,
      errors,
      traces,
      ...(receipt ? { receipt } : {})
    };
  }

  /**
   * Verifies the authenticity and integrity of a Policy Evaluation Receipt.
   */
  public static verifyReceipt(receipt: PolicyEvaluationReceipt, expectedEvaluatorPublicKeyHex?: string): boolean {
    if (!receipt || receipt.type !== 'DocuTrustPolicyReceipt2026' || !receipt.proof) {
      return false;
    }

    const { proof, ...unsigned } = receipt;
    const digest = sha256Hex(canonicalizeJson(unsigned));

    let pubHex = expectedEvaluatorPublicKeyHex;
    if (!pubHex && receipt.evaluatorDid) {
      const cleanDid = receipt.evaluatorDid.split('#')[0];
      if (cleanDid.startsWith('did:key:z')) {
        try {
          const raw = decodeBase58(cleanDid.replace('did:key:z', ''));
          pubHex = raw.subarray(2).toString('hex');
        } catch (_) {}
      } else if (cleanDid.startsWith('did:peer:0z')) {
        try {
          const raw = decodeBase58(cleanDid.replace('did:peer:0z', ''));
          pubHex = raw.subarray(2).toString('hex');
        } catch (_) {}
      }
    }

    if (!pubHex && receipt.evaluatorDid && /^[0-9a-fA-F]{64}$/.test(receipt.evaluatorDid)) {
      pubHex = receipt.evaluatorDid;
    }

    if (!pubHex) return false;
    return verifySignature(`${digest}:${proof.created}`, proof.proofValue, pubHex);
  }

  /**
   * Resolves a nested field value by dot notation and array index notation (e.g. "credentialSubject.scores[0]").
   */
  public static resolveFieldValue(obj: any, path?: string): any {
    if (!path || !obj) return undefined;
    const normalized = path.replace(/\[(\w+)\]/g, '.$1');
    const parts = normalized.split('.');
    let curr = obj;
    for (const part of parts) {
      if (curr === null || curr === undefined) return undefined;
      curr = curr[part];
    }
    return curr;
  }

  /**
   * Evaluates an individual condition node against the payload.
   */
  private static evaluateCondition(
    payload: Record<string, any>,
    condition: PolicyRuleCondition,
    referenceTime: Date = new Date()
  ): ConditionEvaluationTrace {
    const op = condition.operator?.toLowerCase() as PolicyOperator;

    // Composite logic: AND
    if (op === 'and') {
      const childConditions = condition.conditions || [];
      const childrenTraces: ConditionEvaluationTrace[] = [];
      let allPassed = true;
      let failedReason: string | undefined;

      for (const cond of childConditions) {
        const trace = this.evaluateCondition(payload, cond, referenceTime);
        childrenTraces.push(trace);
        if (!trace.passed) {
          allPassed = false;
          if (!failedReason) failedReason = trace.reason;
        }
      }

      return {
        condition,
        passed: allPassed,
        reason: allPassed ? undefined : (failedReason || 'One or more AND conditions failed.'),
        childrenTraces
      };
    }

    // Composite logic: OR
    if (op === 'or') {
      const childConditions = condition.conditions || [];
      const childrenTraces: ConditionEvaluationTrace[] = [];
      let anyPassed = false;

      for (const cond of childConditions) {
        const trace = this.evaluateCondition(payload, cond, referenceTime);
        childrenTraces.push(trace);
        if (trace.passed) anyPassed = true;
      }

      return {
        condition,
        passed: anyPassed,
        reason: anyPassed ? undefined : 'None of the OR conditions were satisfied.',
        childrenTraces
      };
    }

    // Composite logic: NOT
    if (op === 'not') {
      const childCondition = condition.conditions && condition.conditions[0];
      if (!childCondition) {
        return { condition, passed: false, reason: 'NOT condition missing child condition.' };
      }
      const childTrace = this.evaluateCondition(payload, childCondition, referenceTime);
      return {
        condition,
        passed: !childTrace.passed,
        reason: childTrace.passed ? 'NOT condition failed because inner condition evaluated to true.' : undefined,
        childrenTraces: [childTrace]
      };
    }

    // Primitive field evaluations
    const actual = this.resolveFieldValue(payload, condition.field);
    const expected = condition.value;

    switch (op) {
      case 'exists': {
        const exists = actual !== undefined && actual !== null;
        return {
          condition,
          actualValue: actual,
          passed: exists,
          reason: exists ? undefined : `Field "${condition.field}" does not exist.`
        };
      }
      case 'not_exists': {
        const notExists = actual === undefined || actual === null;
        return {
          condition,
          actualValue: actual,
          passed: notExists,
          reason: notExists ? undefined : `Field "${condition.field}" unexpectedly exists.`
        };
      }
      case 'eq': {
        const passed = actual === expected;
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`
        };
      }
      case 'neq': {
        const passed = actual !== expected;
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" expected not equal to ${JSON.stringify(expected)}`
        };
      }
      case 'gt': {
        const passed = typeof actual === 'number' && actual > expected;
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" (${actual}) is not greater than ${expected}`
        };
      }
      case 'gte': {
        const passed = (typeof actual === 'number' || typeof actual === 'string') && actual >= expected;
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" (${actual}) is not greater than or equal to ${expected}`
        };
      }
      case 'lt': {
        const passed = typeof actual === 'number' && actual < expected;
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" (${actual}) is not less than ${expected}`
        };
      }
      case 'lte': {
        const passed = (typeof actual === 'number' || typeof actual === 'string') && actual <= expected;
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" (${actual}) is not less than or equal to ${expected}`
        };
      }
      case 'in': {
        const arr = Array.isArray(expected) ? expected : [expected];
        const passed = arr.includes(actual);
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" (${JSON.stringify(actual)}) not in allowed set [${arr.join(', ')}]`
        };
      }
      case 'not_in': {
        const arr = Array.isArray(expected) ? expected : [expected];
        const passed = !arr.includes(actual);
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" (${JSON.stringify(actual)}) is in forbidden set [${arr.join(', ')}]`
        };
      }
      case 'contains': {
        let passed = false;
        if (Array.isArray(actual)) {
          passed = actual.includes(expected);
        } else if (typeof actual === 'string') {
          passed = actual.includes(String(expected));
        }
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" (${JSON.stringify(actual)}) does not contain ${JSON.stringify(expected)}`
        };
      }
      case 'regex': {
        let passed = false;
        try {
          const re = new RegExp(expected);
          passed = typeof actual === 'string' && re.test(actual);
        } catch (_) {
          passed = false;
        }
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" (${JSON.stringify(actual)}) does not match regex /${expected}/`
        };
      }
      case 'valid_between': {
        if (!actual || !Array.isArray(expected) || expected.length < 2) {
          return { condition, actualValue: actual, passed: false, reason: `Invalid date bounds for valid_between on "${condition.field}"` };
        }
        const actTime = new Date(actual).getTime();
        const startTime = new Date(expected[0]).getTime();
        const endTime = new Date(expected[1]).getTime();
        const passed = !isNaN(actTime) && actTime >= startTime && actTime <= endTime;
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" (${actual}) is outside window [${expected[0]}, ${expected[1]}]`
        };
      }
      case 'epoch_within': {
        if (!actual || typeof expected !== 'number') {
          return { condition, actualValue: actual, passed: false, reason: `epoch_within requires date string and duration in seconds` };
        }
        const actTime = new Date(actual).getTime();
        const diffSeconds = Math.abs(referenceTime.getTime() - actTime) / 1000;
        const passed = diffSeconds <= expected;
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" timestamp is ${Math.round(diffSeconds)}s away, exceeding threshold (${expected}s)`
        };
      }
      case 'type_is': {
        let passed = false;
        const expectedType = String(expected).toLowerCase();
        if (expectedType === 'array') passed = Array.isArray(actual);
        else if (expectedType === 'null') passed = actual === null;
        else passed = typeof actual === expectedType;
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Field "${condition.field}" has type "${Array.isArray(actual) ? 'array' : typeof actual}", expected "${expectedType}"`
        };
      }
      case 'all_of': {
        if (!Array.isArray(actual) || !condition.itemCondition) {
          return { condition, actualValue: actual, passed: false, reason: `all_of requires array field and itemCondition` };
        }
        const passed = actual.every(item => this.evaluateCondition(item, condition.itemCondition!, referenceTime).passed);
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `Not all items in "${condition.field}" satisfied item condition.`
        };
      }
      case 'any_of': {
        if (!Array.isArray(actual) || !condition.itemCondition) {
          return { condition, actualValue: actual, passed: false, reason: `any_of requires array field and itemCondition` };
        }
        const passed = actual.some(item => this.evaluateCondition(item, condition.itemCondition!, referenceTime).passed);
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `None of the items in "${condition.field}" satisfied item condition.`
        };
      }
      case 'none_of': {
        if (!Array.isArray(actual) || !condition.itemCondition) {
          return { condition, actualValue: actual, passed: false, reason: `none_of requires array field and itemCondition` };
        }
        const passed = !actual.some(item => this.evaluateCondition(item, condition.itemCondition!, referenceTime).passed);
        return {
          condition,
          actualValue: actual,
          passed,
          reason: passed ? undefined : `One or more items in "${condition.field}" unexpectedly matched item condition.`
        };
      }
      default:
        return {
          condition,
          passed: false,
          reason: `Unsupported policy operator: ${op}`
        };
    }
  }
}
