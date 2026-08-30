/**
 * @file packages/core/src/presentation-exchange/index.ts
 * @description DIF Presentation Exchange v2.0 Engine & Verifiable Presentation Evaluator
 * Conforms to Decentralized Identity Foundation (DIF) Presentation Exchange 2.0.0 Specification.
 */

import { canonicalizeJson, sha256Hex } from '../crypto/index.js';
import { SchemaValidator } from '../schema/index.js';

export interface FieldConstraint {
  path: string[];
  id?: string;
  purpose?: string;
  filter?: Record<string, any>; // JSON Schema filter
  predicate?: 'preferred' | 'required';
  optional?: boolean;
}

export interface InputDescriptor {
  id: string;
  name?: string;
  purpose?: string;
  group?: string[];
  schema?: Array<{ uri: string; required?: boolean }>;
  constraints?: {
    fields?: FieldConstraint[];
    limit_disclosure?: 'required' | 'preferred';
    is_holder?: Array<{ field_id: string[]; directive: 'required' | 'preferred' }>;
    statuses?: {
      active?: { directive: 'required' | 'allowed' | 'disallowed' };
      suspended?: { directive: 'required' | 'allowed' | 'disallowed' };
      revoked?: { directive: 'required' | 'allowed' | 'disallowed' };
    };
  };
}

export interface PresentationDefinition {
  id: string;
  name?: string;
  purpose?: string;
  format?: Record<string, any>;
  input_descriptors: InputDescriptor[];
}

export interface DescriptorMapEntry {
  id: string;
  format: 'ldp_vc' | 'jwt_vc' | 'sd_jwt' | 'mso_mdoc' | string;
  path: string;
  path_nested?: {
    format: string;
    path: string;
  };
}

export interface PresentationSubmission {
  id: string;
  definition_id: string;
  descriptor_map: DescriptorMapEntry[];
}

export interface EvaluationFieldResult {
  descriptorId: string;
  fieldPath: string;
  matched: boolean;
  value?: any;
  error?: string;
}

export interface PresentationEvaluationResult {
  valid: boolean;
  definitionId: string;
  matchedDescriptors: string[];
  unmatchedDescriptors: string[];
  fieldResults: EvaluationFieldResult[];
  errors: string[];
  auditHash: string;
}

/**
 * Resolves a simple JSONPath like '$.credentialSubject.degree' or '$.type[1]' against an object.
 */
function resolveJsonPath(obj: any, pathStr: string): any {
  if (!obj || typeof obj !== 'object') return undefined;
  const cleanPath = pathStr.replace(/^\$\.?/, '');
  if (!cleanPath) return obj;

  const parts = cleanPath.split('.').flatMap(p => {
    const arrayMatch = p.match(/^([a-zA-Z0-9_-]+)\[(\d+)\]$/);
    if (arrayMatch) {
      return [arrayMatch[1], parseInt(arrayMatch[2], 10)];
    }
    return [p];
  });

  let current = obj;
  for (const part of parts) {
    if (current === undefined || current === null) return undefined;
    current = current[part];
  }
  return current;
}

export class PresentationExchangeEngine {
  /**
   * Constructs a standard DIF PresentationDefinition.
   */
  public static createDefinition(
    id: string,
    inputDescriptors: InputDescriptor[],
    options: { name?: string; purpose?: string; format?: Record<string, any> } = {}
  ): PresentationDefinition {
    if (!id) throw new Error('PresentationDefinition requires a unique id');
    if (!Array.isArray(inputDescriptors) || inputDescriptors.length === 0) {
      throw new Error('PresentationDefinition requires at least one InputDescriptor');
    }

    return {
      id,
      name: options.name,
      purpose: options.purpose,
      format: options.format,
      input_descriptors: inputDescriptors
    };
  }

  /**
   * Creates a standard DIF PresentationSubmission descriptor block.
   */
  public static createSubmission(
    definitionId: string,
    descriptorMap: DescriptorMapEntry[],
    id?: string
  ): PresentationSubmission {
    return {
      id: id || `submission_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      definition_id: definitionId,
      descriptor_map: descriptorMap
    };
  }

  /**
   * Evaluates a Verifiable Presentation against a PresentationDefinition.
   */
  public static evaluatePresentation(
    presentation: any,
    definition: PresentationDefinition,
    submission?: PresentationSubmission
  ): PresentationEvaluationResult {
    const errors: string[] = [];
    const matchedDescriptors: string[] = [];
    const unmatchedDescriptors: string[] = [];
    const fieldResults: EvaluationFieldResult[] = [];

    if (!presentation || typeof presentation !== 'object') {
      return {
        valid: false,
        definitionId: definition.id,
        matchedDescriptors: [],
        unmatchedDescriptors: definition.input_descriptors.map(d => d.id),
        fieldResults: [],
        errors: ['Invalid presentation payload.'],
        auditHash: ''
      };
    }

    if (submission && submission.definition_id !== definition.id) {
      errors.push(`Presentation submission definition_id '${submission.definition_id}' does not match expected '${definition.id}'`);
    }

    // Extract all candidate credentials in the presentation
    let credentials: any[] = [];
    if (Array.isArray(presentation.verifiableCredential)) {
      credentials = presentation.verifiableCredential;
    } else if (presentation.verifiableCredential) {
      credentials = [presentation.verifiableCredential];
    } else if (presentation.credentialSubject) {
      credentials = [presentation];
    }

    // Evaluate each input descriptor
    for (const descriptor of definition.input_descriptors) {
      let descriptorMatched = false;

      // Find matching credential either via submission descriptor_map or heuristic scan
      let targetVc: any = null;
      if (submission) {
        const mapping = submission.descriptor_map.find(m => m.id === descriptor.id);
        if (mapping) {
          targetVc = resolveJsonPath(presentation, mapping.path);
        }
      }

      const candidatesToTest = targetVc ? [targetVc] : credentials;

      for (const vc of candidatesToTest) {
        if (!vc || typeof vc !== 'object') continue;

        let allFieldsMatched = true;

        // Check schema URI constraints if provided
        if (descriptor.schema && descriptor.schema.length > 0) {
          const typeList = Array.isArray(vc.type) ? vc.type : [vc.type];
          const schemaMatches = descriptor.schema.some(s => {
            return typeList.includes(s.uri) || (vc.credentialSchema && vc.credentialSchema.id === s.uri);
          });
          if (!schemaMatches) {
            continue;
          }
        }

        // Check field constraints
        if (descriptor.constraints?.fields && descriptor.constraints.fields.length > 0) {
          for (const field of descriptor.constraints.fields) {
            let fieldMatched = false;
            let extractedValue: any = undefined;

            for (const pathStr of field.path) {
              const val = resolveJsonPath(vc, pathStr);
              if (val !== undefined) {
                extractedValue = val;

                // Validate with filter if present
                if (field.filter) {
                  const filterRes = SchemaValidator.validate(val, field.filter);
                  if (filterRes.valid) {
                    fieldMatched = true;
                    break;
                  }
                } else {
                  fieldMatched = true;
                  break;
                }
              }
            }

            if (!fieldMatched && !field.optional) {
              allFieldsMatched = false;
              fieldResults.push({
                descriptorId: descriptor.id,
                fieldPath: field.path.join(' | '),
                matched: false,
                error: `Field constraint unsatisfied on path [${field.path.join(', ')}]`
              });
            } else {
              fieldResults.push({
                descriptorId: descriptor.id,
                fieldPath: field.path.join(' | '),
                matched: true,
                value: extractedValue
              });
            }
          }
        }

        if (allFieldsMatched) {
          descriptorMatched = true;
          break;
        }
      }

      if (descriptorMatched) {
        matchedDescriptors.push(descriptor.id);
      } else {
        unmatchedDescriptors.push(descriptor.id);
        errors.push(`Descriptor '${descriptor.id}' was not satisfied by presented credentials.`);
      }
    }

    const isValid = unmatchedDescriptors.length === 0 && errors.length === 0;
    const auditPayload = {
      definitionId: definition.id,
      matchedDescriptors,
      unmatchedDescriptors,
      valid: isValid,
      timestamp: new Date().toISOString()
    };
    const auditHash = sha256Hex(canonicalizeJson(auditPayload));

    return {
      valid: isValid,
      definitionId: definition.id,
      matchedDescriptors,
      unmatchedDescriptors,
      fieldResults,
      errors,
      auditHash
    };
  }
}
