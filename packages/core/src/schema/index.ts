/**
 * @file packages/core/src/schema/index.ts
 * @description W3C VC 2.0 Credential Schema & Strict JSON Schema Validation Engine
 * Supports draft-07 and 2020-12 sub-specifications with canonical digest calculation.
 */

import { canonicalizeJson, sha256Hex } from '../crypto/index.js';

export interface JsonSchemaProperty {
  type?: string | string[];
  description?: string;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  minimum?: number;
  maximum?: number;
  exclusiveMinimum?: number;
  exclusiveMaximum?: number;
  enum?: any[];
  items?: JsonSchemaProperty;
  minItems?: number;
  maxItems?: number;
  properties?: Record<string, JsonSchemaProperty>;
  required?: string[];
  additionalProperties?: boolean | JsonSchemaProperty;
  format?: 'email' | 'uri' | 'date-time' | 'date' | 'did' | string;
}

export interface JsonSchema {
  $id?: string;
  $schema?: string;
  title?: string;
  description?: string;
  type: string;
  properties?: Record<string, JsonSchemaProperty>;
  required?: string[];
  additionalProperties?: boolean | JsonSchemaProperty;
}

export interface SchemaValidationResult {
  valid: boolean;
  errors: string[];
  schemaHash: string;
}

export interface W3CCredentialSchema {
  id: string;
  type: string;
  digest?: string;
}

export class SchemaValidator {
  /**
   * Computes deterministic SHA-256 digest of a JSON schema using RFC 8785 canonicalization.
   */
  public static computeSchemaHash(schema: JsonSchema): string {
    const canonical = canonicalizeJson(schema);
    return sha256Hex(canonical);
  }

  /**
   * Constructs standard W3C VC 2.0 credentialSchema metadata block.
   */
  public static createCredentialSchema(
    id: string,
    schema: JsonSchema,
    type: string = 'JsonSchemaValidator2026'
  ): W3CCredentialSchema {
    return {
      id,
      type,
      digest: this.computeSchemaHash(schema)
    };
  }

  /**
   * Validates a target data payload against a JSON schema.
   */
  public static validate(data: any, schema: JsonSchema | JsonSchemaProperty, path: string = '$'): SchemaValidationResult {
    const errors: string[] = [];
    const schemaHash = 'type' in schema && typeof (schema as any).$id !== 'undefined'
      ? this.computeSchemaHash(schema as JsonSchema)
      : sha256Hex(canonicalizeJson(schema));

    this._validateNode(data, schema, path, errors);

    return {
      valid: errors.length === 0,
      errors,
      schemaHash
    };
  }

  /**
   * Validates credentialSubject of a W3C Verifiable Credential against a given JSON Schema.
   */
  public static validateCredentialSubject(credential: any, schema: JsonSchema): SchemaValidationResult {
    if (!credential || typeof credential !== 'object') {
      return { valid: false, errors: ['Invalid credential object.'], schemaHash: this.computeSchemaHash(schema) };
    }

    const subject = credential.credentialSubject;
    if (!subject || typeof subject !== 'object') {
      return { valid: false, errors: ['Credential missing credentialSubject object.'], schemaHash: this.computeSchemaHash(schema) };
    }

    return this.validate(subject, schema, '$.credentialSubject');
  }

  private static _validateNode(value: any, prop: JsonSchemaProperty, path: string, errors: string[]): void {
    // 1. Type validation
    if (prop.type) {
      const allowedTypes = Array.isArray(prop.type) ? prop.type : [prop.type];
      const actualType = this._getType(value);
      
      const typeMatches = allowedTypes.some(t => {
        if (t === 'integer') return typeof value === 'number' && Number.isInteger(value);
        if (t === 'number') return typeof value === 'number';
        return actualType === t;
      });

      if (!typeMatches && value !== undefined) {
        errors.push(`${path}: expected type ${allowedTypes.join(' | ')}, got ${actualType}`);
        return;
      }
    }

    if (value === undefined || value === null) return;

    // 2. Enum check
    if (prop.enum && Array.isArray(prop.enum)) {
      if (!prop.enum.includes(value)) {
        errors.push(`${path}: value ${JSON.stringify(value)} is not in enum [${prop.enum.map(e => JSON.stringify(e)).join(', ')}]`);
      }
    }

    // 3. String validations
    if (typeof value === 'string') {
      if (prop.minLength !== undefined && value.length < prop.minLength) {
        errors.push(`${path}: length ${value.length} is less than minLength ${prop.minLength}`);
      }
      if (prop.maxLength !== undefined && value.length > prop.maxLength) {
        errors.push(`${path}: length ${value.length} exceeds maxLength ${prop.maxLength}`);
      }
      if (prop.pattern) {
        try {
          const regex = new RegExp(prop.pattern);
          if (!regex.test(value)) {
            errors.push(`${path}: value does not match regex pattern ${prop.pattern}`);
          }
        } catch {
          // Ignore invalid regex in schema
        }
      }
      if (prop.format) {
        this._validateFormat(value, prop.format, path, errors);
      }
    }

    // 4. Number validations
    if (typeof value === 'number') {
      if (prop.minimum !== undefined && value < prop.minimum) {
        errors.push(`${path}: value ${value} is less than minimum ${prop.minimum}`);
      }
      if (prop.maximum !== undefined && value > prop.maximum) {
        errors.push(`${path}: value ${value} is greater than maximum ${prop.maximum}`);
      }
      if (prop.exclusiveMinimum !== undefined && value <= prop.exclusiveMinimum) {
        errors.push(`${path}: value ${value} must be strictly greater than ${prop.exclusiveMinimum}`);
      }
      if (prop.exclusiveMaximum !== undefined && value >= prop.exclusiveMaximum) {
        errors.push(`${path}: value ${value} must be strictly less than ${prop.exclusiveMaximum}`);
      }
    }

    // 5. Array validations
    if (Array.isArray(value)) {
      if (prop.minItems !== undefined && value.length < prop.minItems) {
        errors.push(`${path}: array length ${value.length} is less than minItems ${prop.minItems}`);
      }
      if (prop.maxItems !== undefined && value.length > prop.maxItems) {
        errors.push(`${path}: array length ${value.length} exceeds maxItems ${prop.maxItems}`);
      }
      if (prop.items) {
        value.forEach((item, index) => {
          this._validateNode(item, prop.items!, `${path}[${index}]`, errors);
        });
      }
    }

    // 6. Object validations
    if (typeof value === 'object' && !Array.isArray(value)) {
      // Required fields
      if (prop.required && Array.isArray(prop.required)) {
        for (const reqKey of prop.required) {
          if (value[reqKey] === undefined || value[reqKey] === null) {
            errors.push(`${path}.${reqKey}: required property is missing`);
          }
        }
      }

      // Check properties
      if (prop.properties) {
        for (const [key, subProp] of Object.entries(prop.properties)) {
          if (value[key] !== undefined) {
            this._validateNode(value[key], subProp, `${path}.${key}`, errors);
          }
        }
      }

      // Additional properties
      if (prop.additionalProperties === false && prop.properties) {
        const declaredKeys = new Set(Object.keys(prop.properties));
        for (const key of Object.keys(value)) {
          if (!declaredKeys.has(key)) {
            errors.push(`${path}.${key}: unexpected property not allowed by schema`);
          }
        }
      } else if (typeof prop.additionalProperties === 'object' && prop.additionalProperties !== null) {
        const declaredKeys = new Set(prop.properties ? Object.keys(prop.properties) : []);
        for (const [key, val] of Object.entries(value)) {
          if (!declaredKeys.has(key)) {
            this._validateNode(val, prop.additionalProperties as JsonSchemaProperty, `${path}.${key}`, errors);
          }
        }
      }
    }
  }

  private static _getType(val: any): string {
    if (val === null) return 'null';
    if (Array.isArray(val)) return 'array';
    return typeof val;
  }

  private static _validateFormat(val: string, format: string, path: string, errors: string[]): void {
    switch (format) {
      case 'email':
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) {
          errors.push(`${path}: value is not a valid email address`);
        }
        break;
      case 'uri':
        if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:[^\s]*$/.test(val)) {
          errors.push(`${path}: value is not a valid URI`);
        }
        break;
      case 'did':
        if (!/^did:[a-z0-9]+:[a-zA-Z0-9.\-_:%]+$/.test(val)) {
          errors.push(`${path}: value is not a valid W3C DID string`);
        }
        break;
      case 'date':
        if (!/^\d{4}-\d{2}-\d{2}$/.test(val) || isNaN(Date.parse(val))) {
          errors.push(`${path}: value is not a valid YYYY-MM-DD date`);
        }
        break;
      case 'date-time':
        if (isNaN(Date.parse(val))) {
          errors.push(`${path}: value is not a valid ISO 8601 date-time string`);
        }
        break;
    }
  }
}
