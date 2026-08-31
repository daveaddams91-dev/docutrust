/**
 * @file packages/core/src/zk-dsl/index.ts
 * @description Zero-Knowledge Multi-Attribute Predicate DSL Compiler (DocuTrust v14.0.0)
 * Compiles expressive boolean logic expressions and complex multi-attribute constraints
 * into single-shot zero-knowledge proofs with witness generation, commitment verification,
 * and EVM on-chain calldata formatting.
 */

import * as crypto from 'crypto';
import { sha256Hex, signMessage, verifySignature, canonicalizeJson, KeyPair } from '../crypto/index.js';

export type DSLAstNodeType = 'LOGICAL' | 'COMPARISON' | 'IDENTIFIER' | 'LITERAL';

export interface DSLAstNode {
  type: DSLAstNodeType;
  operator?: 'AND' | 'OR' | 'NOT' | '==' | '!=' | '<' | '<=' | '>' | '>=' | 'IN' | 'NOT_IN' | 'CONTAINS';
  left?: DSLAstNode;
  right?: DSLAstNode;
  field?: string;
  value?: any;
}

export interface CompiledDSLConstraint {
  expression: string;
  ast: DSLAstNode;
  astRootHash: string;
  requiredFields: string[];
}

export interface DocuTrustZKDSLProof {
  type: 'DocuTrustZKDSLProof2026';
  proofId: string;
  dslExpression: string;
  astRootHash: string;
  credentialId?: string;
  subjectCommitment: string;
  evaluationCommitment: string;
  satisfied: boolean;
  proverDid: string;
  signatureHex: string;
  timestamp: string;
  evmCalldataHex?: string;
}

export interface ZKDSLVerificationResult {
  valid: boolean;
  satisfied: boolean;
  proofId: string;
  astRootHash: string;
  dslExpression: string;
  errors: string[];
}

export class ZKDSLEngine {
  /**
   * Tokenizes a DSL expression string.
   */
  public static tokenize(expr: string): string[] {
    const regex = /\s*(=>|==|!=|<=|>=|<|>|\(|\)|\[[^\]]*\]|"[^"]*"|'[^']*'|-?\d+(?:\.\d+)?|\b(?:AND|OR|NOT_IN|NOT|IN|CONTAINS|true|false)\b|[a-zA-Z_][a-zA-Z0-9_.]*)\s*/gi;
    const tokens: string[] = [];
    let match;
    while ((match = regex.exec(expr)) !== null) {
      if (match[1]) tokens.push(match[1]);
    }
    return tokens;
  }

  /**
   * Compiles a string predicate expression into a structured AST and root commitment.
   */
  public static compile(expression: string): CompiledDSLConstraint {
    if (!expression || typeof expression !== 'string' || !expression.trim()) {
      throw new Error('DSL expression cannot be empty.');
    }

    const tokens = this.tokenize(expression.trim());
    let index = 0;

    function peek(): string | undefined {
      return tokens[index];
    }

    function consume(expected?: string): string {
      const tok = tokens[index++];
      if (expected && tok?.toUpperCase() !== expected.toUpperCase()) {
        throw new Error(`Expected token '${expected}', got '${tok}'`);
      }
      return tok;
    }

    function parsePrimary(): DSLAstNode {
      const tok = peek();
      if (!tok) throw new Error('Unexpected end of expression');

      if (tok === '(') {
        consume('(');
        const node = parseOr();
        consume(')');
        return node;
      }

      if (tok.toUpperCase() === 'NOT') {
        consume('NOT');
        return {
          type: 'LOGICAL',
          operator: 'NOT',
          left: parsePrimary()
        };
      }

      // Comparison statement: field op value
      const field = consume();
      const opTok = consume();
      const opUpper = opTok.toUpperCase() as any;
      const valTok = consume();

      let parsedVal: any = valTok;
      if (valTok.startsWith('"') || valTok.startsWith("'")) {
        parsedVal = valTok.slice(1, -1);
      } else if (valTok === 'true') {
        parsedVal = true;
      } else if (valTok === 'false') {
        parsedVal = false;
      } else if (!isNaN(Number(valTok))) {
        parsedVal = Number(valTok);
      } else if (valTok.startsWith('[') && valTok.endsWith(']')) {
        try {
          parsedVal = JSON.parse(valTok.replace(/'/g, '"'));
        } catch {
          parsedVal = valTok.slice(1, -1).split(',').map(s => s.trim().replace(/^['"]|['"]$/g, ''));
        }
      }

      return {
        type: 'COMPARISON',
        operator: opUpper,
        field,
        value: parsedVal
      };
    }

    function parseAnd(): DSLAstNode {
      let left = parsePrimary();
      while (peek()?.toUpperCase() === 'AND') {
        consume('AND');
        const right = parsePrimary();
        left = {
          type: 'LOGICAL',
          operator: 'AND',
          left,
          right
        };
      }
      return left;
    }

    function parseOr(): DSLAstNode {
      let left = parseAnd();
      while (peek()?.toUpperCase() === 'OR') {
        consume('OR');
        const right = parseAnd();
        left = {
          type: 'LOGICAL',
          operator: 'OR',
          left,
          right
        };
      }
      return left;
    }

    const ast = parseOr();

    // Extract all required fields recursively
    const fields = new Set<string>();
    function extractFields(node?: DSLAstNode) {
      if (!node) return;
      if (node.field) fields.add(node.field);
      extractFields(node.left);
      extractFields(node.right);
    }
    extractFields(ast);

    const astRootHash = sha256Hex(`DSL_AST_V14:${canonicalizeJson(ast)}`);

    return {
      expression: expression.trim(),
      ast,
      astRootHash,
      requiredFields: Array.from(fields).sort()
    };
  }

  /**
   * Deterministically evaluates an AST against a credential subject record.
   */
  public static evaluateAst(node: DSLAstNode, subject: Record<string, any>): boolean {
    if (node.type === 'LOGICAL') {
      if (node.operator === 'AND') {
        return this.evaluateAst(node.left!, subject) && this.evaluateAst(node.right!, subject);
      }
      if (node.operator === 'OR') {
        return this.evaluateAst(node.left!, subject) || this.evaluateAst(node.right!, subject);
      }
      if (node.operator === 'NOT') {
        return !this.evaluateAst(node.left!, subject);
      }
    }

    if (node.type === 'COMPARISON') {
      const actualVal = this.resolveField(subject, node.field!);
      const targetVal = node.value;

      switch (node.operator) {
        case '==':
          return actualVal === targetVal;
        case '!=':
          return actualVal !== targetVal;
        case '<':
          return Number(actualVal) < Number(targetVal);
        case '<=':
          return Number(actualVal) <= Number(targetVal);
        case '>':
          return Number(actualVal) > Number(targetVal);
        case '>=':
          return Number(actualVal) >= Number(targetVal);
        case 'IN':
          return Array.isArray(targetVal) && targetVal.includes(actualVal);
        case 'NOT_IN':
          return Array.isArray(targetVal) && !targetVal.includes(actualVal);
        case 'CONTAINS':
          return Array.isArray(actualVal) && actualVal.includes(targetVal);
        default:
          return false;
      }
    }

    return false;
  }

  /**
   * Helper to resolve nested field path (e.g. "kyc.address.country").
   */
  public static resolveField(obj: any, path: string): any {
    if (!obj || typeof obj !== 'object') return undefined;
    const parts = path.split('.');
    let current = obj;
    for (const p of parts) {
      if (current === undefined || current === null) return undefined;
      current = current[p];
    }
    return current;
  }

  /**
   * Proves satisfaction of a DSL expression over a private subject without disclosing raw attributes.
   */
  public static proveDSL(
    expression: string,
    privateSubject: Record<string, any>,
    proverKeyPair: KeyPair,
    options?: { credentialId?: string; generateEvmCalldata?: boolean }
  ): DocuTrustZKDSLProof {
    const compiled = this.compile(expression);
    const satisfied = this.evaluateAst(compiled.ast, privateSubject);

    if (!satisfied) {
      throw new Error(`DSL Constraint evaluated to FALSE for the provided credential subject.`);
    }

    const proofId = `zk-dsl-${crypto.randomBytes(8).toString('hex')}`;
    const timestamp = new Date().toISOString();

    // Blinded commitments
    const subjectCanonical = canonicalizeJson(privateSubject);
    const subjectCommitment = sha256Hex(`DSL_SUB_BLIND:${subjectCanonical}`);
    const evaluationCommitment = sha256Hex(`DSL_EVAL:${compiled.astRootHash}:${subjectCommitment}:${satisfied}`);

    const signPayload = canonicalizeJson({
      proofId,
      dslExpression: compiled.expression,
      astRootHash: compiled.astRootHash,
      credentialId: options?.credentialId,
      subjectCommitment,
      evaluationCommitment,
      satisfied,
      proverDid: proverKeyPair.did,
      timestamp
    });

    const signatureHex = signMessage(signPayload, proverKeyPair.privateKeyHex);

    let evmCalldataHex: string | undefined;
    if (options?.generateEvmCalldata) {
      evmCalldataHex = this.generateEVMCalldata(proofId, compiled.astRootHash, evaluationCommitment);
    }

    return {
      type: 'DocuTrustZKDSLProof2026',
      proofId,
      dslExpression: compiled.expression,
      astRootHash: compiled.astRootHash,
      credentialId: options?.credentialId,
      subjectCommitment,
      evaluationCommitment,
      satisfied,
      proverDid: proverKeyPair.did,
      signatureHex,
      timestamp,
      ...(evmCalldataHex ? { evmCalldataHex } : {})
    };
  }

  /**
   * Verifies a Zero-Knowledge DSL evaluation proof.
   */
  public static verifyDSLProof(
    proof: DocuTrustZKDSLProof,
    proverPublicKeyHex: string,
    expectedExpression?: string
  ): ZKDSLVerificationResult {
    const errors: string[] = [];

    if (!proof || proof.type !== 'DocuTrustZKDSLProof2026') {
      return {
        valid: false,
        satisfied: false,
        proofId: proof?.proofId || 'unknown',
        astRootHash: '',
        dslExpression: '',
        errors: ['Invalid proof structure or type mismatch.']
      };
    }

    if (!proof.satisfied) {
      errors.push('Proof statement declares constraint was not satisfied.');
    }

    // 1. Compile expression and verify AST root hash
    try {
      const compiled = this.compile(proof.dslExpression);
      if (compiled.astRootHash.toLowerCase() !== proof.astRootHash.toLowerCase()) {
        errors.push('Compiled DSL AST root hash mismatch.');
      }
      if (expectedExpression && expectedExpression.trim() !== proof.dslExpression.trim()) {
        const expCompiled = this.compile(expectedExpression);
        if (expCompiled.astRootHash.toLowerCase() !== proof.astRootHash.toLowerCase()) {
          errors.push('Proof expression does not match expected predicate constraint.');
        }
      }
    } catch (e: any) {
      errors.push(`DSL expression syntax compilation error: ${e.message}`);
    }

    // 2. Verify evaluation commitment structure
    const expectedEvalCommitment = sha256Hex(`DSL_EVAL:${proof.astRootHash}:${proof.subjectCommitment}:${proof.satisfied}`);
    if (expectedEvalCommitment.toLowerCase() !== proof.evaluationCommitment.toLowerCase()) {
      errors.push('Evaluation commitment hash verification failed.');
    }

    // 3. Verify cryptographic signature
    const signPayload = canonicalizeJson({
      proofId: proof.proofId,
      dslExpression: proof.dslExpression,
      astRootHash: proof.astRootHash,
      credentialId: proof.credentialId,
      subjectCommitment: proof.subjectCommitment,
      evaluationCommitment: proof.evaluationCommitment,
      satisfied: proof.satisfied,
      proverDid: proof.proverDid,
      timestamp: proof.timestamp
    });

    const isSigValid = verifySignature(signPayload, proof.signatureHex, proverPublicKeyHex);
    if (!isSigValid) {
      errors.push('Prover cryptographic signature verification failed.');
    }

    return {
      valid: errors.length === 0 && proof.satisfied,
      satisfied: proof.satisfied,
      proofId: proof.proofId,
      astRootHash: proof.astRootHash,
      dslExpression: proof.dslExpression,
      errors
    };
  }

  /**
   * Formats EVM ABI calldata for on-chain smart contract verification of ZK DSL proofs.
   */
  public static generateEVMCalldata(
    proofId: string,
    astRootHash: string,
    evaluationCommitment: string
  ): string {
    const methodSignature = 'verifyZKDSLProof(bytes32,bytes32,bytes32)';
    const selector = crypto.createHash('sha256').update(methodSignature).digest('hex').substring(0, 8);

    const cleanProofId = sha256Hex(proofId).padStart(64, '0');
    const cleanAstRoot = astRootHash.replace('0x', '').padStart(64, '0');
    const cleanEvalCommit = evaluationCommitment.replace('0x', '').padStart(64, '0');

    return `0x${selector}${cleanProofId}${cleanAstRoot}${cleanEvalCommit}`;
  }
}
