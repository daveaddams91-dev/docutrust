/**
 * @file packages/core/src/verifiable-compute/index.ts
 * @description Verifiable Off-Chain Computation & Execution Trace Engine (DocuTrust v12.0.0)
 * Allows deterministic off-chain execution of parameterized logic functions (eligibility verification,
 * weighted score calculations, compliance aggregations) with unforgeable trace commitments & receipts.
 */

import * as crypto from 'crypto';
import { sha256Hex, signMessage, verifySignature, canonicalizeJson, KeyPair } from '../crypto/index.js';

export interface ComputeInstruction {
  op: 'ADD' | 'SUB' | 'MUL' | 'DIV' | 'WEIGHTED_SUM' | 'THRESHOLD_CHECK' | 'RANGE_CHECK' | 'SET_CONTAINS' | 'HASH_CHAIN';
  args: any[];
  outputVar: string;
}

export interface ComputeProgram {
  programId: string;
  version: string;
  instructions: ComputeInstruction[];
}

export interface ExecutionStepTrace {
  stepIndex: number;
  op: string;
  inputs: any[];
  result: any;
  stateCommitment: string;
}

export interface DocuTrustComputeReceipt {
  type: 'DocuTrustComputeReceipt2026';
  receiptId: string;
  programId: string;
  inputsCommitment: string;
  outputsCommitment: string;
  executionTraceHash: string;
  stepCount: number;
  finalOutputs: Record<string, any>;
  proverDid: string;
  signatureHex: string;
  timestamp: string;
}

export class VerifiableComputeEngine {
  /**
   * Deterministically executes a verifiable compute program against provided input variables.
   */
  public static execute(
    program: ComputeProgram,
    inputs: Record<string, any>,
    proverKeyPair?: KeyPair
  ): {
    finalOutputs: Record<string, any>;
    trace: ExecutionStepTrace[];
    receipt?: DocuTrustComputeReceipt;
  } {
    const memory: Record<string, any> = { ...inputs };
    const trace: ExecutionStepTrace[] = [];

    const resolveVal = (val: any): any => {
      if (typeof val === 'string' && val.startsWith('$')) {
        return memory[val.slice(1)];
      }
      if (Array.isArray(val)) {
        return val.map(resolveVal);
      }
      return val;
    };

    for (let i = 0; i < program.instructions.length; i++) {
      const instr = program.instructions[i];
      const resolvedArgs = instr.args.map(resolveVal);

      let res: any;
      switch (instr.op) {
        case 'ADD':
          res = Number(resolvedArgs[0]) + Number(resolvedArgs[1]);
          break;
        case 'SUB':
          res = Number(resolvedArgs[0]) - Number(resolvedArgs[1]);
          break;
        case 'MUL':
          res = Number(resolvedArgs[0]) * Number(resolvedArgs[1]);
          break;
        case 'DIV':
          res = Number(resolvedArgs[1]) !== 0 ? Number(resolvedArgs[0]) / Number(resolvedArgs[1]) : 0;
          break;
        case 'WEIGHTED_SUM': {
          const values: number[] = Array.isArray(resolvedArgs[0]) ? resolvedArgs[0] : [];
          const weights: number[] = Array.isArray(resolvedArgs[1]) ? resolvedArgs[1] : [];
          let sum = 0;
          for (let j = 0; j < Math.min(values.length, weights.length); j++) {
            sum += Number(values[j]) * Number(weights[j]);
          }
          res = sum;
          break;
        }
        case 'THRESHOLD_CHECK':
          res = Number(resolvedArgs[0]) >= Number(resolvedArgs[1]);
          break;
        case 'RANGE_CHECK':
          res = Number(resolvedArgs[0]) >= Number(resolvedArgs[1]) && Number(resolvedArgs[0]) <= Number(resolvedArgs[2]);
          break;
        case 'SET_CONTAINS': {
          const target = resolvedArgs[0];
          const setList = Array.isArray(resolvedArgs[1]) ? resolvedArgs[1] : [];
          res = setList.includes(target);
          break;
        }
        case 'HASH_CHAIN': {
          let h = String(resolvedArgs[0]);
          const rounds = Number(resolvedArgs[1]) || 1;
          for (let r = 0; r < rounds; r++) {
            h = sha256Hex(h);
          }
          res = h;
          break;
        }
        default:
          throw new Error(`Unsupported compute opcode: ${instr.op}`);
      }

      memory[instr.outputVar] = res;

      const stateCommitment = sha256Hex(canonicalizeJson(memory));
      trace.push({
        stepIndex: i,
        op: instr.op,
        inputs: resolvedArgs,
        result: res,
        stateCommitment
      });
    }

    // Filter memory to only instruction outputs
    const finalOutputs: Record<string, any> = {};
    for (const instr of program.instructions) {
      finalOutputs[instr.outputVar] = memory[instr.outputVar];
    }

    let receipt: DocuTrustComputeReceipt | undefined;
    if (proverKeyPair) {
      const inputsCommitment = sha256Hex(canonicalizeJson(inputs));
      const outputsCommitment = sha256Hex(canonicalizeJson(finalOutputs));
      const executionTraceHash = sha256Hex(canonicalizeJson(trace));
      const receiptId = `vcomp-${crypto.randomBytes(8).toString('hex')}`;
      const timestamp = new Date().toISOString();

      const signPayload = {
        receiptId,
        programId: program.programId,
        inputsCommitment,
        outputsCommitment,
        executionTraceHash,
        stepCount: trace.length,
        finalOutputs,
        proverDid: proverKeyPair.did,
        timestamp
      };

      const signatureHex = signMessage(canonicalizeJson(signPayload), proverKeyPair.privateKeyHex);

      receipt = {
        type: 'DocuTrustComputeReceipt2026',
        receiptId,
        programId: program.programId,
        inputsCommitment,
        outputsCommitment,
        executionTraceHash,
        stepCount: trace.length,
        finalOutputs,
        proverDid: proverKeyPair.did,
        signatureHex,
        timestamp
      };
    }

    return {
      finalOutputs,
      trace,
      receipt
    };
  }

  /**
   * Verifies the cryptographic receipt and commitments of a verifiable computation.
   */
  public static verifyReceipt(
    receipt: DocuTrustComputeReceipt,
    proverPublicKeyHex: string,
    inputs?: Record<string, any>
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!receipt || receipt.type !== 'DocuTrustComputeReceipt2026') {
      return { valid: false, errors: ['Invalid compute receipt type.'] };
    }

    const signPayload = {
      receiptId: receipt.receiptId,
      programId: receipt.programId,
      inputsCommitment: receipt.inputsCommitment,
      outputsCommitment: receipt.outputsCommitment,
      executionTraceHash: receipt.executionTraceHash,
      stepCount: receipt.stepCount,
      finalOutputs: receipt.finalOutputs,
      proverDid: receipt.proverDid,
      timestamp: receipt.timestamp
    };

    const isSigValid = verifySignature(canonicalizeJson(signPayload), receipt.signatureHex, proverPublicKeyHex);
    if (!isSigValid) {
      errors.push('Prover signature verification failed on compute receipt.');
    }

    // Verify output commitment
    const actualOutputCommitment = sha256Hex(canonicalizeJson(receipt.finalOutputs));
    if (actualOutputCommitment.toLowerCase() !== receipt.outputsCommitment.toLowerCase()) {
      errors.push('Outputs commitment does not match finalOutputs payload.');
    }

    // If original inputs provided, verify input commitment
    if (inputs) {
      const actualInputCommitment = sha256Hex(canonicalizeJson(inputs));
      if (actualInputCommitment.toLowerCase() !== receipt.inputsCommitment.toLowerCase()) {
        errors.push('Inputs commitment does not match provided inputs.');
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}
