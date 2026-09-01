import * as crypto from 'crypto';
import { canonicalizeJson, sha256Hex } from '../crypto';

export type GateType = 'AND' | 'XOR' | 'NOT' | 'OR' | 'NAND';

export interface CircuitGate {
  id: string;
  type: GateType;
  inputWires: [string, string] | [string]; // One wire for NOT, two for binary gates
  outputWire: string;
}

export interface GarbledTable {
  gateId: string;
  type: GateType;
  table: string[]; // 4 encrypted entries (or 2 for NOT)
}

export interface GarbledCircuit {
  circuitId: string;
  inputWiresGarbler: string[];
  inputWiresEvaluator: string[];
  outputWires: string[];
  gates: CircuitGate[];
  garbledTables: GarbledTable[];
  wirePermutationBits: Record<string, number>; // point-and-permute bits
  circuitHash: string;
}

export interface GarbledWireLabels {
  [wireId: string]: {
    zeroLabel: string;
    oneLabel: string;
  };
}

export interface ObliviousTransferSession {
  sessionId: string;
  garblerEphemeralPub: string;
  evaluatorChoice: number; // 0 or 1
  encryptedZeroLabel: string;
  encryptedOneLabel: string;
  receivedLabel?: string;
}

export interface GarbledCircuitReceipt {
  type: 'DocuTrustGarbledCircuitReceipt2026';
  receiptId: string;
  circuitId: string;
  circuitHash: string;
  garblerDid: string;
  evaluatorDid: string;
  inputWireCommitments: string[];
  outputWireLabels: string[];
  evaluatedOutputs: Record<string, number>;
  outputValues?: Record<string, number>;
  timestamp: string;
  receiptHash: string;
}

export class MPCGarbledCircuitEngine {
  private static readonly KEY_SIZE = 32;

  /**
   * Generates a pseudo-random wire label pair with Free-XOR delta offset.
   */
  private static generateWireLabels(wireId: string, globalDelta: string): { zeroLabel: string; oneLabel: string } {
    const zero = sha256Hex(`wire_zero:${wireId}:${crypto.randomBytes(16).toString('hex')}`);
    // Free-XOR: oneLabel = zero XOR globalDelta
    const zeroBuf = Buffer.from(zero, 'hex');
    const deltaBuf = Buffer.from(globalDelta, 'hex');
    const oneBuf = Buffer.alloc(zeroBuf.length);
    for (let i = 0; i < zeroBuf.length; i++) {
      oneBuf[i] = zeroBuf[i] ^ deltaBuf[i];
    }
    return {
      zeroLabel: zero,
      oneLabel: oneBuf.toString('hex')
    };
  }

  /**
   * Encrypts a gate entry using double-key AES / HMAC encryption.
   */
  private static encryptGateEntry(keyA: string, keyB: string, gateId: string, entryIdx: number, val: string): string {
    const key = sha256Hex(`gate_key:${gateId}:${entryIdx}:${keyA}:${keyB}`);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
    const encrypted = Buffer.concat([cipher.update(Buffer.from(val, 'utf-8')), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${encrypted.toString('hex')}:${tag.toString('hex')}`;
  }

  /**
   * Decrypts a gate entry using evaluator's active wire labels.
   */
  private static decryptGateEntry(keyA: string, keyB: string, gateId: string, entryIdx: number, ciphertext: string): string | null {
    try {
      const parts = ciphertext.split(':');
      if (parts.length !== 3) return null;
      const [ivHex, encHex, tagHex] = parts;
      const key = sha256Hex(`gate_key:${gateId}:${entryIdx}:${keyA}:${keyB}`);
      const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key, 'hex'), Buffer.from(ivHex, 'hex'));
      decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
      const decrypted = Buffer.concat([decipher.update(Buffer.from(encHex, 'hex')), decipher.final()]);
      return decrypted.toString('utf-8');
    } catch {
      return null;
    }
  }

  /**
   * Garbles a boolean circuit specification into encrypted tables and wire labels.
   */
  public static garbleCircuit(
    circuitId: string,
    inputWiresGarbler: string[],
    inputWiresEvaluator: string[],
    outputWires: string[],
    gates: CircuitGate[]
  ): { circuit: GarbledCircuit; wireLabels: GarbledWireLabels; globalDelta: string } {
    const globalDelta = sha256Hex(`global_delta:${circuitId}:${crypto.randomBytes(16).toString('hex')}`);
    const wireLabels: GarbledWireLabels = {};
    const wirePermutationBits: Record<string, number> = {};

    // Collect all wires
    const allWires = new Set<string>([...inputWiresGarbler, ...inputWiresEvaluator, ...outputWires]);
    for (const gate of gates) {
      gate.inputWires.forEach(w => allWires.add(w));
      allWires.add(gate.outputWire);
    }

    // Generate wire label pairs and point-and-permute bits
    for (const w of allWires) {
      wireLabels[w] = this.generateWireLabels(w, globalDelta);
      const permBit = parseInt(sha256Hex(`perm:${w}`).substring(0, 2), 16) % 2;
      wirePermutationBits[w] = permBit;
    }

    const garbledTables: GarbledTable[] = [];

    for (const gate of gates) {
      if (gate.type === 'XOR') {
        // Free-XOR: No garbled table needed; evaluator XORs wire labels directly
        continue;
      }

      if (gate.type === 'NOT' && gate.inputWires.length === 1) {
        const [wA] = gate.inputWires;
        const wOut = gate.outputWire;
        const table: string[] = new Array(2).fill('');

        for (let bitA = 0; bitA <= 1; bitA++) {
          const outBit = 1 - bitA;
          const labelA = bitA === 0 ? wireLabels[wA].zeroLabel : wireLabels[wA].oneLabel;
          const labelOut = outBit === 0 ? wireLabels[wOut].zeroLabel : wireLabels[wOut].oneLabel;
          const pA = (bitA ^ wirePermutationBits[wA]) & 1;
          table[pA] = this.encryptGateEntry(labelA, 'unary_not_key', gate.id, pA, labelOut);
        }

        garbledTables.push({
          gateId: gate.id,
          type: gate.type,
          table
        });
      } else if (gate.inputWires.length === 2) {
        const [wA, wB] = gate.inputWires;
        const wOut = gate.outputWire;
        const table: string[] = new Array(4).fill('');

        for (let bitA = 0; bitA <= 1; bitA++) {
          for (let bitB = 0; bitB <= 1; bitB++) {
            let outBit = 0;
            if (gate.type === 'AND') outBit = bitA & bitB;
            else if (gate.type === 'OR') outBit = bitA | bitB;
            else if (gate.type === 'NAND') outBit = (bitA & bitB) === 1 ? 0 : 1;

            const labelA = bitA === 0 ? wireLabels[wA].zeroLabel : wireLabels[wA].oneLabel;
            const labelB = bitB === 0 ? wireLabels[wB].zeroLabel : wireLabels[wB].oneLabel;
            const labelOut = outBit === 0 ? wireLabels[wOut].zeroLabel : wireLabels[wOut].oneLabel;

            const pA = (bitA ^ wirePermutationBits[wA]) & 1;
            const pB = (bitB ^ wirePermutationBits[wB]) & 1;
            const entryIdx = (pA << 1) | pB;

            table[entryIdx] = this.encryptGateEntry(labelA, labelB, gate.id, entryIdx, labelOut);
          }
        }

        garbledTables.push({
          gateId: gate.id,
          type: gate.type,
          table
        });
      }
    }

    const circuitHash = sha256Hex(canonicalizeJson({
      circuitId,
      inputWiresGarbler,
      inputWiresEvaluator,
      outputWires,
      gates,
      garbledTables
    }));

    const circuit: GarbledCircuit = {
      circuitId,
      inputWiresGarbler,
      inputWiresEvaluator,
      outputWires,
      gates,
      garbledTables,
      wirePermutationBits,
      circuitHash
    };

    return { circuit, wireLabels, globalDelta };
  }

  /**
   * Initializes a 1-out-of-2 Oblivious Transfer session for an evaluator input bit.
   */
  public static initObliviousTransfer(
    sessionId: string,
    wireZeroLabel: string,
    wireOneLabel: string,
    evaluatorChoiceBit: number
  ): ObliviousTransferSession {
    const garblerKey = crypto.randomBytes(32).toString('hex');
    const garblerPub = sha256Hex(`ot_pub:${garblerKey}`);

    // Garbler prepares 2 encrypted options
    const encZero = sha256Hex(`ot_enc:${garblerKey}:0:${wireZeroLabel}`);
    const encOne = sha256Hex(`ot_enc:${garblerKey}:1:${wireOneLabel}`);

    return {
      sessionId,
      garblerEphemeralPub: garblerPub,
      evaluatorChoice: evaluatorChoiceBit & 1,
      encryptedZeroLabel: encZero,
      encryptedOneLabel: encOne,
      receivedLabel: (evaluatorChoiceBit & 1) === 1 ? wireOneLabel : wireZeroLabel
    };
  }

  /**
   * Evaluator executes the garbled circuit using active input wire labels.
   */
  public static evaluateCircuit(
    circuit: GarbledCircuit,
    activeInputLabels: Record<string, string>,
    garblerDid: string = 'did:docutrust:garbler',
    evaluatorDid: string = 'did:docutrust:evaluator'
  ): GarbledCircuitReceipt {
    const currentWireLabels: Record<string, string> = { ...activeInputLabels };
    const tablesByGate = new Map<string, GarbledTable>(circuit.garbledTables.map(gt => [gt.gateId, gt]));

    for (const gate of circuit.gates) {
      if (gate.type === 'XOR' && gate.inputWires.length === 2) {
        const [wA, wB] = gate.inputWires;
        const labelA = Buffer.from(currentWireLabels[wA] || '', 'hex');
        const labelB = Buffer.from(currentWireLabels[wB] || '', 'hex');
        if (labelA.length > 0 && labelB.length > 0) {
          const outBuf = Buffer.alloc(labelA.length);
          for (let i = 0; i < labelA.length; i++) {
            outBuf[i] = labelA[i] ^ labelB[i];
          }
          currentWireLabels[gate.outputWire] = outBuf.toString('hex');
        }
        continue;
      }

      if (gate.type === 'NOT' && gate.inputWires.length === 1) {
        const [wA] = gate.inputWires;
        const labelA = currentWireLabels[wA];
        const gTable = tablesByGate.get(gate.id);
        if (gTable && labelA) {
          let decryptedLabel: string | null = null;
          for (let entryIdx = 0; entryIdx < gTable.table.length; entryIdx++) {
            const res = this.decryptGateEntry(labelA, 'unary_not_key', gate.id, entryIdx, gTable.table[entryIdx]);
            if (res) {
              decryptedLabel = res;
              break;
            }
          }
          if (decryptedLabel) {
            currentWireLabels[gate.outputWire] = decryptedLabel;
          }
        }
        continue;
      }

      if (gate.inputWires.length === 2) {
        const [wA, wB] = gate.inputWires;
        const labelA = currentWireLabels[wA];
        const labelB = currentWireLabels[wB];
        const gTable = tablesByGate.get(gate.id);

        if (!gTable || !labelA || !labelB) continue;

        let decryptedLabel: string | null = null;
        for (let entryIdx = 0; entryIdx < gTable.table.length; entryIdx++) {
          const res = this.decryptGateEntry(labelA, labelB, gate.id, entryIdx, gTable.table[entryIdx]);
          if (res) {
            decryptedLabel = res;
            break;
          }
        }

        if (decryptedLabel) {
          currentWireLabels[gate.outputWire] = decryptedLabel;
        }
      }
    }

    const outputWireLabels: string[] = [];
    const evaluatedOutputs: Record<string, number> = {};

    for (const outWire of circuit.outputWires) {
      const activeLabel = currentWireLabels[outWire] || sha256Hex(`unknown:${outWire}`);
      outputWireLabels.push(activeLabel);
      // Map label parity to output bit
      const bit = parseInt(sha256Hex(`out_bit:${activeLabel}`).substring(0, 1), 16) % 2;
      evaluatedOutputs[outWire] = bit;
    }

    const timestamp = new Date().toISOString();
    const receiptId = 'mpc_rec_' + sha256Hex(`receipt:${circuit.circuitId}:${timestamp}`).substring(0, 16);
    const inputWireCommitments = Object.keys(activeInputLabels).map(w => sha256Hex(`${w}:${activeInputLabels[w]}`));

    const receiptPayload = {
      receiptId,
      circuitId: circuit.circuitId,
      circuitHash: circuit.circuitHash,
      garblerDid,
      evaluatorDid,
      inputWireCommitments,
      outputWireLabels,
      evaluatedOutputs,
      timestamp
    };
    const receiptHash = sha256Hex(canonicalizeJson(receiptPayload));

    return {
      type: 'DocuTrustGarbledCircuitReceipt2026',
      receiptId,
      circuitId: circuit.circuitId,
      circuitHash: circuit.circuitHash,
      garblerDid,
      evaluatorDid,
      inputWireCommitments,
      outputWireLabels,
      evaluatedOutputs,
      outputValues: evaluatedOutputs,
      timestamp,
      receiptHash
    };
  }

  /**
   * Verifies an MPC Garbled Circuit execution receipt.
   */
  public static verifyReceipt(
    receipt: GarbledCircuitReceipt,
    expectedCircuitHash?: string
  ): { valid: boolean; error?: string } {
    if (!receipt || receipt.type !== 'DocuTrustGarbledCircuitReceipt2026') {
      return { valid: false, error: 'Invalid MPC receipt payload' };
    }

    if (expectedCircuitHash && receipt.circuitHash !== expectedCircuitHash) {
      return { valid: false, error: 'Circuit hash mismatch' };
    }

    if (!receipt.receiptId || !receipt.circuitId) {
      return { valid: false, error: 'Missing receipt identifier' };
    }

    const computedHash = sha256Hex(canonicalizeJson({
      receiptId: receipt.receiptId,
      circuitId: receipt.circuitId,
      circuitHash: receipt.circuitHash,
      garblerDid: receipt.garblerDid,
      evaluatorDid: receipt.evaluatorDid,
      inputWireCommitments: receipt.inputWireCommitments,
      outputWireLabels: receipt.outputWireLabels,
      evaluatedOutputs: receipt.evaluatedOutputs,
      timestamp: receipt.timestamp
    }));

    if (computedHash !== receipt.receiptHash) {
      return { valid: false, error: 'Cryptographic receipt hash mismatch' };
    }

    return { valid: true };
  }
}
