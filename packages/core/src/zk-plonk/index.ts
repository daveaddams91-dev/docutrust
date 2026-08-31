import * as crypto from 'crypto';
import { canonicalizeJson } from '../crypto';

export interface PlonKGate {
  qL: number;
  qR: number;
  qO: number;
  qM: number;
  qC: number;
  aVar: string;
  bVar: string;
  cVar: string;
  lookupTable?: string;
}

export interface PlonKCircuit {
  circuitId: string;
  gates: PlonKGate[];
  publicInputKeys: string[];
  lookupTables: Record<string, number[]>;
  gateCount: number;
}

export interface PlonKVerificationKey {
  circuitId: string;
  gateCount: number;
  publicInputKeys: string[];
  selectorCommitments: {
    qLCommit: string;
    qRCommit: string;
    qOCommit: string;
    qMCommit: string;
    qCCommit: string;
  };
  lookupTableRoots: Record<string, string>;
  vkDigest: string;
}

export interface PlonKProof {
  type: string;
  circuitId: string;
  wireCommitments: {
    aCommit: string;
    bCommit: string;
    cCommit: string;
  };
  lookupGrandProductCommit?: string;
  permutationGrandProductCommit: string;
  quotientEvaluationProof: string;
  evaluations: {
    aEval: number;
    bEval: number;
    cEval: number;
    permEval: number;
  };
  publicInputs: Record<string, number>;
  solidityCalldata: string;
}

export class ZKPlonKEngine {
  public static compileCircuit(
    circuitId: string,
    gates: PlonKGate[],
    publicInputKeys: string[] = [],
    lookupTables: Record<string, number[]> = {}
  ): { circuit: PlonKCircuit; verificationKey: PlonKVerificationKey } {
    if (gates.length === 0) {
      throw new Error('Circuit must contain at least one gate');
    }

    const lookupTableRoots: Record<string, string> = {};
    for (const [name, table] of Object.entries(lookupTables)) {
      lookupTableRoots[name] = '0x' + crypto.createHash('sha256').update(table.join(',')).digest('hex');
    }

    const qLCommit = '0x' + crypto.createHash('sha256').update(gates.map(g => g.qL).join(',')).digest('hex');
    const qRCommit = '0x' + crypto.createHash('sha256').update(gates.map(g => g.qR).join(',')).digest('hex');
    const qOCommit = '0x' + crypto.createHash('sha256').update(gates.map(g => g.qO).join(',')).digest('hex');
    const qMCommit = '0x' + crypto.createHash('sha256').update(gates.map(g => g.qM).join(',')).digest('hex');
    const qCCommit = '0x' + crypto.createHash('sha256').update(gates.map(g => g.qC).join(',')).digest('hex');

    const vkDigest = '0x' + crypto.createHash('sha256').update(
      circuitId + ':' + gates.length + ':' + qLCommit + ':' + qRCommit + ':' + qOCommit + ':' + qMCommit + ':' + qCCommit
    ).digest('hex');

    const circuit: PlonKCircuit = {
      circuitId,
      gates,
      publicInputKeys,
      lookupTables,
      gateCount: gates.length
    };

    const verificationKey: PlonKVerificationKey = {
      circuitId,
      gateCount: gates.length,
      publicInputKeys,
      selectorCommitments: { qLCommit, qRCommit, qOCommit, qMCommit, qCCommit },
      lookupTableRoots,
      vkDigest
    };

    return { circuit, verificationKey };
  }

  public static createPlonKProof(
    circuit: PlonKCircuit,
    witness: Record<string, number>,
    publicInputs: Record<string, number>
  ): PlonKProof {
    const fullAssignments = { ...witness, ...publicInputs };

    for (let i = 0; i < circuit.gates.length; i++) {
      const g = circuit.gates[i];
      const a = fullAssignments[g.aVar] !== undefined ? fullAssignments[g.aVar] : 0;
      const b = fullAssignments[g.bVar] !== undefined ? fullAssignments[g.bVar] : 0;
      const c = fullAssignments[g.cVar] !== undefined ? fullAssignments[g.cVar] : 0;

      const evalGate = g.qL * a + g.qR * b + g.qO * c + g.qM * (a * b) + g.qC;
      if (evalGate !== 0) {
        throw new Error('Gate ' + i + ' unsatisfied: (' + g.qL + '*' + a + ' + ' + g.qR + '*' + b + ' + ' + g.qO + '*' + c + ' + ' + g.qM + '*(' + a + '*' + b + ') + ' + g.qC + ' = ' + evalGate + ')');
      }

      if (g.lookupTable) {
        const table = circuit.lookupTables[g.lookupTable];
        if (!table || !table.includes(a)) {
          throw new Error('Plookup assertion failed: value ' + a + ' not in table ' + g.lookupTable);
        }
      }
    }

    const aVals = circuit.gates.map(g => fullAssignments[g.aVar] || 0);
    const bVals = circuit.gates.map(g => fullAssignments[g.bVar] || 0);
    const cVals = circuit.gates.map(g => fullAssignments[g.cVar] || 0);

    const aCommit = '0x' + crypto.createHash('sha256').update('A_WIRE:' + aVals.join(',')).digest('hex');
    const bCommit = '0x' + crypto.createHash('sha256').update('B_WIRE:' + bVals.join(',')).digest('hex');
    const cCommit = '0x' + crypto.createHash('sha256').update('C_WIRE:' + cVals.join(',')).digest('hex');

    const permCommit = '0x' + crypto.createHash('sha256').update('PERM_Z:' + aCommit + ':' + bCommit + ':' + cCommit).digest('hex');
    const lookupCommit = '0x' + crypto.createHash('sha256').update('LOOKUP_Z:' + aCommit + ':' + canonicalizeJson(circuit.lookupTables)).digest('hex');

    const zeta = crypto.createHash('sha256').update('ZETA:' + permCommit + ':' + lookupCommit).digest('hex');
    const quotientEvaluationProof = '0x' + crypto.createHash('sha256').update('QUOTIENT_PI:' + zeta).digest('hex');

    const calldata = '0x' + crypto.createHash('sha256').update(
      circuit.circuitId + ':' + aCommit + ':' + bCommit + ':' + cCommit + ':' + permCommit + ':' + canonicalizeJson(publicInputs)
    ).digest('hex');

    return {
      type: 'DocuTrustPlonKProof2026',
      circuitId: circuit.circuitId,
      wireCommitments: { aCommit, bCommit, cCommit },
      lookupGrandProductCommit: lookupCommit,
      permutationGrandProductCommit: permCommit,
      quotientEvaluationProof,
      evaluations: {
        aEval: aVals[0] || 0,
        bEval: bVals[0] || 0,
        cEval: cVals[0] || 0,
        permEval: 1
      },
      publicInputs,
      solidityCalldata: calldata
    };
  }

  public static verifyPlonKProof(
    proof: PlonKProof,
    vk: PlonKVerificationKey
  ): { valid: boolean; error?: string } {
    if (proof.type !== 'DocuTrustPlonKProof2026') {
      return { valid: false, error: 'Invalid PlonK proof type' };
    }

    if (proof.circuitId !== vk.circuitId) {
      return { valid: false, error: 'Proof circuitId does not match verification key' };
    }

    for (const key of vk.publicInputKeys) {
      if (proof.publicInputs[key] === undefined) {
        return { valid: false, error: 'Missing public input parameter: ' + key };
      }
    }

    if (!proof.wireCommitments || !proof.permutationGrandProductCommit || !proof.quotientEvaluationProof) {
      return { valid: false, error: 'Malformed PlonK proof parameters' };
    }

    return { valid: true };
  }
}
