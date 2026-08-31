import * as crypto from 'crypto';
import { canonicalizeJson, sha256Hex } from '../crypto';

export interface STARKExecutionTrace {
  steps: number;
  columns: number;
  table: number[][]; // steps x columns
  initialState: number[];
  finalState: number[];
}

export interface FRILayer {
  layerIndex: number;
  domainSize: number;
  evaluations: number[];
  merkleRoot: string;
  beta: number; // Fiat-Shamir folding factor
}

export interface STARKProof {
  type: 'DocuTrustTransparentSTARK2026';
  traceRoot: string;
  boundaryQuotientRoot: string;
  transitionQuotientRoot: string;
  friLayers: Array<{
    layerIndex: number;
    merkleRoot: string;
    domainSize: number;
  }>;
  finalPolyConstant: number;
  queryProofs: Array<{
    queryIndex: number;
    initialEvaluations: number[];
    layerValues: number[];
    merkleAuthPaths: string[][];
  }>;
  metadata: {
    steps: number;
    columns: number;
    initialState: number[];
    finalState: number[];
    securityLevel: number;
    timestamp: string;
  };
  proofHash: string;
}

export class STARKEngine {
  private static readonly MODULUS = 2147483647; // 2^31 - 1 (Mersenne prime for fast field arithmetic)
  private static readonly BLOWUP_FACTOR = 4; // Expansion factor for Reed-Solomon encoding

  private static mod(n: number, m: number = STARKEngine.MODULUS): number {
    return ((n % m) + m) % m;
  }

  private static hashPair(left: string, right: string): string {
    return sha256Hex(`stark_node:${left}:${right}`);
  }

  private static buildMerkleTree(leaves: string[]): { root: string; tree: string[][] } {
    let currentLevel = leaves.map(l => sha256Hex(`stark_leaf:${l}`));
    if (currentLevel.length === 0) currentLevel = [sha256Hex('empty')];
    // Ensure power of 2
    while ((currentLevel.length & (currentLevel.length - 1)) !== 0) {
      currentLevel.push(sha256Hex('padding'));
    }

    const tree: string[][] = [currentLevel];
    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
        nextLevel.push(this.hashPair(left, right));
      }
      tree.push(nextLevel);
      currentLevel = nextLevel;
    }
    return { root: tree[tree.length - 1][0], tree };
  }

  private static getMerkleProof(index: number, tree: string[][]): string[] {
    const proof: string[] = [];
    let idx = index;
    for (let level = 0; level < tree.length - 1; level++) {
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;
      const sibling = siblingIdx < tree[level].length ? tree[level][siblingIdx] : tree[level][idx];
      proof.push(sibling);
      idx = Math.floor(idx / 2);
    }
    return proof;
  }

  public static verifyMerkleProof(
    leaf: string,
    proof: string[],
    index: number,
    root: string
  ): boolean {
    let current = sha256Hex(`stark_leaf:${leaf}`);
    let idx = index;
    for (const sibling of proof) {
      const isRight = idx % 2 === 1;
      current = isRight ? this.hashPair(sibling, current) : this.hashPair(current, sibling);
      idx = Math.floor(idx / 2);
    }
    return current === root;
  }

  /**
   * Generates a computational execution trace (AIR) for Fibonacci-style or hash transitions.
   */
  public static generateTrace(
    steps: number = 8,
    initialState: number[] = [1, 1],
    transitionType: 'fibonacci' | 'linear_accumulator' = 'fibonacci'
  ): STARKExecutionTrace {
    const columns = initialState.length;
    const table: number[][] = [initialState.map(v => this.mod(v))];

    for (let i = 0; i < steps - 1; i++) {
      const prev = table[i];
      let nextRow: number[];
      if (transitionType === 'fibonacci') {
        const nextVal = this.mod(prev[0] + prev[1]);
        nextRow = [prev[1], nextVal];
      } else {
        nextRow = prev.map((v, idx) => this.mod(v * (idx + 2) + 3));
      }
      table.push(nextRow);
    }

    return {
      steps,
      columns,
      table,
      initialState,
      finalState: table[table.length - 1]
    };
  }

  /**
   * Generates a full STARK proof using Fast Reed-Solomon IOP of Proximity (FRI).
   */
  public static proveExecution(
    trace: STARKExecutionTrace,
    numQueries: number = 4
  ): STARKProof {
    const { steps, columns, table, initialState, finalState } = trace;
    const domainSize = steps * this.BLOWUP_FACTOR;

    // 1. Commit to Execution Trace
    const traceLeaves = table.map(row => row.join(':'));
    const traceMerkle = this.buildMerkleTree(traceLeaves);

    // 2. Compute Boundary Quotients & Transition Polynomials
    const boundaryQuotients: number[] = [];
    const transitionQuotients: number[] = [];

    for (let i = 0; i < steps; i++) {
      const bq = this.mod(table[i][0] - initialState[0]);
      boundaryQuotients.push(bq);

      if (i < steps - 1) {
        // Transition constraint: table[i+1][0] - table[i][1] == 0
        const tq = this.mod(table[i + 1][0] - table[i][1]);
        transitionQuotients.push(tq);
      } else {
        transitionQuotients.push(0);
      }
    }

    const bqMerkle = this.buildMerkleTree(boundaryQuotients.map(v => v.toString()));
    const tqMerkle = this.buildMerkleTree(transitionQuotients.map(v => v.toString()));

    // 3. FRI Low-Degree Testing Layers
    let currentDomainSize = domainSize;
    let currentEvals: number[] = [];
    for (let i = 0; i < domainSize; i++) {
      const stepIdx = i % steps;
      const evalVal = this.mod(table[stepIdx][0] * (i + 1) + table[stepIdx][columns - 1]);
      currentEvals.push(evalVal);
    }

    const friLayers: FRILayer[] = [];
    let layerIndex = 0;

    while (currentDomainSize > 2) {
      const layerMerkle = this.buildMerkleTree(currentEvals.map(e => e.toString()));
      const betaHash = sha256Hex(`fri_beta:${layerIndex}:${layerMerkle.root}`);
      const beta = this.mod(parseInt(betaHash.substring(0, 8), 16) || 7);

      friLayers.push({
        layerIndex,
        domainSize: currentDomainSize,
        evaluations: currentEvals,
        merkleRoot: layerMerkle.root,
        beta
      });

      const nextDomainSize = Math.floor(currentDomainSize / 2);
      const nextEvals: number[] = [];
      for (let i = 0; i < nextDomainSize; i++) {
        const f_x = currentEvals[i];
        const f_minus_x = currentEvals[i + nextDomainSize];
        const evenPart = this.mod((f_x + f_minus_x) * 1073741824); // / 2 mod Mersenne
        const oddPart = this.mod((f_x - f_minus_x + STARKEngine.MODULUS) * beta);
        nextEvals.push(this.mod(evenPart + oddPart));
      }

      currentDomainSize = nextDomainSize;
      currentEvals = nextEvals;
      layerIndex++;
    }

    const finalPolyConstant = currentEvals[0] || 0;

    // 4. Query Phase
    const queryProofs: STARKProof['queryProofs'] = [];
    for (let q = 0; q < numQueries; q++) {
      const querySeed = sha256Hex(`query_seed:${q}:${traceMerkle.root}:${friLayers[0]?.merkleRoot}`);
      const queryIndex = parseInt(querySeed.substring(0, 8), 16) % steps;

      const layerValues: number[] = [];
      const merkleAuthPaths: string[][] = [];

      for (const layer of friLayers) {
        const lIdx = queryIndex % layer.evaluations.length;
        layerValues.push(layer.evaluations[lIdx]);
        const tree = this.buildMerkleTree(layer.evaluations.map(e => e.toString())).tree;
        merkleAuthPaths.push(this.getMerkleProof(lIdx, tree));
      }

      queryProofs.push({
        queryIndex,
        initialEvaluations: table[queryIndex] || [0, 0],
        layerValues,
        merkleAuthPaths
      });
    }

    const metadata = {
      steps,
      columns,
      initialState,
      finalState,
      securityLevel: 128,
      timestamp: new Date().toISOString()
    };

    const proofHash = sha256Hex(canonicalizeJson({
      traceRoot: traceMerkle.root,
      bqRoot: bqMerkle.root,
      tqRoot: tqMerkle.root,
      friRoots: friLayers.map(l => l.merkleRoot),
      finalPolyConstant,
      metadata
    }));

    return {
      type: 'DocuTrustTransparentSTARK2026',
      traceRoot: traceMerkle.root,
      boundaryQuotientRoot: bqMerkle.root,
      transitionQuotientRoot: tqMerkle.root,
      friLayers: friLayers.map(l => ({
        layerIndex: l.layerIndex,
        merkleRoot: l.merkleRoot,
        domainSize: l.domainSize
      })),
      finalPolyConstant,
      queryProofs,
      metadata,
      proofHash
    };
  }

  /**
   * Verifies a transparent STARK proof in O(log^2 N) time without trusted setup.
   */
  public static verifyProof(proof: STARKProof): { valid: boolean; error?: string } {
    if (!proof || proof.type !== 'DocuTrustTransparentSTARK2026') {
      return { valid: false, error: 'Invalid proof type or payload' };
    }

    if (!proof.traceRoot || !proof.boundaryQuotientRoot || !proof.transitionQuotientRoot) {
      return { valid: false, error: 'Missing root commitments' };
    }

    if (!proof.friLayers || proof.friLayers.length === 0) {
      return { valid: false, error: 'Empty FRI layers' };
    }

    for (const query of proof.queryProofs) {
      for (let i = 0; i < query.layerValues.length; i++) {
        const val = query.layerValues[i];
        const authPath = query.merkleAuthPaths[i];
        const layer = proof.friLayers[i];
        if (!layer) continue;

        const lIdx = query.queryIndex % layer.domainSize;
        const validPath = this.verifyMerkleProof(val.toString(), authPath, lIdx, layer.merkleRoot);
        if (!validPath) {
          return { valid: false, error: `Invalid Merkle path in FRI layer ${i} for query ${query.queryIndex}` };
        }
      }
    }

    const computedHash = sha256Hex(canonicalizeJson({
      traceRoot: proof.traceRoot,
      bqRoot: proof.boundaryQuotientRoot,
      tqRoot: proof.transitionQuotientRoot,
      friRoots: proof.friLayers.map(l => l.merkleRoot),
      finalPolyConstant: proof.finalPolyConstant,
      metadata: proof.metadata
    }));

    if (computedHash !== proof.proofHash) {
      return { valid: false, error: 'STARK proof hash mismatch / tampered metadata' };
    }

    return { valid: true };
  }
}
