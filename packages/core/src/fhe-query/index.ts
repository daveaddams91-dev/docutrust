import * as crypto from 'crypto';
import { canonicalizeJson } from '../crypto';

export interface FHEKeyPair {
  publicKey: {
    A: number[][];
    B: number[];
    modulus: number;
    dimension: number;
    id: string;
  };
  privateKey: {
    secret: number[];
    modulus: number;
    dimension: number;
    id: string;
  };
}

export interface FHECiphertext {
  c0: number[];
  c1: number;
  noiseBudget: number;
  modulus: number;
  dimension: number;
  tag?: string;
}

export interface FHEQueryReceipt {
  type: string;
  queryId: string;
  filterType: string;
  recordCount: number;
  resultCiphertext: FHECiphertext;
  noiseBudgetRemaining: number;
  timestamp: string;
  issuer: string;
  signature: string;
}

export class FHEQueryEngine {
  private static readonly DEFAULT_MODULUS = 2147483647; // 2^31 - 1
  private static readonly DEFAULT_DIMENSION = 8;
  private static readonly INITIAL_NOISE_BUDGET = 100;

  private static mod(n: number, m: number): number {
    return ((n % m) + m) % m;
  }

  public static generateKeyPair(
    dimension: number = this.DEFAULT_DIMENSION,
    modulus: number = this.DEFAULT_MODULUS
  ): FHEKeyPair {
    const keyId = 'fhe_' + crypto.randomBytes(8).toString('hex');
    const secret: number[] = [];
    for (let i = 0; i < dimension; i++) {
      secret.push(crypto.randomInt(1, 16));
    }

    const A: number[][] = [];
    const B: number[] = [];
    for (let i = 0; i < dimension; i++) {
      const row: number[] = [];
      let dot = 0;
      for (let j = 0; j < dimension; j++) {
        const a_ij = crypto.randomInt(0, 10000);
        row.push(a_ij);
        dot = (dot + a_ij * secret[j]) % modulus;
      }
      A.push(row);
      B.push(this.mod(dot, modulus));
    }

    return {
      publicKey: { A, B, modulus, dimension, id: keyId },
      privateKey: { secret, modulus, dimension, id: keyId }
    };
  }

  public static encryptValue(
    value: number,
    publicKey: FHEKeyPair['publicKey'],
    tag?: string
  ): FHECiphertext {
    const { A, B, modulus, dimension } = publicKey;
    const vMod = this.mod(Math.floor(value), modulus);

    const r: number[] = [];
    for (let i = 0; i < dimension; i++) {
      r.push(crypto.randomInt(0, 2));
    }

    const c0: number[] = new Array(dimension).fill(0);
    for (let j = 0; j < dimension; j++) {
      let sum = 0;
      for (let i = 0; i < dimension; i++) {
        sum = (sum + r[i] * A[i][j]) % modulus;
      }
      c0[j] = this.mod(sum, modulus);
    }

    let dotB = 0;
    for (let i = 0; i < dimension; i++) {
      dotB = (dotB + r[i] * B[i]) % modulus;
    }
    const c1 = this.mod(dotB + vMod, modulus);

    return {
      c0,
      c1,
      noiseBudget: this.INITIAL_NOISE_BUDGET - 5,
      modulus,
      dimension,
      tag: tag || 'scalar'
    };
  }

  public static decryptValue(
    ciphertext: FHECiphertext,
    privateKey: FHEKeyPair['privateKey']
  ): number {
    const { c0, c1, modulus, dimension } = ciphertext;
    const { secret } = privateKey;

    if (c0.length !== dimension || secret.length !== dimension) {
      throw new Error('Ciphertext and private key dimension mismatch');
    }

    let dot = 0;
    for (let i = 0; i < dimension; i++) {
      dot = (dot + c0[i] * secret[i]) % modulus;
    }

    let diff = this.mod(c1 - dot, modulus);
    if (diff > modulus / 2) {
      diff = diff - modulus;
    }
    return Math.round(diff);
  }

  public static addCiphertexts(c1: FHECiphertext, c2: FHECiphertext): FHECiphertext {
    if (c1.modulus !== c2.modulus || c1.dimension !== c2.dimension) {
      throw new Error('Cannot add ciphertexts with incompatible parameters');
    }
    const dimension = c1.dimension;
    const modulus = c1.modulus;

    const c0: number[] = [];
    for (let i = 0; i < dimension; i++) {
      c0.push(this.mod(c1.c0[i] + c2.c0[i], modulus));
    }
    const c1Val = this.mod(c1.c1 + c2.c1, modulus);
    const noiseBudget = Math.max(0, Math.min(c1.noiseBudget, c2.noiseBudget) - 2);

    return {
      c0,
      c1: c1Val,
      noiseBudget,
      modulus,
      dimension,
      tag: 'sum(' + (c1.tag || 'c1') + ',' + (c2.tag || 'c2') + ')'
    };
  }

  public static multiplyScalar(c: FHECiphertext, scalar: number): FHECiphertext {
    const modulus = c.modulus;
    const dimension = c.dimension;
    const sMod = this.mod(Math.floor(scalar), modulus);

    const c0: number[] = c.c0.map(v => this.mod(v * sMod, modulus));
    const c1Val = this.mod(c.c1 * sMod, modulus);
    const noiseBudget = Math.max(0, c.noiseBudget - Math.ceil(Math.log2(Math.abs(scalar) + 1)) - 3);

    return {
      c0,
      c1: c1Val,
      noiseBudget,
      modulus,
      dimension,
      tag: 'scale(' + (c.tag || 'c') + ',' + scalar + ')'
    };
  }

  public static linearCombination(
    ciphertexts: FHECiphertext[],
    weights: number[]
  ): FHECiphertext {
    if (ciphertexts.length === 0 || ciphertexts.length !== weights.length) {
      throw new Error('Ciphertexts and weights must be non-empty and of equal length');
    }

    let acc = this.multiplyScalar(ciphertexts[0], weights[0]);
    for (let i = 1; i < ciphertexts.length; i++) {
      const term = this.multiplyScalar(ciphertexts[i], weights[i]);
      acc = this.addCiphertexts(acc, term);
    }
    return acc;
  }

  public static evaluateEncryptedEquality(
    c1: FHECiphertext,
    c2: FHECiphertext
  ): FHECiphertext {
    const negC2 = this.multiplyScalar(c2, -1);
    return this.addCiphertexts(c1, negC2);
  }

  public static queryEncryptedDatabase(
    records: Array<{ id: string; encryptedAttributes: Record<string, FHECiphertext> }>,
    attributeName: string,
    weights?: number[]
  ): { aggregatedResult: FHECiphertext; evaluatedCount: number } {
    if (records.length === 0) {
      throw new Error('Records collection is empty');
    }
    const ciphertexts: FHECiphertext[] = [];
    const effectiveWeights: number[] = [];

    for (let i = 0; i < records.length; i++) {
      const attr = records[i].encryptedAttributes[attributeName];
      if (attr) {
        ciphertexts.push(attr);
        effectiveWeights.push(weights && weights[i] !== undefined ? weights[i] : 1);
      }
    }

    if (ciphertexts.length === 0) {
      throw new Error('No records contain attribute ' + attributeName);
    }

    const aggregatedResult = this.linearCombination(ciphertexts, effectiveWeights);
    return {
      aggregatedResult,
      evaluatedCount: ciphertexts.length
    };
  }

  public static createQueryReceipt(
    queryId: string,
    filterType: string,
    recordCount: number,
    resultCiphertext: FHECiphertext,
    issuerDid: string,
    issuerPrivateKeyHex: string
  ): FHEQueryReceipt {
    const unsignedReceipt = {
      type: 'DocuTrustFHEQueryReceipt2026',
      queryId,
      filterType,
      recordCount,
      resultCiphertext,
      noiseBudgetRemaining: resultCiphertext.noiseBudget,
      timestamp: new Date().toISOString(),
      issuer: issuerDid
    };

    const canonical = canonicalizeJson(unsignedReceipt);
    const hash = crypto.createHash('sha256').update(canonical).digest();
    const hmac = crypto.createHmac('sha256', Buffer.from(issuerPrivateKeyHex, 'hex'));
    hmac.update(hash);
    const signature = '0x' + hmac.digest('hex');

    return {
      ...unsignedReceipt,
      signature
    };
  }

  public static verifyQueryReceipt(
    receipt: FHEQueryReceipt,
    expectedIssuerPrivateKeyHex?: string
  ): { valid: boolean; noiseAcceptable: boolean; error?: string } {
    if (receipt.type !== 'DocuTrustFHEQueryReceipt2026') {
      return { valid: false, noiseAcceptable: false, error: 'Invalid receipt type' };
    }

    if (!receipt.resultCiphertext || !Array.isArray(receipt.resultCiphertext.c0)) {
      return { valid: false, noiseAcceptable: false, error: 'Malformed result ciphertext' };
    }

    const noiseAcceptable = receipt.noiseBudgetRemaining > 10;

    if (expectedIssuerPrivateKeyHex) {
      const { signature, ...unsigned } = receipt;
      const canonical = canonicalizeJson(unsigned);
      const hash = crypto.createHash('sha256').update(canonical).digest();
      const hmac = crypto.createHmac('sha256', Buffer.from(expectedIssuerPrivateKeyHex, 'hex'));
      hmac.update(hash);
      const expectedSig = '0x' + hmac.digest('hex');

      if (signature !== expectedSig) {
        return { valid: false, noiseAcceptable, error: 'Cryptographic signature mismatch' };
      }
    }

    return { valid: true, noiseAcceptable };
  }
}
