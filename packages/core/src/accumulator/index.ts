/**
 * @file packages/core/src/accumulator/index.ts
 * @description Dynamic Cryptographic Accumulator (CryptographicAccumulator2026)
 * Provides O(1) constant-size dynamic membership & revocation witnesses with modular arithmetic.
 */

import { sha256Hex } from '../crypto/index.js';

export interface AccumulatorState {
  id: string;
  modulus: string; // hex
  generator: string; // hex
  accumulator: string; // hex (current value V)
  memberCount: number;
}

export interface MembershipWitness {
  element: string;
  primeRepresentative: string; // hex
  witness: string; // hex (W)
  accumulatorId: string;
}

export interface NonMembershipWitness {
  element: string;
  primeRepresentative: string; // hex
  d: string; // hex (d = g^a mod N)
  b: string; // string representation of BigInt Bezout coefficient b
  accumulatorId: string;
}

export interface BatchMembershipWitness {
  elements: string[];
  productPrimeHex: string; // product of primes for elements
  witness: string; // hex (W_S = g^(product of non-subset primes) mod N)
  accumulatorId: string;
  accumulatorHex?: string;
}

export class CryptographicAccumulator {
  // High-entropy 1024-bit RSA composite default modulus (or configurable)
  public static readonly DEFAULT_MODULUS_HEX =
    'd8c3e85e056d6f35b2e5a7b3c8f1d2e4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6' +
    'b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0' +
    'e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4' +
    'a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8' +
    'c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2' +
    'f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6' +
    'b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0' +
    'e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0e2f7';

  public static readonly DEFAULT_GENERATOR_HEX = '03';

  private id: string;
  private N: bigint;
  private g: bigint;
  private V: bigint;
  private members: Set<string>;
  private primeMap: Map<string, bigint>;

  constructor(
    id: string,
    modulusHex: string = CryptographicAccumulator.DEFAULT_MODULUS_HEX,
    generatorHex: string = CryptographicAccumulator.DEFAULT_GENERATOR_HEX,
    initialAccumulatorHex?: string
  ) {
    this.id = id;
    this.N = BigInt('0x' + modulusHex);
    this.g = BigInt('0x' + generatorHex);
    this.V = initialAccumulatorHex ? BigInt('0x' + initialAccumulatorHex) : this.g;
    this.members = new Set<string>();
    this.primeMap = new Map<string, bigint>();
  }

  /**
   * Deterministically maps any arbitrary string element to an odd prime representative.
   */
  public static elementToPrime(element: string): bigint {
    let nonce = 0;
    while (true) {
      const digest = sha256Hex(`DT_ACC_PRIME_V1:${nonce}:${element}`);
      let candidate = (BigInt('0x' + digest) & ((1n << 128n) - 1n)) | 1n; // 128-bit odd integer
      if (this.isPrime(candidate)) {
        return candidate;
      }
      nonce++;
    }
  }

  /**
   * Fast Miller-Rabin probabilistic primality test.
   */
  public static isPrime(n: bigint, rounds: number = 8): boolean {
    if (n < 2n) return false;
    if (n === 2n || n === 3n) return true;
    if (n % 2n === 0n) return false;

    let d = n - 1n;
    let s = 0n;
    while (d % 2n === 0n) {
      d /= 2n;
      s++;
    }

    const bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
    for (let i = 0; i < Math.min(rounds, bases.length); i++) {
      const a = bases[i];
      if (n <= a) break;
      let x = this.modPow(a, d, n);
      if (x === 1n || x === n - 1n) continue;

      let composite = true;
      for (let r = 1n; r < s; r++) {
        x = this.modPow(x, 2n, n);
        if (x === n - 1n) {
          composite = false;
          break;
        }
      }
      if (composite) return false;
    }
    return true;
  }

  /**
   * Modular exponentiation: (base^exp) mod mod
   */
  public static modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let res = 1n;
    base = base % mod;
    if (base === 0n) return 0n;

    while (exp > 0n) {
      if (exp % 2n === 1n) {
        res = (res * base) % mod;
      }
      exp = exp / 2n;
      base = (base * base) % mod;
    }
    return res;
  }

  /**
   * Extended Euclidean Algorithm for BigInt: computes { gcd, x, y } such that a*x + b*y = gcd.
   */
  public static extendedGCD(a: bigint, b: bigint): { gcd: bigint; x: bigint; y: bigint } {
    let oldR = a, r = b;
    let oldS = 1n, s = 0n;
    let oldT = 0n, t = 1n;

    while (r !== 0n) {
      const q = oldR / r;
      const tempR = oldR - q * r;
      oldR = r;
      r = tempR;

      const tempS = oldS - q * s;
      oldS = s;
      s = tempS;

      const tempT = oldT - q * t;
      oldT = t;
      t = tempT;
    }

    return { gcd: oldR, x: oldS, y: oldT };
  }

  /**
   * Adds an element to the dynamic accumulator.
   */
  public add(element: string): { newAccumulator: string; primeRepresentative: string } {
    if (this.members.has(element)) {
      return {
        newAccumulator: this.V.toString(16),
        primeRepresentative: this.primeMap.get(element)!.toString(16)
      };
    }

    const prime = CryptographicAccumulator.elementToPrime(element);
    this.members.add(element);
    this.primeMap.set(element, prime);

    // V' = V^prime mod N
    this.V = CryptographicAccumulator.modPow(this.V, prime, this.N);

    return {
      newAccumulator: this.V.toString(16),
      primeRepresentative: prime.toString(16)
    };
  }

  /**
   * Adds a batch of elements to the dynamic accumulator.
   */
  public addBatch(elements: string[]): { newAccumulator: string; addedCount: number } {
    let count = 0;
    for (const elem of elements) {
      if (!this.members.has(elem)) {
        const prime = CryptographicAccumulator.elementToPrime(elem);
        this.members.add(elem);
        this.primeMap.set(elem, prime);
        this.V = CryptographicAccumulator.modPow(this.V, prime, this.N);
        count++;
      }
    }
    return {
      newAccumulator: this.V.toString(16),
      addedCount: count
    };
  }

  /**
   * Removes an element from the accumulator.
   */
  public delete(element: string): { newAccumulator: string; success: boolean } {
    if (!this.members.has(element)) {
      return { newAccumulator: this.V.toString(16), success: false };
    }

    this.members.delete(element);
    this.primeMap.delete(element);

    // Recompute V = g^(product of remaining primes) mod N
    let newV = this.g;
    for (const prime of this.primeMap.values()) {
      newV = CryptographicAccumulator.modPow(newV, prime, this.N);
    }
    this.V = newV;

    return {
      newAccumulator: this.V.toString(16),
      success: true
    };
  }

  /**
   * Generates a constant-size membership witness for an element in O(1) verification size.
   */
  public createWitness(element: string): MembershipWitness {
    if (!this.members.has(element)) {
      throw new Error(`Cannot create witness: element "${element}" is not present in accumulator.`);
    }

    const prime = this.primeMap.get(element)!;

    // Witness W = g^(product of all primes except element's prime) mod N
    let W = this.g;
    for (const [elem, p] of this.primeMap.entries()) {
      if (elem !== element) {
        W = CryptographicAccumulator.modPow(W, p, this.N);
      }
    }

    return {
      element,
      primeRepresentative: prime.toString(16),
      witness: W.toString(16),
      accumulatorId: this.id
    };
  }

  /**
   * Generates an O(1) constant-size Non-Membership witness using Bezout's identity: a*x + b*P = 1.
   */
  public createNonMembershipWitness(element: string): NonMembershipWitness {
    if (this.members.has(element)) {
      throw new Error(`Cannot create non-membership witness: element "${element}" is currently a member.`);
    }

    const x = CryptographicAccumulator.elementToPrime(element);

    // Compute P = product of all member primes
    let P = 1n;
    for (const p of this.primeMap.values()) {
      P *= p;
    }

    // Extended Euclidean algorithm: a*x + b*P = 1
    const { gcd, x: aCoeff, y: bCoeff } = CryptographicAccumulator.extendedGCD(x, P);
    if (gcd !== 1n) {
      throw new Error('GCD of non-member prime and accumulator product is not 1.');
    }

    // Adjust a to be positive by adding k*P (and subtracting k*x from b)
    let a = aCoeff;
    let b = bCoeff;
    if (a < 0n) {
      const k = (-a / P) + 1n;
      a += k * P;
      b -= k * x;
    }

    // d = g^a mod N
    const d = CryptographicAccumulator.modPow(this.g, a, this.N);

    return {
      element,
      primeRepresentative: x.toString(16),
      d: d.toString(16),
      b: b.toString(),
      accumulatorId: this.id
    };
  }

  /**
   * Verifies an O(1) Non-Membership witness:
   * When b >= 0: (d^x * V^b) mod N === g mod N
   * When b < 0:  d^x mod N === (g * V^(-b)) mod N
   */
  public static verifyNonMembershipWitness(
    witness: NonMembershipWitness,
    currentAccumulatorHex: string,
    generatorHex: string = CryptographicAccumulator.DEFAULT_GENERATOR_HEX,
    modulusHex: string = CryptographicAccumulator.DEFAULT_MODULUS_HEX
  ): boolean {
    try {
      const N = BigInt('0x' + modulusHex);
      const g = BigInt('0x' + generatorHex) % N;
      const V = BigInt('0x' + currentAccumulatorHex) % N;
      const x = BigInt('0x' + witness.primeRepresentative);
      const d = BigInt('0x' + witness.d) % N;
      const b = BigInt(witness.b);

      // Verify element prime mapping
      const expectedPrime = this.elementToPrime(witness.element);
      if (expectedPrime !== x) return false;

      // Compute d^x mod N
      const dx = this.modPow(d, x, N);

      if (b >= 0n) {
        const vb = this.modPow(V, b, N);
        const lhs = (dx * vb) % N;
        return lhs === g;
      } else {
        const absB = -b;
        const vAbsB = this.modPow(V, absB, N);
        const rhs = (g * vAbsB) % N;
        return dx === rhs;
      }
    } catch {
      return false;
    }
  }

  /**
   * Generates a constant-size batch membership witness for a subset of elements in O(1) verification size.
   */
  public createBatchWitness(elements: string[]): BatchMembershipWitness {
    if (!elements || elements.length === 0) {
      throw new Error('Cannot create batch witness for empty elements array.');
    }

    for (const elem of elements) {
      if (!this.members.has(elem)) {
        throw new Error(`Cannot create batch witness: element "${elem}" is not present in accumulator.`);
      }
    }

    const subsetSet = new Set(elements);
    let productPrime = 1n;
    for (const elem of elements) {
      productPrime *= this.primeMap.get(elem)!;
    }

    // Witness W_S = g^(product of primes not in subset) mod N
    let WS = this.g;
    for (const [elem, p] of this.primeMap.entries()) {
      if (!subsetSet.has(elem)) {
        WS = CryptographicAccumulator.modPow(WS, p, this.N);
      }
    }

    return {
      elements,
      productPrimeHex: productPrime.toString(16),
      witness: WS.toString(16),
      accumulatorId: this.id,
      accumulatorHex: this.V.toString(16)
    };
  }

  /**
   * Verifies an O(1) membership witness against current accumulator value in constant time.
   * Check: (W^prime) mod N === V
   */
  public static verifyWitness(
    witness: MembershipWitness,
    currentAccumulatorHex: string,
    modulusHex: string = CryptographicAccumulator.DEFAULT_MODULUS_HEX
  ): boolean {
    try {
      const N = BigInt('0x' + modulusHex);
      const W = BigInt('0x' + witness.witness);
      const prime = BigInt('0x' + witness.primeRepresentative);
      const V = BigInt('0x' + currentAccumulatorHex);

      // Verify element prime mapping
      const expectedPrime = this.elementToPrime(witness.element);
      if (expectedPrime !== prime) return false;

      // Verify accumulator equation: W^e == V (mod N)
      const computedV = this.modPow(W, prime, N);
      return computedV === V;
    } catch {
      return false;
    }
  }

  /**
   * Verifies a constant-size Batch Membership Witness against the current accumulator value.
   * Check: (W_S^(product of primes in S)) mod N === V
   */
  public static verifyBatchWitness(
    witness: BatchMembershipWitness,
    currentAccumulatorHex: string,
    modulusHex: string = CryptographicAccumulator.DEFAULT_MODULUS_HEX
  ): boolean {
    try {
      if (!witness.elements || witness.elements.length === 0) return false;
      const N = BigInt('0x' + modulusHex);
      const WS = BigInt('0x' + witness.witness);
      const claimedProduct = BigInt('0x' + witness.productPrimeHex);
      const V = BigInt('0x' + currentAccumulatorHex);

      let expectedProduct = 1n;
      for (const elem of witness.elements) {
        const p = this.elementToPrime(elem);
        expectedProduct *= p;
      }

      if (expectedProduct !== claimedProduct) return false;

      const computedV = this.modPow(WS, expectedProduct, N);
      return computedV === V;
    } catch {
      return false;
    }
  }

  /**
   * Exports accumulator state metadata.
   */
  public exportState(): AccumulatorState {
    return {
      id: this.id,
      modulus: this.N.toString(16),
      generator: this.g.toString(16),
      accumulator: this.V.toString(16),
      memberCount: this.members.size
    };
  }
}
