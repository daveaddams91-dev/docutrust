import * as crypto from 'crypto';
import { sha256Hex } from '../crypto';

export interface MMRProof {
  elementIndex: number;
  elementHash: string;
  peakHashes: string[];
  siblings: string[];
  baggedPeakRoot: string;
  size: number;
}

export class MerkleMountainRange {
  private leaves: string[] = [];
  private nodes: string[] = [];

  constructor(initialLeaves: string[] = []) {
    initialLeaves.forEach(leaf => this.append(leaf));
  }

  public append(leaf: string | Buffer): { index: number; hash: string; peakRoot: string } {
    const leafBuf = typeof leaf === 'string' ? Buffer.from(leaf, 'utf-8') : leaf;
    const leafHash = sha256Hex(Buffer.concat([Buffer.from([0x00]), leafBuf]));

    const index = this.leaves.length;
    this.leaves.push(leafHash);
    this.nodes.push(leafHash);

    // Merge peaks as needed
    this.recalculatePeaks();

    return {
      index,
      hash: leafHash,
      peakRoot: this.getBaggedPeakRoot()
    };
  }

  private recalculatePeaks(): void {
    // Computes peaks
  }

  public getPeaks(): string[] {
    if (this.leaves.length === 0) return [];
    // Calculate binary decomposition peaks
    const peaks: string[] = [];
    let remaining = this.leaves.length;
    let offset = 0;

    while (remaining > 0) {
      const largestPower = 1 << Math.floor(Math.log2(remaining));
      const subLeaves = this.leaves.slice(offset, offset + largestPower);
      
      let layer = subLeaves;
      while (layer.length > 1) {
        const next: string[] = [];
        for (let i = 0; i < layer.length; i += 2) {
          next.push(sha256Hex(Buffer.concat([Buffer.from([0x01]), Buffer.from(layer[i], 'hex'), Buffer.from(layer[i + 1], 'hex')])));
        }
        layer = next;
      }
      peaks.push(layer[0]);
      offset += largestPower;
      remaining -= largestPower;
    }
    return peaks;
  }

  public getBaggedPeakRoot(): string {
    const peaks = this.getPeaks();
    if (peaks.length === 0) return '0x0000000000000000000000000000000000000000000000000000000000000000';
    if (peaks.length === 1) return peaks[0];

    // Bag peaks from right to left
    let root = peaks[peaks.length - 1];
    for (let i = peaks.length - 2; i >= 0; i--) {
      root = sha256Hex(Buffer.concat([Buffer.from([0x02]), Buffer.from(peaks[i], 'hex'), Buffer.from(root, 'hex')]));
    }
    return root;
  }

  public getProof(elementIndex: number): MMRProof {
    if (elementIndex < 0 || elementIndex >= this.leaves.length) {
      throw new Error(`Element index ${elementIndex} out of bounds (0..${this.leaves.length - 1})`);
    }

    const peaks = this.getPeaks();
    const elementHash = this.leaves[elementIndex];
    const baggedPeakRoot = this.getBaggedPeakRoot();

    // Find the sub-tree containing elementIndex and calculate sibling path
    const siblings: string[] = [];
    let remaining = this.leaves.length;
    let offset = 0;

    while (remaining > 0) {
      const largestPower = 1 << Math.floor(Math.log2(remaining));
      if (elementIndex >= offset && elementIndex < offset + largestPower) {
        // Element is in this sub-tree
        let localIdx = elementIndex - offset;
        let layer = this.leaves.slice(offset, offset + largestPower);

        while (layer.length > 1) {
          const isRight = (localIdx % 2 === 1);
          const sibIdx = isRight ? localIdx - 1 : localIdx + 1;
          const pos = isRight ? 'L' : 'R';
          siblings.push(`${pos}:${layer[sibIdx]}`);

          const nextLayer: string[] = [];
          for (let i = 0; i < layer.length; i += 2) {
            nextLayer.push(sha256Hex(Buffer.concat([Buffer.from([0x01]), Buffer.from(layer[i], 'hex'), Buffer.from(layer[i + 1], 'hex')])));
          }
          layer = nextLayer;
          localIdx = Math.floor(localIdx / 2);
        }
        break;
      }
      offset += largestPower;
      remaining -= largestPower;
    }

    return {
      elementIndex,
      elementHash,
      peakHashes: peaks,
      siblings,
      baggedPeakRoot,
      size: this.leaves.length
    };
  }

  public static verifyProof(proof: MMRProof): boolean {
    if (!proof.peakHashes || proof.peakHashes.length === 0) return false;

    // 1. If siblings are present, verify elementHash accumulates to one of the peakHashes
    if (proof.siblings && proof.siblings.length > 0) {
      let curr = proof.elementHash;
      for (const sib of proof.siblings) {
        const isLeft = sib.startsWith('L:');
        const sibHash = sib.replace(/^[LR]:/, '');
        const leftBuf = Buffer.from(isLeft ? sibHash : curr, 'hex');
        const rightBuf = Buffer.from(isLeft ? curr : sibHash, 'hex');
        curr = sha256Hex(Buffer.concat([Buffer.from([0x01]), leftBuf, rightBuf]));
      }
      if (!proof.peakHashes.includes(curr)) {
        return false;
      }
    } else if (proof.elementHash && proof.size === 1) {
      if (!proof.peakHashes.includes(proof.elementHash)) {
        return false;
      }
    }

    // 2. Check bagged peak root consistency
    let computedRoot = proof.peakHashes[proof.peakHashes.length - 1];
    for (let i = proof.peakHashes.length - 2; i >= 0; i--) {
      computedRoot = sha256Hex(Buffer.concat([Buffer.from([0x02]), Buffer.from(proof.peakHashes[i], 'hex'), Buffer.from(computedRoot, 'hex')]));
    }

    return computedRoot === proof.baggedPeakRoot;
  }

  public get size(): number {
    return this.leaves.length;
  }
}
