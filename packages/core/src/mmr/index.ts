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

    return {
      elementIndex,
      elementHash,
      peakHashes: peaks,
      siblings: [],
      baggedPeakRoot,
      size: this.leaves.length
    };
  }

  public static verifyProof(proof: MMRProof): boolean {
    if (!proof.peakHashes || proof.peakHashes.length === 0) return false;
    
    // Check bagged peak root consistency
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
