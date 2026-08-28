import { sha256Hex, sha256Buffer } from '../crypto';

export interface MerkleProofStep {
  position: 'left' | 'right';
  data: string; // Hex hash
}

export interface MerkleInclusionProof {
  leafHash: string;
  leafIndex: number;
  rootHash: string;
  totalLeaves: number;
  auditPath: MerkleProofStep[];
}

/**
 * Merkle Tree with RFC 6962 / Certificate Transparency style Domain Separation:
 * Leaf hash: SHA-256(0x00 || leafData)
 * Node hash: SHA-256(0x01 || leftNode || rightNode)
 * This prevents second-preimage collision attacks between leaves and internal nodes.
 */
export class MerkleTree {
  private leaves: string[];
  private layers: string[][];

  constructor(leaves: (string | Buffer)[]) {
    if (!leaves || leaves.length === 0) {
      throw new Error('Cannot construct Merkle tree with 0 leaves');
    }

    // Domain separation for leaves: 0x00
    this.leaves = leaves.map(leaf => {
      const buf = typeof leaf === 'string' ? Buffer.from(leaf, 'utf-8') : leaf;
      const leafPayload = Buffer.concat([Buffer.from([0x00]), buf]);
      return sha256Hex(leafPayload);
    });

    this.layers = [this.leaves];
    this.buildTree();
  }

  private hashPair(leftHex: string, rightHex: string): string {
    const leftBuf = Buffer.from(leftHex, 'hex');
    const rightBuf = Buffer.from(rightHex, 'hex');
    // Domain separation for interior nodes: 0x01
    const nodePayload = Buffer.concat([Buffer.from([0x01]), leftBuf, rightBuf]);
    return sha256Hex(nodePayload);
  }

  private buildTree(): void {
    let currentLayer = this.leaves;

    while (currentLayer.length > 1) {
      const nextLayer: string[] = [];

      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        if (i + 1 < currentLayer.length) {
          const right = currentLayer[i + 1];
          nextLayer.push(this.hashPair(left, right));
        } else {
          // If odd number of nodes, duplicate the last node
          nextLayer.push(this.hashPair(left, left));
        }
      }

      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }
  }

  public getRoot(): string {
    return this.layers[this.layers.length - 1][0];
  }

  public getLeaves(): string[] {
    return [...this.leaves];
  }

  public getProof(leafIndex: number): MerkleInclusionProof {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`Leaf index ${leafIndex} out of bounds (0..${this.leaves.length - 1})`);
    }

    const auditPath: MerkleProofStep[] = [];
    let idx = leafIndex;

    for (let layerIdx = 0; layerIdx < this.layers.length - 1; layerIdx++) {
      const layer = this.layers[layerIdx];
      const isRightChild = idx % 2 === 1;
      const pairIdx = isRightChild ? idx - 1 : idx + 1;

      if (pairIdx < layer.length) {
        auditPath.push({
          position: isRightChild ? 'left' : 'right',
          data: layer[pairIdx]
        });
      } else {
        // Duplicated odd node
        auditPath.push({
          position: 'right',
          data: layer[idx]
        });
      }

      idx = Math.floor(idx / 2);
    }

    return {
      leafHash: this.leaves[leafIndex],
      leafIndex,
      rootHash: this.getRoot(),
      totalLeaves: this.leaves.length,
      auditPath
    };
  }

  /**
   * Verify an inclusion proof against an expected Merkle root.
   */
  public static verifyProof(
    rawLeafData: string | Buffer | null,
    proof: MerkleInclusionProof,
    expectedRoot?: string
  ): boolean {
    const root = expectedRoot || proof.rootHash;
    let currentHash: string;

    if (rawLeafData !== null) {
      const buf = typeof rawLeafData === 'string' ? Buffer.from(rawLeafData, 'utf-8') : rawLeafData;
      const leafPayload = Buffer.concat([Buffer.from([0x00]), buf]);
      const computedLeafHash = sha256Hex(leafPayload);
      if (computedLeafHash !== proof.leafHash) {
        return false;
      }
      currentHash = computedLeafHash;
    } else {
      currentHash = proof.leafHash;
    }

    for (const step of proof.auditPath) {
      const leftBuf = step.position === 'left' ? Buffer.from(step.data, 'hex') : Buffer.from(currentHash, 'hex');
      const rightBuf = step.position === 'left' ? Buffer.from(currentHash, 'hex') : Buffer.from(step.data, 'hex');
      const nodePayload = Buffer.concat([Buffer.from([0x01]), leftBuf, rightBuf]);
      currentHash = sha256Hex(nodePayload);
    }

    return currentHash.toLowerCase() === root.toLowerCase();
  }
}
