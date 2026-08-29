import * as crypto from 'crypto';
import { sha256Hex, canonicalizeJson } from '../crypto';

export interface AuditBlock {
  index: number;
  timestamp: number;
  merkleRoot: string;
  leafCount: number;
  previousBlockHash: string;
  blockHash: string;
  signerDid: string;
  signature: string;
}

export class TamperEvidentHashChain {
  private chain: AuditBlock[] = [];
  public static readonly GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

  constructor(initialBlocks: AuditBlock[] = []) {
    this.chain = initialBlocks.slice();
  }

  public getLatestBlock(): AuditBlock | null {
    return this.chain.length > 0 ? this.chain[this.chain.length - 1] : null;
  }

  public getChain(): AuditBlock[] {
    return this.chain.slice();
  }

  public appendBlock(
    merkleRoot: string,
    leafCount: number,
    signerDid: string,
    signerFunction: (hash: string) => string
  ): AuditBlock {
    const prevBlock = this.getLatestBlock();
    const index = prevBlock ? prevBlock.index + 1 : 0;
    const previousBlockHash = prevBlock ? prevBlock.blockHash : TamperEvidentHashChain.GENESIS_PREV_HASH;
    const timestamp = Date.now();

    const blockHeader = {
      index,
      timestamp,
      merkleRoot,
      leafCount,
      previousBlockHash,
      signerDid
    };

    const blockHash = sha256Hex(canonicalizeJson(blockHeader));
    const signature = signerFunction(blockHash);

    const block: AuditBlock = {
      ...blockHeader,
      blockHash,
      signature
    };

    this.chain.push(block);
    return block;
  }

  public verifyChainIntegrity(verifierFunction?: (data: string, sig: string, did: string) => boolean): {
    valid: boolean;
    brokenIndex?: number;
    error?: string;
  } {
    for (let i = 0; i < this.chain.length; i++) {
      const block = this.chain[i];

      // 1. Verify previous hash linkage
      const expectedPrevHash = i === 0 ? TamperEvidentHashChain.GENESIS_PREV_HASH : this.chain[i - 1].blockHash;
      if (block.previousBlockHash !== expectedPrevHash) {
        return { valid: false, brokenIndex: i, error: `Broken chain link at index ${i}: prevHash mismatch.` };
      }

      // 2. Verify block hash calculation
      const blockHeader = {
        index: block.index,
        timestamp: block.timestamp,
        merkleRoot: block.merkleRoot,
        leafCount: block.leafCount,
        previousBlockHash: block.previousBlockHash,
        signerDid: block.signerDid
      };
      const recomputedHash = sha256Hex(canonicalizeJson(blockHeader));
      if (recomputedHash !== block.blockHash) {
        return { valid: false, brokenIndex: i, error: `Tampered block data at index ${i}: hash mismatch.` };
      }

      // 3. Optional signature verification
      if (verifierFunction) {
        const isSigValid = verifierFunction(block.blockHash, block.signature, block.signerDid);
        if (!isSigValid) {
          return { valid: false, brokenIndex: i, error: `Invalid block signature at index ${i}.` };
        }
      }
    }

    return { valid: true };
  }
}
