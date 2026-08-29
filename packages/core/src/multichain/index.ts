/**
 * @fileoverview Multi-Chain Ledger Anchor and Calldata Formatter.
 * Formats standardized transaction payloads and calldata for EVM (Ethereum, Polygon, Arbitrum, Base),
 * Solana Anchor programs, and Bitcoin OP_RETURN script hashes.
 * @module @docutrust/core/multichain
 */

import * as crypto from 'crypto';
import { sha256Hex } from '../crypto';

export type SupportedChain =
  | 'ethereum'
  | 'polygon'
  | 'arbitrum'
  | 'base'
  | 'optimism'
  | 'solana'
  | 'bitcoin';

export interface ChainConfig {
  chainId?: number;
  networkName: string;
  defaultContractAddress?: string;
  explorerTxBaseUrl: string;
}

export const CHAIN_CONFIGS: Record<SupportedChain, ChainConfig> = {
  ethereum: {
    chainId: 1,
    networkName: 'Ethereum Mainnet',
    defaultContractAddress: '0x8888888888888888888888888888888888888888',
    explorerTxBaseUrl: 'https://etherscan.io/tx/'
  },
  polygon: {
    chainId: 137,
    networkName: 'Polygon PoS',
    defaultContractAddress: '0x8888888888888888888888888888888888888888',
    explorerTxBaseUrl: 'https://polygonscan.com/tx/'
  },
  arbitrum: {
    chainId: 42161,
    networkName: 'Arbitrum One',
    defaultContractAddress: '0x8888888888888888888888888888888888888888',
    explorerTxBaseUrl: 'https://arbiscan.io/tx/'
  },
  base: {
    chainId: 8453,
    networkName: 'Base Mainnet',
    defaultContractAddress: '0x8888888888888888888888888888888888888888',
    explorerTxBaseUrl: 'https://basescan.org/tx/'
  },
  optimism: {
    chainId: 10,
    networkName: 'Optimism Mainnet',
    defaultContractAddress: '0x8888888888888888888888888888888888888888',
    explorerTxBaseUrl: 'https://optimistic.etherscan.io/tx/'
  },
  solana: {
    networkName: 'Solana Mainnet-Beta',
    defaultContractAddress: 'DocuTrust1111111111111111111111111111111111',
    explorerTxBaseUrl: 'https://solscan.io/tx/'
  },
  bitcoin: {
    networkName: 'Bitcoin Mainnet',
    explorerTxBaseUrl: 'https://mempool.space/tx/'
  }
};

export interface MultiChainAnchorPayload {
  chain: SupportedChain;
  networkName: string;
  merkleRoot: string;
  batchCount: number;
  timestamp: string;
  memo: string;
  calldataHex?: string;
  opReturnHex?: string;
  instructionDataHex?: string;
  targetContract?: string;
  simulatedTxHash: string;
  explorerUrl: string;
}

export class MultiChainLedgerAnchor {
  /**
   * Generates EVM ABI-encoded calldata for function `anchorBatch(bytes32 root, uint256 count, string memo)`.
   * Function selector: 0x892a4b12
   */
  static formatEVMCalldata(merkleRoot: string, batchCount: number, memo: string = 'DocuTrust Anchor'): string {
    const cleanRoot = merkleRoot.replace(/^0x/, '').padStart(64, '0');
    // Function selector: keccak256("anchorBatch(bytes32,uint256,string)")[0..4] -> 0x892a4b12
    const selector = '892a4b12';

    // Param 1: bytes32 root
    const param1 = cleanRoot;

    // Param 2: uint256 count
    const countBuf = Buffer.alloc(32);
    countBuf.writeBigUInt64BE(BigInt(batchCount), 24);
    const param2 = countBuf.toString('hex');

    // Param 3: offset to string (0x60 = 96 bytes)
    const offsetBuf = Buffer.alloc(32);
    offsetBuf.writeBigUInt64BE(BigInt(96), 24);
    const param3 = offsetBuf.toString('hex');

    // String length
    const strBytes = Buffer.from(memo, 'utf-8');
    const strLenBuf = Buffer.alloc(32);
    strLenBuf.writeBigUInt64BE(BigInt(strBytes.length), 24);

    // String data padded to 32 bytes
    const padLen = Math.ceil(strBytes.length / 32) * 32 || 32;
    const strPadded = Buffer.alloc(padLen);
    strBytes.copy(strPadded);

    return '0x' + selector + param1 + param2 + param3 + strLenBuf.toString('hex') + strPadded.toString('hex');
  }

  /**
   * Generates Bitcoin OP_RETURN script payload (up to 80 bytes): 0x6a + len + "DOCU" + 32-byte Merkle root + 4-byte count.
   */
  static formatBitcoinOpReturn(merkleRoot: string, batchCount: number): string {
    const cleanRoot = merkleRoot.replace(/^0x/, '').padStart(64, '0');
    const rootBuf = Buffer.from(cleanRoot, 'hex');
    const prefix = Buffer.from('DOCU', 'ascii'); // 4 bytes

    const countBuf = Buffer.alloc(4);
    countBuf.writeUInt32BE(batchCount, 0);

    const payload = Buffer.concat([prefix, rootBuf, countBuf]); // 40 bytes
    // OP_RETURN opcode is 0x6a, followed by payload length 0x28 (40 bytes)
    return '0x6a28' + payload.toString('hex');
  }

  /**
   * Generates Solana Anchor instruction data payload (8-byte discriminator + 32-byte root + 8-byte count).
   */
  static formatSolanaInstruction(merkleRoot: string, batchCount: number): string {
    const cleanRoot = merkleRoot.replace(/^0x/, '').padStart(64, '0');
    const rootBuf = Buffer.from(cleanRoot, 'hex');
    // Discriminator: sha256("global:anchor_merkle_batch")[0..8]
    const disc = crypto.createHash('sha256').update('global:anchor_merkle_batch').digest().subarray(0, 8);

    const countBuf = Buffer.alloc(8);
    countBuf.writeBigUInt64LE(BigInt(batchCount), 0);

    const payload = Buffer.concat([disc, rootBuf, countBuf]);
    return '0x' + payload.toString('hex');
  }

  /**
   * Formats a complete multi-chain anchor payload for any supported blockchain.
   */
  static formatAnchor(
    chain: SupportedChain,
    merkleRoot: string,
    batchCount: number,
    memo: string = 'DocuTrust Merkle Batch Anchor'
  ): MultiChainAnchorPayload {
    const config = CHAIN_CONFIGS[chain] || CHAIN_CONFIGS.ethereum;
    const cleanRoot = merkleRoot.startsWith('0x') ? merkleRoot : '0x' + merkleRoot;
    const now = new Date().toISOString();
    const simTxHash = '0x' + sha256Hex(`${chain}:${cleanRoot}:${batchCount}:${now}`);

    const baseResult: MultiChainAnchorPayload = {
      chain,
      networkName: config.networkName,
      merkleRoot: cleanRoot,
      batchCount,
      timestamp: now,
      memo,
      targetContract: config.defaultContractAddress,
      simulatedTxHash: simTxHash,
      explorerUrl: `${config.explorerTxBaseUrl}${simTxHash}`
    };

    if (chain === 'bitcoin') {
      baseResult.opReturnHex = this.formatBitcoinOpReturn(cleanRoot, batchCount);
    } else if (chain === 'solana') {
      baseResult.instructionDataHex = this.formatSolanaInstruction(cleanRoot, batchCount);
    } else {
      // EVM chains
      baseResult.calldataHex = this.formatEVMCalldata(cleanRoot, batchCount, memo);
    }

    return baseResult;
  }
}
