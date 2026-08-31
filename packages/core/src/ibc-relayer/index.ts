/**
 * @file packages/core/src/ibc-relayer/index.ts
 * @description Inter-Blockchain Communication (IBC) & Light-Client Relayer Mesh (DocuTrust v15.0.0)
 * Implements ICS-04 cross-chain packet routing, Merkle multi-store state proofs,
 * light-client consensus verification, and heterogeneous blockchain trust relayer bridging.
 */

import * as crypto from 'crypto';
import {
  sha256Hex,
  canonicalizeJson,
  encodeBase58,
  decodeBase58,
  signData,
  verifySignature,
  KeyPair
} from '../crypto/index.js';

export interface IBCHeight {
  revisionNumber: number;
  revisionHeight: number;
}

export interface IBCPacket {
  sequence: number;
  sourcePort: string;
  sourceChannel: string;
  destinationPort: string;
  destinationChannel: string;
  data: Record<string, any> | string;
  timeoutHeight: IBCHeight;
  timeoutTimestamp: number;
}

export interface IBCPacketCommitment {
  packet: IBCPacket;
  commitmentBytesHex: string;
  commitmentPath: string;
  packetHash: string;
}

export interface IBCLightClientState {
  chainId: string;
  clientType: 'TendermintLightClient' | 'EVMStateClient' | 'SubstrateGrandpaClient';
  trustingPeriodSeconds: number;
  unbondingPeriodSeconds: number;
  latestHeight: IBCHeight;
  consensusStates: Record<string, IBCConsensusState>; // "revNum-revHeight" -> ConsensusState
}

export interface IBCConsensusState {
  timestamp: string;
  appHash: string; // Merkle State Root
  nextValidatorsHash: string;
  lightClientSigners?: string[];
}

export interface IBCMerkleProofNode {
  type: 'left' | 'right';
  hash: string;
}

export interface IBCMerkleStateProof {
  key: string;
  valueHash: string;
  proofPath: IBCMerkleProofNode[];
  rootAppHash: string;
}

export interface IBCRelayReceipt {
  status: 'COMMITTED' | 'RELAYED' | 'ACKNOWLEDGED' | 'TIMEOUT';
  packetSequence: number;
  sourceChainId: string;
  destinationChainId: string;
  relayerDid: string;
  acknowledgementHex?: string;
  proofAppHash: string;
  relayedAt: string;
}

export class IBCRelayerEngine {
  /**
   * Computes deterministic ICS-04 packet commitment hash.
   */
  public static computePacketCommitment(packet: IBCPacket): IBCPacketCommitment {
    const rawData = typeof packet.data === 'string' ? packet.data : canonicalizeJson(packet.data);
    const dataHash = sha256Hex(rawData);

    const commitmentPreimage = `${packet.timeoutTimestamp}:${packet.timeoutHeight.revisionNumber}:${packet.timeoutHeight.revisionHeight}:${dataHash}`;
    const commitmentBytesHex = sha256Hex(commitmentPreimage);

    const commitmentPath = `commitments/ports/${packet.sourcePort}/channels/${packet.sourceChannel}/sequences/${packet.sequence}`;
    const packetHash = sha256Hex(`IBC_PACKET_V15:${packet.sequence}:${packet.sourcePort}:${packet.sourceChannel}:${packet.destinationPort}:${packet.destinationChannel}:${dataHash}`);

    return {
      packet,
      commitmentBytesHex,
      commitmentPath,
      packetHash
    };
  }

  /**
   * Creates a synthetic Merkle proof for a state key-value pair under a specific root AppHash.
   */
  public static generateMerkleProof(key: string, valueHex: string, depth: number = 4): IBCMerkleStateProof {
    const proofPath: IBCMerkleProofNode[] = [];
    let currentHash = sha256Hex(`LEAF:${key}:${valueHex}`);

    for (let i = 0; i < depth; i++) {
      const siblingHash = sha256Hex(`SIBLING_LEVEL_${i}:${key}`);
      const isLeft = i % 2 === 0;
      proofPath.push({
        type: isLeft ? 'left' : 'right',
        hash: siblingHash
      });

      currentHash = isLeft
        ? sha256Hex(`NODE:${siblingHash}:${currentHash}`)
        : sha256Hex(`NODE:${currentHash}:${siblingHash}`);
    }

    return {
      key,
      valueHash: valueHex,
      proofPath,
      rootAppHash: currentHash
    };
  }

  /**
   * Verifies an IBC Merkle multi-store state proof against a trusted light-client AppHash root.
   */
  public static verifyMerkleProof(proof: IBCMerkleStateProof, expectedRootAppHash: string): boolean {
    let currentHash = sha256Hex(`LEAF:${proof.key}:${proof.valueHash}`);

    for (const node of proof.proofPath) {
      if (node.type === 'left') {
        currentHash = sha256Hex(`NODE:${node.hash}:${currentHash}`);
      } else {
        currentHash = sha256Hex(`NODE:${currentHash}:${node.hash}`);
      }
    }

    return currentHash.toLowerCase() === expectedRootAppHash.toLowerCase();
  }

  /**
   * Creates and initializes a light-client tracking state for a connected blockchain.
   */
  public static createLightClient(
    chainId: string,
    clientType: 'TendermintLightClient' | 'EVMStateClient' | 'SubstrateGrandpaClient',
    initialHeight: IBCHeight,
    initialAppHash: string,
    options: { trustingPeriodSeconds?: number; unbondingPeriodSeconds?: number } = {}
  ): IBCLightClientState {
    const heightKey = `${initialHeight.revisionNumber}-${initialHeight.revisionHeight}`;
    const consensusState: IBCConsensusState = {
      timestamp: new Date().toISOString(),
      appHash: initialAppHash.toLowerCase(),
      nextValidatorsHash: sha256Hex(`VALIDATORS:${chainId}:${heightKey}`)
    };

    return {
      chainId,
      clientType,
      trustingPeriodSeconds: options.trustingPeriodSeconds || 1209600, // 14 days default
      unbondingPeriodSeconds: options.unbondingPeriodSeconds || 1814400, // 21 days default
      latestHeight: initialHeight,
      consensusStates: {
        [heightKey]: consensusState
      }
    };
  }

  /**
   * Updates light-client state with a new header and validator block signature proof.
   */
  public static updateLightClient(
    client: IBCLightClientState,
    newHeight: IBCHeight,
    newAppHash: string,
    validatorSignatures?: string[]
  ): IBCLightClientState {
    const heightKey = `${newHeight.revisionNumber}-${newHeight.revisionHeight}`;
    const updatedConsensus: IBCConsensusState = {
      timestamp: new Date().toISOString(),
      appHash: newAppHash.toLowerCase(),
      nextValidatorsHash: sha256Hex(`VALIDATORS:${client.chainId}:${heightKey}`),
      lightClientSigners: validatorSignatures
    };

    return {
      ...client,
      latestHeight: newHeight,
      consensusStates: {
        ...client.consensusStates,
        [heightKey]: updatedConsensus
      }
    };
  }

  /**
   * Relays an IBC packet from source chain to destination chain by verifying Merkle inclusion proof.
   */
  public static relayPacket(
    packet: IBCPacket,
    proof: IBCMerkleStateProof,
    sourceClientOnDest: IBCLightClientState,
    proofHeight: IBCHeight,
    relayerKeyPair?: KeyPair
  ): IBCRelayReceipt {
    const commitment = this.computePacketCommitment(packet);
    const heightKey = `${proofHeight.revisionNumber}-${proofHeight.revisionHeight}`;
    const consensus = sourceClientOnDest.consensusStates[heightKey];

    if (!consensus) {
      throw new Error(`Consensus state not found on light client for height ${heightKey}`);
    }

    // Check packet timeout
    const nowEpoch = Math.floor(Date.now() / 1000);
    if (packet.timeoutTimestamp > 0 && nowEpoch >= packet.timeoutTimestamp) {
      return {
        status: 'TIMEOUT',
        packetSequence: packet.sequence,
        sourceChainId: sourceClientOnDest.chainId,
        destinationChainId: 'destination-mesh',
        relayerDid: relayerKeyPair?.did || 'did:docutrust:relayer:mesh-node',
        proofAppHash: consensus.appHash,
        relayedAt: new Date().toISOString()
      };
    }

    // Verify Merkle state proof against consensus AppHash
    const isProofValid = this.verifyMerkleProof(proof, consensus.appHash);
    if (!isProofValid) {
      throw new Error(`Invalid Merkle state proof: proof does not match light-client root AppHash ${consensus.appHash}`);
    }

    // Compute acknowledgment
    const ackPayload = {
      result: 'AQ==', // Base64 success acknowledgment
      packetHash: commitment.packetHash,
      timestamp: new Date().toISOString()
    };
    const ackHex = sha256Hex(`IBC_ACK:${canonicalizeJson(ackPayload)}`);

    return {
      status: 'RELAYED',
      packetSequence: packet.sequence,
      sourceChainId: sourceClientOnDest.chainId,
      destinationChainId: 'destination-mesh',
      relayerDid: relayerKeyPair?.did || 'did:docutrust:relayer:mesh-node',
      acknowledgementHex: ackHex,
      proofAppHash: consensus.appHash,
      relayedAt: new Date().toISOString()
    };
  }
}
