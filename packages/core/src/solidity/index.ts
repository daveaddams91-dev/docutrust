/**
 * @file packages/core/src/solidity/index.ts
 * @description EVM Smart Contract Verifier Generator & On-Chain ABI Calldata Engine
 * Generates production Solidity contracts (DocuTrustVerifier.sol & DocuTrustRegistry.sol)
 * and formats EVM ABI calldata for Ethereum, Polygon, Arbitrum, Base, and Optimism.
 */

import { VerifierGenerator } from './generators/VerifierGenerator.js';
import { RegistryGenerator } from './generators/RegistryGenerator.js';
import { SMTVerifierGenerator } from './generators/SMTVerifierGenerator.js';
import { BridgeRelayerGenerator } from './generators/BridgeRelayerGenerator.js';
import { Groth16VerifierGenerator } from './generators/Groth16VerifierGenerator.js';
import { UniversalVerifierGenerator } from './generators/UniversalVerifierGenerator.js';
import { ZKStateMachineVerifierGenerator } from './generators/ZKStateMachineVerifierGenerator.js';
import { SolidityUtils } from './utils.js';

export interface SolidityContractOptions {
  solidityVersion?: string;
  contractName?: string;
  enableEIP712?: boolean;
  enableBitstringStatus?: boolean;
  ownerAddress?: string;
}

export interface EVMCalldataResult {
  methodSignature: string;
  functionSelector: string;
  calldataHex: string;
  abi: Array<Record<string, any>>;
}

export class SolidityEngine {
  public static generateVerifierContract(options: SolidityContractOptions = {}): string {
    return VerifierGenerator.generateVerifierContract(options);
  }

  public static generateRegistryContract(options: SolidityContractOptions = {}): string {
    return RegistryGenerator.generateRegistryContract(options);
  }

  public static generateSMTVerifierContract(options: SolidityContractOptions = {}): string {
    return SMTVerifierGenerator.generateSMTVerifierContract(options);
  }

  public static generateBridgeRelayerContract(options: SolidityContractOptions = {}): string {
    return BridgeRelayerGenerator.generateBridgeRelayerContract(options);
  }

  public static generateGroth16VerifierContract(options: SolidityContractOptions = {}): string {
    return Groth16VerifierGenerator.generateGroth16VerifierContract(options);
  }

  public static generateUniversalVerifierContract(options: SolidityContractOptions = {}): string {
    return UniversalVerifierGenerator.generateUniversalVerifierContract(options);
  }

  public static generateZKStateMachineVerifierContract(options: SolidityContractOptions = {}): string {
    return ZKStateMachineVerifierGenerator.generateZKStateMachineVerifierContract(options);
  }

  public static encodeVerificationCalldata(
    credentialHashHex: string,
    merkleProof: Array<string | { data: string }>,
    rootHashHex: string
  ): EVMCalldataResult {
    return SolidityUtils.encodeVerificationCalldata(credentialHashHex, merkleProof, rootHashHex);
  }

  public static verifyMerkleProofEVM(
    leafHex: string,
    proofHexArray: string[],
    rootHex: string
  ): boolean {
    return SolidityUtils.verifyMerkleProofEVM(leafHex, proofHexArray, rootHex);
  }
}

export const generateVerifierContract = SolidityEngine.generateVerifierContract;
export const generateRegistryContract = SolidityEngine.generateRegistryContract;
export const generateSMTVerifierContract = SolidityEngine.generateSMTVerifierContract;
export const generateBridgeRelayerContract = SolidityEngine.generateBridgeRelayerContract;
export const generateGroth16VerifierContract = SolidityEngine.generateGroth16VerifierContract;
export const generateUniversalVerifierContract = SolidityEngine.generateUniversalVerifierContract;
export const generateZKStateMachineVerifierContract = SolidityEngine.generateZKStateMachineVerifierContract;
export const encodeVerificationCalldata = SolidityEngine.encodeVerificationCalldata;
export const verifyMerkleProofEVM = SolidityEngine.verifyMerkleProofEVM;
