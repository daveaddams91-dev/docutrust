/**
 * @file packages/core/src/solidity/index.ts
 * @description EVM Smart Contract Verifier Generator & On-Chain ABI Calldata Engine
 * Generates production Solidity contracts (DocuTrustVerifier.sol & DocuTrustRegistry.sol)
 * and formats EVM ABI calldata for Ethereum, Polygon, Arbitrum, Base, and Optimism.
 */

import * as crypto from 'crypto';
import { sha256Hex } from '../crypto/index.js';

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
  /**
   * Generates production-ready Solidity contract code for verifying DocuTrust credentials on-chain.
   */
  public static generateVerifierContract(options: SolidityContractOptions = {}): string {
    const version = options.solidityVersion || '^0.8.20';
    const name = options.contractName || 'DocuTrustVerifier';

    return `// SPDX-License-Identifier: Apache-2.0
pragma solidity ${version};

/**
 * @title ${name}
 * @author DocuTrust Sovereign Trust Engine v9.0.0
 * @notice Verifies W3C Verifiable Credentials, Merkle Inclusion Proofs, and EIP-712 attestations on-chain.
 */
contract ${name} {
    // Events
    event CredentialVerified(bytes32 indexed rootHash, bytes32 indexed credentialHash, address indexed verifier, uint256 timestamp);
    event RootAnchored(bytes32 indexed rootHash, uint256 indexed batchSize, address indexed authority, uint256 timestamp);
    event StatusUpdated(bytes32 indexed statusListRoot, uint256 indexed index, uint8 status);

    // Storage for accredited roots and authorities
    mapping(bytes32 => bool) public anchoredRoots;
    mapping(bytes32 => uint256) public rootTimestamps;
    mapping(address => bool) public authorizedIssuers;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "DocuTrust: caller is not the owner");
        _;
    }

    modifier onlyAuthorized() {
        require(authorizedIssuers[msg.sender] || msg.sender == owner, "DocuTrust: caller not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedIssuers[msg.sender] = true;
    }

    function setIssuerAuthorization(address issuer, bool authorized) external onlyOwner {
        authorizedIssuers[issuer] = authorized;
    }

    /**
     * @notice Anchors a batch Merkle Root to the ledger.
     */
    function anchorBatchRoot(bytes32 rootHash, uint256 batchSize) external onlyAuthorized {
        require(rootHash != bytes32(0), "DocuTrust: invalid root hash");
        anchoredRoots[rootHash] = true;
        rootTimestamps[rootHash] = block.timestamp;
        emit RootAnchored(rootHash, batchSize, msg.sender, block.timestamp);
    }

    /**
     * @notice Verifies a Merkle inclusion proof for a credential leaf hash against an anchored root.
     */
    function verifyMerkleProof(
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32 root
    ) public pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                // Hash(current, element)
                computedHash = sha256(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(element, current)
                computedHash = sha256(abi.encodePacked(proofElement, computedHash));
            }
        }

        return computedHash == root;
    }

    /**
     * @notice Complete on-chain verification of a credential against an anchored Merkle root.
     */
    function verifyCredentialOnChain(
        bytes32 credentialHash,
        bytes32[] calldata merkleProof,
        bytes32 rootHash
    ) external returns (bool) {
        require(anchoredRoots[rootHash], "DocuTrust: root not anchored on-chain");
        bool valid = verifyMerkleProof(credentialHash, merkleProof, rootHash);
        require(valid, "DocuTrust: cryptographic Merkle proof invalid");

        emit CredentialVerified(rootHash, credentialHash, msg.sender, block.timestamp);
        return true;
    }

    /**
     * @notice Verifies an EIP-712 secp256k1 credential signature on-chain using ecrecover.
     */
    function verifyEIP712Attestation(
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s,
        address expectedSigner
    ) public pure returns (bool) {
        address recovered = ecrecover(digest, v, r, s);
        return recovered != address(0) && recovered == expectedSigner;
    }
}
`;
  }

  /**
   * Generates a multi-issuer Sovereign Trust Registry smart contract for on-chain accreditation,
   * credential revocation status roots, and dynamic trust anchor tracking.
   */
  public static generateRegistryContract(options: SolidityContractOptions = {}): string {
    const version = options.solidityVersion || '^0.8.20';
    const name = options.contractName || 'DocuTrustRegistry';

    return `// SPDX-License-Identifier: Apache-2.0
pragma solidity ${version};

/**
 * @title ${name}
 * @author DocuTrust Sovereign Trust Engine v9.0.0
 * @notice Manages accredited issuer registries, revocation status roots, and multi-schema accreditation policies.
 */
contract ${name} {
    struct IssuerInfo {
        bool accredited;
        uint8 accreditationLevel; // 1 = Standard, 2 = Enhanced, 3 = Sovereign Root
        string didUri;
        uint256 registeredAt;
        uint256 expiresAt;
    }

    event IssuerRegistered(address indexed issuerAddress, string didUri, uint8 level, uint256 expiresAt);
    event IssuerRevoked(address indexed issuerAddress, string reason);
    event RevocationRootUpdated(address indexed issuerAddress, bytes32 indexed rootHash, uint256 indexed version);

    address public owner;
    mapping(address => IssuerInfo) public issuers;
    mapping(address => bytes32) public issuerRevocationRoots;
    mapping(address => uint256) public issuerRevocationVersions;

    modifier onlyOwner() {
        require(msg.sender == owner, "DocuTrust: caller is not owner");
        _;
    }

    modifier onlyAccredited() {
        require(issuers[msg.sender].accredited, "DocuTrust: caller is not accredited");
        require(issuers[msg.sender].expiresAt == 0 || block.timestamp <= issuers[msg.sender].expiresAt, "DocuTrust: accreditation expired");
        _;
    }

    constructor() {
        owner = msg.sender;
        issuers[msg.sender] = IssuerInfo({
            accredited: true,
            accreditationLevel: 3,
            didUri: "did:key:docutrust-root",
            registeredAt: block.timestamp,
            expiresAt: 0
        });
    }

    function registerIssuer(
        address issuerAddress,
        string calldata didUri,
        uint8 level,
        uint256 validDurationSeconds
    ) external onlyOwner {
        require(issuerAddress != address(0), "DocuTrust: invalid issuer address");
        uint256 expiresAt = validDurationSeconds > 0 ? block.timestamp + validDurationSeconds : 0;

        issuers[issuerAddress] = IssuerInfo({
            accredited: true,
            accreditationLevel: level,
            didUri: didUri,
            registeredAt: block.timestamp,
            expiresAt: expiresAt
        });

        emit IssuerRegistered(issuerAddress, didUri, level, expiresAt);
    }

    function revokeIssuer(address issuerAddress, string calldata reason) external onlyOwner {
        require(issuers[issuerAddress].accredited, "DocuTrust: issuer not accredited");
        issuers[issuerAddress].accredited = false;
        emit IssuerRevoked(issuerAddress, reason);
    }

    function updateRevocationRoot(bytes32 newRoot) external onlyAccredited {
        require(newRoot != bytes32(0), "DocuTrust: invalid revocation root");
        issuerRevocationRoots[msg.sender] = newRoot;
        issuerRevocationVersions[msg.sender] += 1;
        emit RevocationRootUpdated(msg.sender, newRoot, issuerRevocationVersions[msg.sender]);
    }

    function isIssuerAccredited(address issuerAddress) external view returns (bool) {
        IssuerInfo memory info = issuers[issuerAddress];
        if (!info.accredited) return false;
        if (info.expiresAt > 0 && block.timestamp > info.expiresAt) return false;
        return true;
    }
}
`;
  }

  /**
   * Generates production-ready Solidity contract for 256-bit Sparse Merkle Tree (SMT) verification.
   */
  public static generateSMTVerifierContract(options: SolidityContractOptions = {}): string {
    const version = options.solidityVersion || '^0.8.24';
    const name = options.contractName || 'DocuTrustSMTVerifier';

    return `// SPDX-License-Identifier: Apache-2.0
pragma solidity ${version};

/**
 * @title ${name}
 * @author DocuTrust Sovereign Trust Engine v10.0.0
 * @notice Verifies 256-bit Sparse Merkle Tree (SMT) inclusion & non-membership proofs on-chain.
 */
contract ${name} {
    struct Sibling {
        uint8 depth;
        bytes32 siblingHash;
        bool isRight;
    }

    event SMTProofVerified(bytes32 indexed root, bytes32 indexed key, bytes32 valueHash, bool exists, address verifier);

    /**
     * @notice Computes leaf hash for key-value pair in SMT.
     */
    function computeLeafHash(bytes32 key, bytes32 value) public pure returns (bytes32) {
        return sha256(abi.encodePacked("SMT_LEAF:", key, ":", value));
    }

    /**
     * @notice Verifies a Sparse Merkle Tree audit proof against an anchored root.
     */
    function verifySMTProof(
        bytes32 root,
        bytes32 key,
        bytes32 value,
        bool exists,
        Sibling[] calldata siblings
    ) public returns (bool) {
        bytes32 current = exists ? computeLeafHash(key, value) : bytes32(0);

        for (uint256 i = 0; i < siblings.length; i++) {
            Sibling memory s = siblings[i];
            if (s.isRight) {
                current = sha256(abi.encodePacked(current, ":", s.siblingHash));
            } else {
                current = sha256(abi.encodePacked(s.siblingHash, ":", current));
            }
        }

        bool valid = (current == root);
        if (valid) {
            emit SMTProofVerified(root, key, value, exists, msg.sender);
        }
        return valid;
    }
}
`;
  }

  /**
   * Encodes ABI calldata for calling verifyCredentialOnChain.
   */
  public static encodeVerificationCalldata(
    credentialHashHex: string,
    merkleProof: Array<string | { data: string }>,
    rootHashHex: string
  ): EVMCalldataResult {
    const methodSignature = 'verifyCredentialOnChain(bytes32,bytes32[],bytes32)';
    const functionSelector = crypto.createHash('sha3-256')
      .update(methodSignature)
      .digest('hex')
      .substring(0, 8); // 4 bytes selector

    const merkleProofHexArray = (merkleProof || []).map(p => typeof p === 'string' ? p : p.data);

    // Format parameters
    const cleanHash = credentialHashHex.replace('0x', '').padStart(64, '0');
    const cleanRoot = rootHashHex.replace('0x', '').padStart(64, '0');

    // ABI encoding: head (offset to proof array) + credentialHash + rootHash + length of proof + proof items
    const offsetProof = (3 * 32).toString(16).padStart(64, '0'); // offset = 0x60
    const proofLen = merkleProofHexArray.length.toString(16).padStart(64, '0');
    const proofEncoded = merkleProofHexArray.map(p => p.replace('0x', '').padStart(64, '0')).join('');

    const calldataHex = `0x${functionSelector}${cleanHash}${offsetProof}${cleanRoot}${proofLen}${proofEncoded}`;

    const abi = [
      {
        name: 'verifyCredentialOnChain',
        type: 'function',
        inputs: [
          { name: 'credentialHash', type: 'bytes32' },
          { name: 'merkleProof', type: 'bytes32[]' },
          { name: 'rootHash', type: 'bytes32' }
        ],
        outputs: [{ name: '', type: 'bool' }]
      }
    ];

    return {
      methodSignature,
      functionSelector: `0x${functionSelector}`,
      calldataHex,
      abi
    };
  }

  /**
   * Verifies a Merkle proof in JavaScript using EVM sha256 packed semantics.
   */
  public static verifyMerkleProofEVM(
    leafHex: string,
    proofHexArray: string[],
    rootHex: string
  ): boolean {
    let current = Buffer.from(leafHex.replace('0x', ''), 'hex');

    for (const p of proofHexArray) {
      const elem = Buffer.from(p.replace('0x', ''), 'hex');
      const comp = Buffer.compare(current, elem);
      const combined = comp <= 0 ? Buffer.concat([current, elem]) : Buffer.concat([elem, current]);
      current = crypto.createHash('sha256').update(combined).digest();
    }

    return current.toString('hex') === rootHex.replace('0x', '');
  }
}

export const generateVerifierContract = SolidityEngine.generateVerifierContract;
export const generateRegistryContract = SolidityEngine.generateRegistryContract;
export const generateSMTVerifierContract = SolidityEngine.generateSMTVerifierContract;
export const encodeVerificationCalldata = SolidityEngine.encodeVerificationCalldata;
export const verifyMerkleProofEVM = SolidityEngine.verifyMerkleProofEVM;


