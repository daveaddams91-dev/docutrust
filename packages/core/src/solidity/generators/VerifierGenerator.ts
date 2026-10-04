import { SolidityContractOptions } from '../index.js';

export class VerifierGenerator {
  public static generateVerifierContract(options: SolidityContractOptions = {}): string {
    const version = options.solidityVersion || '^0.8.20';
    const name = options.contractName || 'DocuTrustVerifier';

    return `// SPDX-License-Identifier: Apache-2.0
pragma solidity ${version};

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

    function anchorBatchRoot(bytes32 rootHash, uint256 batchSize) external onlyAuthorized {
        require(rootHash != bytes32(0), "DocuTrust: invalid root hash");
        anchoredRoots[rootHash] = true;
        rootTimestamps[rootHash] = block.timestamp;
        emit RootAnchored(rootHash, batchSize, msg.sender, block.timestamp);
    }

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

}
