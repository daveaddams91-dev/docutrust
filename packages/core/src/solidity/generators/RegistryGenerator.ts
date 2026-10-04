import { SolidityContractOptions } from '../index.js';

export class RegistryGenerator {
  public static generateRegistryContract(options: SolidityContractOptions = {}): string {
    const version = options.solidityVersion || '^0.8.20';
    const name = options.contractName || 'DocuTrustRegistry';

    return `// SPDX-License-Identifier: Apache-2.0
pragma solidity ${version};

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

}
