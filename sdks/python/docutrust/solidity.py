from __future__ import annotations
import hashlib
from typing import Dict, Any, List, Optional, Union

class SolidityEngine:
    """EVM Smart Contract Verifier Generator & On-Chain ABI Calldata Engine for Python."""

    @staticmethod
    def generate_verifier_contract(
        contract_name: str = "DocuTrustVerifier",
        solidity_version: str = "^0.8.20",
        owner_address: Optional[str] = None
    ) -> str:
        """Generates production-ready Solidity contract code for verifying DocuTrust credentials on-chain."""
        return f"""// SPDX-License-Identifier: Apache-2.0
pragma solidity {solidity_version};

/**
 * @title {contract_name}
 * @author DocuTrust Sovereign Trust Engine v9.0.0
 * @notice Verifies W3C Verifiable Credentials, Merkle Inclusion Proofs, and EIP-712 attestations on-chain.
 */
contract {contract_name} {{
    // Events
    event CredentialVerified(bytes32 indexed rootHash, bytes32 indexed credentialHash, address indexed verifier, uint256 timestamp);
    event RootAnchored(bytes32 indexed rootHash, uint256 indexed batchSize, address indexed authority, uint256 timestamp);
    event StatusUpdated(bytes32 indexed statusListRoot, uint256 indexed index, uint8 status);

    // Storage for accredited roots and authorities
    mapping(bytes32 => bool) public anchoredRoots;
    mapping(bytes32 => uint256) public rootTimestamps;
    mapping(address => bool) public authorizedIssuers;
    address public owner;

    modifier onlyOwner() {{
        require(msg.sender == owner, "DocuTrust: caller is not the owner");
        _;
    }}

    modifier onlyAuthorized() {{
        require(authorizedIssuers[msg.sender] || msg.sender == owner, "DocuTrust: caller not authorized");
        _;
    }}

    constructor() {{
        owner = msg.sender;
        authorizedIssuers[msg.sender] = true;
    }}

    function setIssuerAuthorization(address issuer, bool authorized) external onlyOwner {{
        authorizedIssuers[issuer] = authorized;
    }}

    /**
     * @notice Anchors a batch Merkle Root to the ledger.
     */
    function anchorBatchRoot(bytes32 rootHash, uint256 batchSize) external onlyAuthorized {{
        require(rootHash != bytes32(0), "DocuTrust: invalid root hash");
        anchoredRoots[rootHash] = true;
        rootTimestamps[rootHash] = block.timestamp;
        emit RootAnchored(rootHash, batchSize, msg.sender, block.timestamp);
    }}

    /**
     * @notice Verifies a Merkle inclusion proof for a credential leaf hash against an anchored root.
     */
    function verifyMerkleProof(
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32 root
    ) public pure returns (bool) {{
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {{
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {{
                computedHash = sha256(abi.encodePacked(computedHash, proofElement));
            }} else {{
                computedHash = sha256(abi.encodePacked(proofElement, computedHash));
            }}
        }}

        return computedHash == root;
    }}

    /**
     * @notice Complete on-chain verification of a credential against an anchored Merkle root.
     */
    function verifyCredentialOnChain(
        bytes32 credentialHash,
        bytes32[] calldata merkleProof,
        bytes32 rootHash
    ) external returns (bool) {{
        require(anchoredRoots[rootHash], "DocuTrust: root not anchored on-chain");
        bool valid = verifyMerkleProof(credentialHash, merkleProof, rootHash);
        require(valid, "DocuTrust: cryptographic Merkle proof invalid");

        emit CredentialVerified(rootHash, credentialHash, msg.sender, block.timestamp);
        return true;
    }}

    /**
     * @notice Verifies an EIP-712 secp256k1 credential signature on-chain using ecrecover.
     */
    function verifyEIP712Attestation(
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s,
        address expectedSigner
    ) public pure returns (bool) {{
        address recovered = ecrecover(digest, v, r, s);
        return recovered != address(0) && recovered == expectedSigner;
    }}
}}
"""

    @staticmethod
    def generate_registry_contract(
        contract_name: str = "DocuTrustRegistry",
        solidity_version: str = "^0.8.20"
    ) -> str:
        """Generates a multi-issuer Sovereign Trust Registry smart contract for on-chain accreditation."""
        return f"""// SPDX-License-Identifier: Apache-2.0
pragma solidity {solidity_version};

/**
 * @title {contract_name}
 * @author DocuTrust Sovereign Trust Engine v9.0.0
 * @notice Manages accredited issuer registries, revocation status roots, and multi-schema accreditation policies.
 */
contract {contract_name} {{
    struct IssuerInfo {{
        bool accredited;
        uint8 accreditationLevel;
        string didUri;
        uint256 registeredAt;
        uint256 expiresAt;
    }}

    event IssuerRegistered(address indexed issuerAddress, string didUri, uint8 level, uint256 expiresAt);
    event IssuerRevoked(address indexed issuerAddress, string reason);
    event RevocationRootUpdated(address indexed issuerAddress, bytes32 indexed rootHash, uint256 indexed version);

    address public owner;
    mapping(address => IssuerInfo) public issuers;
    mapping(address => bytes32) public issuerRevocationRoots;
    mapping(address => uint256) public issuerRevocationVersions;

    modifier onlyOwner() {{
        require(msg.sender == owner, "DocuTrust: caller is not owner");
        _;
    }}

    modifier onlyAccredited() {{
        require(issuers[msg.sender].accredited, "DocuTrust: caller is not accredited");
        require(issuers[msg.sender].expiresAt == 0 || block.timestamp <= issuers[msg.sender].expiresAt, "DocuTrust: accreditation expired");
        _;
    }}

    constructor() {{
        owner = msg.sender;
        issuers[msg.sender] = IssuerInfo({{
            accredited: true,
            accreditationLevel: 3,
            didUri: "did:key:docutrust-root",
            registeredAt: block.timestamp,
            expiresAt: 0
        }});
    }}

    function registerIssuer(
        address issuerAddress,
        string calldata didUri,
        uint8 level,
        uint256 validDurationSeconds
    ) external onlyOwner {{
        require(issuerAddress != address(0), "DocuTrust: invalid issuer address");
        uint256 expiresAt = validDurationSeconds > 0 ? block.timestamp + validDurationSeconds : 0;

        issuers[issuerAddress] = IssuerInfo({{
            accredited: true,
            accreditationLevel: level,
            didUri: didUri,
            registeredAt: block.timestamp,
            expiresAt: expiresAt
        }});

        emit IssuerRegistered(issuerAddress, didUri, level, expiresAt);
    }}

    function revokeIssuer(address issuerAddress, string calldata reason) external onlyOwner {{
        require(issuers[issuerAddress].accredited, "DocuTrust: issuer not accredited");
        issuers[issuerAddress].accredited = false;
        emit IssuerRevoked(issuerAddress, reason);
    }}

    function updateRevocationRoot(bytes32 newRoot) external onlyAccredited {{
        require(newRoot != bytes32(0), "DocuTrust: invalid revocation root");
        issuerRevocationRoots[msg.sender] = newRoot;
        issuerRevocationVersions[msg.sender] += 1;
        emit RevocationRootUpdated(msg.sender, newRoot, issuerRevocationVersions[msg.sender]);
    }}

    function isIssuerAccredited(address issuerAddress) external view returns (bool) {{
        IssuerInfo memory info = issuers[issuerAddress];
        if (!info.accredited) return false;
        if (info.expiresAt > 0 && block.timestamp > info.expiresAt) return false;
        return true;
    }}
}}
"""

    @staticmethod
    def encode_verification_calldata(
        credential_hash_hex: str,
        merkle_proof: List[Union[str, Dict[str, Any]]],
        root_hash_hex: str
    ) -> Dict[str, Any]:
        """Encodes ABI calldata for calling verifyCredentialOnChain."""
        method_sig = "verifyCredentialOnChain(bytes32,bytes32[],bytes32)"
        # Keccak-256 (sha3-256 in Python or hashlib sha3_256)
        func_sel = hashlib.sha3_256(method_sig.encode('utf-8')).hexdigest()[:8]

        proof_hex_array = []
        for p in merkle_proof:
            if isinstance(p, str):
                proof_hex_array.append(p)
            elif isinstance(p, dict) and "data" in p:
                proof_hex_array.append(p["data"])

        clean_hash = credential_hash_hex.replace("0x", "").zfill(64)
        clean_root = root_hash_hex.replace("0x", "").zfill(64)

        offset_proof = hex(3 * 32)[2:].zfill(64) # 0x60
        proof_len = hex(len(proof_hex_array))[2:].zfill(64)
        proof_encoded = "".join(p.replace("0x", "").zfill(64) for p in proof_hex_array)

        calldata_hex = f"0x{func_sel}{clean_hash}{offset_proof}{clean_root}{proof_len}{proof_encoded}"

        abi = [
            {
                "name": "verifyCredentialOnChain",
                "type": "function",
                "inputs": [
                    {"name": "credentialHash", "type": "bytes32"},
                    {"name": "merkleProof", "type": "bytes32[]"},
                    {"name": "rootHash", "type": "bytes32"}
                ],
                "outputs": [{"name": "", "type": "bool"}]
            }
        ]

        return {
            "methodSignature": method_sig,
            "functionSelector": f"0x{func_sel}",
            "calldataHex": calldata_hex,
            "abi": abi
        }

    @staticmethod
    def verify_merkle_proof_evm(
        leaf_hex: str,
        proof_hex_array: List[str],
        root_hex: str
    ) -> bool:
        """Verifies a Merkle proof in Python using EVM sha256 packed semantics."""
        current = bytes.fromhex(leaf_hex.replace("0x", ""))

        for p in proof_hex_array:
            elem = bytes.fromhex(p.replace("0x", ""))
            combined = (current + elem) if current <= elem else (elem + current)
            current = hashlib.sha256(combined).digest()

        return current.hex().lower() == root_hex.replace("0x", "").lower()

    @staticmethod
    def generate_smt_verifier_contract(
        contract_name: str = "DocuTrustSMTVerifier",
        solidity_version: str = "^0.8.20"
    ) -> str:
        """Generates production-ready Solidity contract code for verifying 256-bit Sparse Merkle Trees on-chain."""
        return f"""// SPDX-License-Identifier: Apache-2.0
pragma solidity {solidity_version};

/**
 * @title {contract_name}
 * @author DocuTrust Sovereign Trust Engine v10.0.0
 * @notice Verifies 256-bit Sparse Merkle Tree (SMT) inclusion and non-membership proofs on-chain.
 */
contract {contract_name} {{
    event SMTVerified(bytes32 indexed root, bytes32 indexed key, bytes32 indexed value, bool exists);

    function verifySMTProof(
        bytes32 key,
        bytes32 value,
        bytes32 root,
        bytes32[] calldata sideNodes,
        uint256 depth
    ) public pure returns (bool) {{
        require(depth <= 256, "DocuTrust: depth out of bounds");
        require(sideNodes.length == depth, "DocuTrust: side nodes mismatch depth");

        bytes32 current = value == bytes32(0) ? bytes32(0) : sha256(abi.encodePacked(bytes1(0x00), key, value));

        for (uint256 i = 0; i < depth; i++) {{
            bytes32 sibling = sideNodes[i];
            uint256 bit = (uint256(key) >> (255 - i)) & 1;

            if (current == bytes32(0) && sibling == bytes32(0)) {{
                current = bytes32(0);
            }} else {{
                if (bit == 1) {{
                    current = sha256(abi.encodePacked(bytes1(0x01), sibling, current));
                }} else {{
                    current = sha256(abi.encodePacked(bytes1(0x01), current, sibling));
                }}
            }}
        }}

        return current == root;
    }}
}}
"""

