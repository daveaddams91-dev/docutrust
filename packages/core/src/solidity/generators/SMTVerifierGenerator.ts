import { SolidityContractOptions } from '../index.js';

export class SMTVerifierGenerator {
  public static generateSMTVerifierContract(options: SolidityContractOptions = {}): string {
    const version = options.solidityVersion || '^0.8.24';
    const name = options.contractName || 'DocuTrustSMTVerifier';

    return `// SPDX-License-Identifier: Apache-2.0
pragma solidity ${version};

contract ${name} {
    struct Sibling {
        uint8 depth;
        bytes32 siblingHash;
        bool isRight;
    }

    event SMTProofVerified(bytes32 indexed root, bytes32 indexed key, bytes32 valueHash, bool exists, address verifier);

    function computeLeafHash(bytes32 key, bytes32 value) public pure returns (bytes32) {
        return sha256(abi.encodePacked("SMT_LEAF:", key, ":", value));
    }

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

}
