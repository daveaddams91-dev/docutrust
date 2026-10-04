import { SolidityContractOptions } from '../index.js';

export class Groth16VerifierGenerator {
  public static generateGroth16VerifierContract(options: SolidityContractOptions = {}): string {
    const version = options.solidityVersion || '^0.8.20';
    const name = options.contractName || 'DocuTrustGroth16Verifier';

    return `// SPDX-License-Identifier: Apache-2.0
pragma solidity ${version};

contract ${name} {
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    event ProofVerified(bytes32 indexed publicInputsHash, bool success, address indexed verifier);

    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata input
    ) public returns (bool) {
        // Prepare pairing buffer
        bytes memory inputBuffer = abi.encodePacked(
            a[0], a[1],
            b[0][0], b[0][1], b[1][0], b[1][1],
            c[0], c[1]
        );

        bool success;
        bytes32 pubHash = keccak256(abi.encode(input));

        // Call precompile 0x08 for pairing check
        uint256[1] memory out;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(inputBuffer, 0x20), mload(inputBuffer), out, 0x20)
        }

        emit ProofVerified(pubHash, success, msg.sender);
        return success;
    }
}
`;
  }

}
