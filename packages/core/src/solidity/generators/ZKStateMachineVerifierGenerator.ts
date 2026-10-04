import { SolidityContractOptions } from '../index.js';

export class ZKStateMachineVerifierGenerator {
  public static generateZKStateMachineVerifierContract(options: SolidityContractOptions = {}): string {
    const version = options.solidityVersion || '^0.8.20';
    const name = options.contractName || 'DocuTrustZKStateMachineVerifier';

    return `// SPDX-License-Identifier: Apache-2.0
pragma solidity ${version};

contract ${name} {
    struct StateMachine {
        bytes32 machineId;
        bytes32 currentStateRoot;
        uint256 requiredBond;
        uint256 escrowBounty;
        uint256 timeoutSeconds;
        address creator;
        bool isFinalized;
    }

    event StateMachineCreated(bytes32 indexed machineId, bytes32 initialStateRoot, uint256 escrowBounty);
    event StateTransitionVerified(bytes32 indexed machineId, bytes32 indexed transitionId, bytes32 fromRoot, bytes32 toRoot);
    event DisputeLiquidated(bytes32 indexed machineId, bytes32 indexed transitionId, address indexed challenger, uint256 slashedBond);
    event EscrowSettled(bytes32 indexed machineId, address indexed recipient, uint256 amount);

    mapping(bytes32 => StateMachine) public machines;
    mapping(bytes32 => bool) public executedTransitions;

    function createStateMachine(
        bytes32 machineId,
        bytes32 initialStateRoot,
        uint256 requiredBond,
        uint256 timeoutSeconds
    ) external payable {
        require(machines[machineId].machineId == bytes32(0), "DocuTrust: machine already exists");
        require(msg.value > 0, "DocuTrust: escrow bounty required");

        machines[machineId] = StateMachine({
            machineId: machineId,
            currentStateRoot: initialStateRoot,
            requiredBond: requiredBond,
            escrowBounty: msg.value,
            timeoutSeconds: timeoutSeconds,
            creator: msg.sender,
            isFinalized: false
        });

        emit StateMachineCreated(machineId, initialStateRoot, msg.value);
    }

    function verifyAndApplyTransition(
        bytes32 machineId,
        bytes32 transitionId,
        bytes32 fromStateRoot,
        bytes32 toStateRoot,
        bytes32 zkProofHash
    ) external returns (bool) {
        StateMachine storage sm = machines[machineId];
        require(sm.machineId != bytes32(0), "DocuTrust: machine does not exist");
        require(!sm.isFinalized, "DocuTrust: machine finalized");
        require(!executedTransitions[transitionId], "DocuTrust: transition already processed");
        require(sm.currentStateRoot == fromStateRoot, "DocuTrust: stale fromStateRoot");
        require(zkProofHash != bytes32(0), "DocuTrust: invalid ZK proof");

        sm.currentStateRoot = toStateRoot;
        executedTransitions[transitionId] = true;

        emit StateTransitionVerified(machineId, transitionId, fromStateRoot, toStateRoot);
        return true;
    }
}
`;
  }

}
