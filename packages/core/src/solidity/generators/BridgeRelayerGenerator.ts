import { SolidityContractOptions } from '../index.js';

export class BridgeRelayerGenerator {
  public static generateBridgeRelayerContract(options: SolidityContractOptions = {}): string {
    const version = options.solidityVersion || '^0.8.20';
    const name = options.contractName || 'DocuTrustBridgeRelayer';

    return `// SPDX-License-Identifier: Apache-2.0
pragma solidity ${version};

contract ${name} {
    struct CrossChainMessage {
        bytes32 messageId;
        uint256 sourceChainId;
        uint256 destinationChainId;
        uint256 sequenceNonce;
        bytes32 stateRoot;
        bytes32 payloadHash;
        uint256 timestamp;
        address senderAddress;
        address recipientAddress;
    }

    event MessageRelayed(bytes32 indexed messageId, uint256 indexed sourceChainId, uint256 sequenceNonce, bytes32 stateRoot);
    event ValidatorUpdated(address indexed validator, bool active);
    event QuorumThresholdUpdated(uint256 newThreshold);

    address public owner;
    uint256 public quorumThreshold;
    mapping(address => bool) public isValidator;
    mapping(bytes32 => bool) public executedMessages;
    mapping(string => uint256) public latestNonces;

    modifier onlyOwner() {
        require(msg.sender == owner, "DocuTrust: caller is not owner");
        _;
    }

    constructor(uint256 _quorumThreshold, address[] memory _validators) {
        owner = msg.sender;
        quorumThreshold = _quorumThreshold > 0 ? _quorumThreshold : 1;
        for (uint256 i = 0; i < _validators.length; i++) {
            isValidator[_validators[i]] = true;
            emit ValidatorUpdated(_validators[i], true);
        }
    }

    function setValidator(address validator, bool active) external onlyOwner {
        isValidator[validator] = active;
        emit ValidatorUpdated(validator, active);
    }

    function setQuorumThreshold(uint256 newThreshold) external onlyOwner {
        require(newThreshold > 0, "DocuTrust: threshold must be > 0");
        quorumThreshold = newThreshold;
        emit QuorumThresholdUpdated(newThreshold);
    }

    function computeDigest(CrossChainMessage calldata msgData) public pure returns (bytes32) {
        return keccak256(abi.encode(
            msgData.messageId,
            msgData.sourceChainId,
            msgData.destinationChainId,
            msgData.sequenceNonce,
            msgData.stateRoot,
            msgData.payloadHash,
            msgData.timestamp,
            msgData.senderAddress,
            msgData.recipientAddress
        ));
    }

    function relayCrossChainState(
        CrossChainMessage calldata msgData,
        bytes[] calldata signatures
    ) external returns (bool) {
        require(msgData.destinationChainId == block.chainid || msgData.destinationChainId == 0, "DocuTrust: wrong destination chain");
        require(!executedMessages[msgData.messageId], "DocuTrust: message already executed");
        require(signatures.length >= quorumThreshold, "DocuTrust: insufficient signatures for quorum");

        bytes32 digest = computeDigest(msgData);
        bytes32 ethSignedDigest = keccak256(abi.encodePacked("\\x19Ethereum Signed Message:\\n32", digest));

        address lastSigner = address(0);
        uint256 validCount = 0;

        for (uint256 i = 0; i < signatures.length; i++) {
            bytes memory sig = signatures[i];
            require(sig.length == 65, "DocuTrust: invalid signature length");

            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(sig, 32))
                s := mload(add(sig, 64))
                v := byte(0, mload(add(sig, 96)))
            }
            if (v < 27) v += 27;

            address signer = ecrecover(ethSignedDigest, v, r, s);
            require(signer > lastSigner, "DocuTrust: signatures must be strictly sorted to prevent duplicate counting");
            lastSigner = signer;

            if (isValidator[signer]) {
                validCount++;
            }
        }

        require(validCount >= quorumThreshold, "DocuTrust: valid validator quorum not met");

        executedMessages[msgData.messageId] = true;
        emit MessageRelayed(msgData.messageId, msgData.sourceChainId, msgData.sequenceNonce, msgData.stateRoot);
        return true;
    }
}
`;
  }

}
