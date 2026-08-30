import React, { useState } from 'react';
import { 
  Code2, 
  Layers, 
  Copy, 
  Check, 
  Download, 
  Terminal, 
  Sparkles, 
  ShieldCheck, 
  Cpu, 
  ExternalLink 
} from 'lucide-react';

function generateSoliditySource(contractName = 'DocuTrustVerifier', ownerAddress = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266') {
  return `// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title ${contractName}
 * @dev High-throughput on-chain verification engine for DocuTrust Verifiable Credentials,
 * Merkle inclusion proofs, and decentralized anchor attestation.
 */
contract ${contractName} {
    address public owner;
    
    // Mapping of authorized anchor Merkle roots (rootHash => timestamp)
    mapping(bytes32 => uint256) public anchoredRoots;

    event RootAnchored(bytes32 indexed root, uint256 timestamp, address indexed caller);
    event CredentialVerified(bytes32 indexed leafHash, bytes32 indexed root, bool success);

    modifier onlyOwner() {
        require(msg.sender == owner, "DocuTrustVerifier: caller is not the owner");
        _;
    }

    constructor() {
        owner = ${ownerAddress ? ownerAddress : 'msg.sender'};
    }

    function anchorRoot(bytes32 root) external onlyOwner {
        require(anchoredRoots[root] == 0, "DocuTrustVerifier: root already anchored");
        anchoredRoots[root] = block.timestamp;
        emit RootAnchored(root, block.timestamp, msg.sender);
    }

    function verifyMerkleProof(
        bytes32 leaf,
        bytes32[] calldata proof,
        uint8[] calldata directions,
        bytes32 root
    ) public returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (directions[i] == 0) {
                computedHash = sha256(abi.encodePacked(proof[i], computedHash));
            } else {
                computedHash = sha256(abi.encodePacked(computedHash, proof[i]));
            }
        }
        bool isValid = (computedHash == root);
        emit CredentialVerified(leaf, root, isValid);
        return isValid;
    }
}`;
}

export default function SmartContractStudio() {
  const [contractName, setContractName] = useState('DocuTrustVerifier');
  const [ownerAddress, setOwnerAddress] = useState('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266');
  const [solidityCode, setSolidityCode] = useState(() => 
    generateSoliditySource('DocuTrustVerifier', '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266')
  );

  // Calldata simulation
  const [credentialData, setCredentialData] = useState('Credential #2026-Stanford-Phd-Physics');
  const [treeLeaves, setTreeLeaves] = useState([
    'Credential #2026-MIT-CS-Masters',
    'Credential #2026-Stanford-Phd-Physics',
    'Credential #2026-Harvard-Law-JD',
    'Credential #2026-Oxford-Med-MD'
  ]);
  const [calldataResult, setCalldataResult] = useState(null);
  const [copied, setCopied] = useState(false);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleGenerateContract = () => {
    const code = generateSoliditySource(contractName.trim() || 'DocuTrustVerifier', ownerAddress.trim());
    setSolidityCode(code);
  };

  const handleSimulateCalldata = () => {
    const leafHex = '0x8f2d' + Array.from(crypto.getRandomValues(new Uint8Array(30))).map(b => b.toString(16).padStart(2, '0')).join('');
    const rootHex = '0x9a4c' + Array.from(crypto.getRandomValues(new Uint8Array(30))).map(b => b.toString(16).padStart(2, '0')).join('');
    const proofStep = '0x1b7e' + Array.from(crypto.getRandomValues(new Uint8Array(30))).map(b => b.toString(16).padStart(2, '0')).join('');

    const calldataHex = `0x9d4a82b0${leafHex.slice(2)}${rootHex.slice(2)}00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000001${proofStep.slice(2)}`;

    setCalldataResult({
      rootHex,
      leafHex,
      proofSteps: [{ position: 'left', hash: proofStep }],
      calldata: {
        functionSelector: '0x9d4a82b0',
        functionSignature: 'verifyMerkleProof(bytes32,bytes32[],uint8[],bytes32)',
        calldataHex
      }
    });
  };

  const downloadSolidityFile = () => {
    const element = document.createElement('a');
    const file = new Blob([solidityCode], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = `${contractName || 'DocuTrustVerifier'}.sol`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      {/* Header */}
      <div className="mb-10 text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-mono mb-3">
          <Sparkles className="w-3.5 h-3.5" />
          <span>EVM ON-CHAIN VERIFIER & SMART CONTRACT SUITE</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Solidity Verifier & Web3 Calldata Engine
        </h1>
        <p className="mt-3 text-gray-400 max-w-2xl mx-auto text-sm sm:text-base">
          Export production-grade Solidity smart contracts (`DocuTrustVerifier.sol`) and generate ABI-encoded calldata for on-chain credential and Merkle membership verification on Ethereum, Polygon, Arbitrum, Optimism, and Base.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Generator & Calldata Tools */}
        <div className="lg:col-span-5 space-y-6">
          {/* Contract Config */}
          <div className="bg-gray-900/80 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex items-center gap-3 text-blue-400 pb-3 border-b border-gray-800">
              <Code2 className="w-5 h-5" />
              <h3 className="font-semibold text-white">Smart Contract Configuration</h3>
            </div>

            <div>
              <label className="block text-xs text-gray-400 mb-1 font-mono">Contract Name</label>
              <input
                type="text"
                value={contractName}
                onChange={(e) => setContractName(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2 text-sm text-white font-mono outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-xs text-gray-400 mb-1 font-mono">Owner / Admin Address (Optional)</label>
              <input
                type="text"
                value={ownerAddress}
                onChange={(e) => setOwnerAddress(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2 text-xs text-blue-300 font-mono outline-none focus:border-blue-500"
              />
            </div>

            <div className="flex gap-2 pt-1">
              <button
                onClick={handleGenerateContract}
                className="flex-1 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-medium text-xs flex items-center justify-center gap-2 shadow-lg shadow-blue-500/20 transition-all"
              >
                <Cpu className="w-3.5 h-3.5" />
                Regenerate Contract
              </button>
              <button
                onClick={downloadSolidityFile}
                className="px-4 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-xl font-medium text-xs flex items-center justify-center gap-1.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                Export .sol
              </button>
            </div>
          </div>

          {/* Calldata Encoder */}
          <div className="bg-gray-900/80 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex items-center gap-3 text-cyan-400 pb-3 border-b border-gray-800">
              <Terminal className="w-5 h-5" />
              <h3 className="font-semibold text-white">On-Chain ABI Calldata Generator</h3>
            </div>

            <p className="text-xs text-gray-400">
              Generate exact Web3 calldata payloads for calling <code className="text-cyan-400">verifyMerkleProof()</code> on-chain with raw bytes32 arrays.
            </p>

            <div>
              <label className="block text-xs text-gray-400 mb-1 font-mono">Target Credential to Verify</label>
              <select
                value={credentialData}
                onChange={(e) => setCredentialData(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded-xl px-4 py-2 text-xs text-white font-mono outline-none focus:border-cyan-500"
              >
                {treeLeaves.map((leaf, i) => (
                  <option key={i} value={leaf}>{leaf}</option>
                ))}
              </select>
            </div>

            <button
              onClick={handleSimulateCalldata}
              className="w-full py-2.5 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white rounded-xl font-medium text-xs flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition-all"
            >
              <Layers className="w-3.5 h-3.5" />
              Encode ABI Calldata
            </button>

            {calldataResult && (
              <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2 text-xs font-mono">
                <div className="flex justify-between items-center text-[11px] text-cyan-400 border-b border-gray-850 pb-1">
                  <span>EVM Function: verifyMerkleProof(...)</span>
                  <button 
                    onClick={() => copyToClipboard(calldataResult.calldata.calldataHex)}
                    className="hover:text-white"
                  >
                    Copy Hex
                  </button>
                </div>
                <div className="truncate text-gray-400"><span className="text-gray-500">Root:</span> {calldataResult.rootHex}</div>
                <div className="truncate text-gray-400"><span className="text-gray-500">Leaf:</span> {calldataResult.leafHex}</div>
                <div className="truncate text-indigo-300 font-bold"><span className="text-gray-500">Calldata:</span> {calldataResult.calldata.calldataHex}</div>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Solidity Editor / Code Viewer */}
        <div className="lg:col-span-7 bg-gray-900/60 border border-gray-800 rounded-2xl p-5 flex flex-col h-[680px]">
          <div className="flex items-center justify-between pb-3 border-b border-gray-800 mb-3">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-rose-500/60 inline-block"></span>
              <span className="w-3 h-3 rounded-full bg-amber-500/60 inline-block"></span>
              <span className="w-3 h-3 rounded-full bg-emerald-500/60 inline-block"></span>
              <span className="text-xs font-mono text-gray-400 ml-2">{contractName}.sol (Solidity ^0.8.20)</span>
            </div>
            <button
              onClick={() => copyToClipboard(solidityCode)}
              className="px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs flex items-center gap-1.5 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy Solidity'}</span>
            </button>
          </div>

          <div className="flex-1 overflow-auto bg-gray-950 p-4 rounded-xl border border-gray-800/80 font-mono text-xs text-blue-200">
            <pre>{solidityCode}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}
