import * as crypto from 'crypto';
import { EVMCalldataResult } from './index.js';

export class SolidityUtils {
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
