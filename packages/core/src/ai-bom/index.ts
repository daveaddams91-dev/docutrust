/**
 * @file packages/core/src/ai-bom/index.ts
 * @description Verifiable AI Model Weights & Provenance Registry (AI-BOM) (DocuTrust v14.0.0)
 * Generates cryptographic Machine Learning Bill of Materials (AI-BOM), layer-by-layer
 * tensor weight Merkle root hashing, LoRA adapter provenance chaining, dataset lineage tracking,
 * and immutable verifiable AI Model receipts (DocuTrustAIBOMReceipt2026).
 */

import * as crypto from 'crypto';
import { sha256Hex, signMessage, verifySignature, canonicalizeJson, KeyPair } from '../crypto/index.js';
import { MerkleTree, MerkleInclusionProof } from '../merkle/index.js';

export interface ModelLayerWeightInfo {
  layerIndex: number;
  layerName: string;
  tensorShape: number[];
  dataType: string;
  tensorDigestHex: string;
}

export interface ModelLoRAAdapter {
  adapterId: string;
  rank: number;
  alpha: number;
  baseLayerTarget: string;
  adapterWeightsHash: string;
}

export interface AIBOMManifest {
  modelId: string;
  modelName: string;
  architecture: string;
  parametersCount: string | number;
  quantization?: string;
  baseModelId?: string;
  layers: ModelLayerWeightInfo[];
  adapters?: ModelLoRAAdapter[];
  datasetLineage?: {
    datasetName: string;
    datasetHash: string;
    sampleCount?: number;
    license: string;
  };
  benchmarks?: Record<string, number>;
}

export interface DocuTrustAIBOMReceipt {
  type: 'DocuTrustAIBOMReceipt2026';
  receiptId: string;
  modelId: string;
  modelName: string;
  architecture: string;
  parametersCount: string | number;
  quantization: string;
  layerCount: number;
  weightsMerkleRoot: string;
  adaptersChainHash: string;
  datasetLineageHash: string;
  overallBOMDigest: string;
  benchmarks?: Record<string, number>;
  certifierDid: string;
  signatureHex: string;
  timestamp: string;
}

export interface AIBOMVerificationResult {
  valid: boolean;
  receiptId: string;
  modelId: string;
  layerCount: number;
  weightsMerkleRoot: string;
  errors: string[];
}

export class AIBOMRegistryEngine {
  /**
   * Computes the Merkle Root of the model layers and tensor weight digests.
   */
  public static computeWeightsMerkleTree(layers: any[]): MerkleTree {
    if (!layers || layers.length === 0) {
      throw new Error('AI Model must have at least one layer to compute weights Merkle tree.');
    }

    const normalizedLayers = layers.map((l: any, i: number) => ({
      layerIndex: l.layerIndex !== undefined ? l.layerIndex : i,
      layerName: l.layerName || `layer-${i}`,
      tensorShape: l.tensorShape || [],
      dataType: l.dataType || l.quantizationType || 'fp16',
      tensorDigestHex: l.tensorDigestHex || l.weightsDigest || sha256Hex(`LAYER_${i}_DIGEST`)
    }));

    const sortedLayers = [...normalizedLayers].sort((a, b) => a.layerIndex - b.layerIndex);
    const leaves = sortedLayers.map(l => {
      return canonicalizeJson({
        idx: l.layerIndex,
        name: l.layerName,
        shape: l.tensorShape,
        dtype: l.dataType,
        hash: l.tensorDigestHex
      });
    });

    return new MerkleTree(leaves);
  }

  /**
   * Computes the hash chain of LoRA fine-tuning adapters.
   */
  public static computeAdaptersChainHash(adapters?: ModelLoRAAdapter[]): string {
    if (!adapters || adapters.length === 0) {
      return sha256Hex('NO_ADAPTERS');
    }
    const canonical = canonicalizeJson(adapters);
    return sha256Hex(`ADAPTERS_CHAIN:${canonical}`);
  }

  /**
   * Creates a cryptographically signed DocuTrustAIBOMReceipt2026.
   */
  public static createAIBOMReceipt(
    manifest: AIBOMManifest,
    certifierKeyPair: KeyPair
  ): DocuTrustAIBOMReceipt {
    if (!manifest || (!manifest.modelId && !manifest.modelName) || !manifest.layers || manifest.layers.length === 0) {
      throw new Error('Missing required AI-BOM manifest fields: modelId/modelName, and layers.');
    }

    const modelId = manifest.modelId || manifest.modelName.toLowerCase().replace(/[^a-z0-9]/g, '-');
    const architecture = manifest.architecture || 'neural-network';
    const adapters = manifest.adapters || (manifest as any).loraAdapters;
    const datasetLineage = manifest.datasetLineage || (manifest as any).datasetsLineage;

    const receiptId = `aibom-${crypto.randomBytes(8).toString('hex')}`;
    const timestamp = new Date().toISOString();

    const weightsTree = this.computeWeightsMerkleTree(manifest.layers);
    const weightsMerkleRoot = weightsTree.getRoot();

    const adaptersChainHash = this.computeAdaptersChainHash(adapters);
    const datasetLineageHash = datasetLineage
      ? sha256Hex(`DATASET_LINEAGE:${canonicalizeJson(datasetLineage)}`)
      : sha256Hex('NO_DATASET_LINEAGE');

    const parametersCount = manifest.parametersCount || (manifest as any).trainingParameters?.totalParameters || 'unknown';
    const quantization = manifest.quantization || 'fp16';

    const overallBOMDigest = sha256Hex(canonicalizeJson({
      modelId,
      architecture,
      weightsMerkleRoot,
      adaptersChainHash,
      datasetLineageHash,
      quantization
    }));

    const signPayload = canonicalizeJson({
      receiptId,
      modelId,
      modelName: manifest.modelName,
      architecture,
      parametersCount,
      quantization,
      layerCount: manifest.layers.length,
      weightsMerkleRoot,
      adaptersChainHash,
      datasetLineageHash,
      overallBOMDigest,
      certifierDid: certifierKeyPair.did,
      timestamp
    });

    const signatureHex = signMessage(signPayload, certifierKeyPair.privateKeyHex);

    return {
      type: 'DocuTrustAIBOMReceipt2026',
      receiptId,
      modelId,
      modelName: manifest.modelName,
      architecture,
      parametersCount,
      quantization,
      layerCount: manifest.layers.length,
      weightsMerkleRoot,
      adaptersChainHash,
      datasetLineageHash,
      overallBOMDigest,
      benchmarks: manifest.benchmarks,
      certifierDid: certifierKeyPair.did,
      signatureHex,
      timestamp
    };
  }

  /**
   * Verifies an AI-BOM receipt against certifier public key and optional expected weights root.
   */
  public static verifyAIBOMReceipt(
    receipt: DocuTrustAIBOMReceipt,
    certifierPublicKeyHex: string,
    expectedWeightsMerkleRoot?: string
  ): AIBOMVerificationResult {
    const errors: string[] = [];

    if (!receipt || receipt.type !== 'DocuTrustAIBOMReceipt2026') {
      return {
        valid: false,
        receiptId: receipt?.receiptId || 'unknown',
        modelId: receipt?.modelId || 'unknown',
        layerCount: 0,
        weightsMerkleRoot: '',
        errors: ['Invalid AI-BOM receipt structure or type mismatch.']
      };
    }

    // 1. Verify weights Merkle root if provided
    if (expectedWeightsMerkleRoot && expectedWeightsMerkleRoot.toLowerCase() !== receipt.weightsMerkleRoot.toLowerCase()) {
      errors.push(`Weights Merkle root mismatch: expected ${expectedWeightsMerkleRoot}, found ${receipt.weightsMerkleRoot}`);
    }

    // 2. Recompute overall BOM digest
    const expectedBOMDigest = sha256Hex(canonicalizeJson({
      modelId: receipt.modelId,
      architecture: receipt.architecture,
      weightsMerkleRoot: receipt.weightsMerkleRoot,
      adaptersChainHash: receipt.adaptersChainHash,
      datasetLineageHash: receipt.datasetLineageHash,
      quantization: receipt.quantization
    }));

    if (expectedBOMDigest.toLowerCase() !== receipt.overallBOMDigest.toLowerCase()) {
      errors.push('Overall AI-BOM digest hash verification failed.');
    }

    // 3. Verify cryptographic signature
    const signPayload = canonicalizeJson({
      receiptId: receipt.receiptId,
      modelId: receipt.modelId,
      modelName: receipt.modelName,
      architecture: receipt.architecture,
      parametersCount: receipt.parametersCount,
      quantization: receipt.quantization,
      layerCount: receipt.layerCount,
      weightsMerkleRoot: receipt.weightsMerkleRoot,
      adaptersChainHash: receipt.adaptersChainHash,
      datasetLineageHash: receipt.datasetLineageHash,
      overallBOMDigest: receipt.overallBOMDigest,
      certifierDid: receipt.certifierDid,
      timestamp: receipt.timestamp
    });

    const isSigValid = verifySignature(signPayload, receipt.signatureHex, certifierPublicKeyHex);
    if (!isSigValid) {
      errors.push('Certifier cryptographic signature verification failed on AI-BOM receipt.');
    }

    return {
      valid: errors.length === 0,
      receiptId: receipt.receiptId,
      modelId: receipt.modelId,
      layerCount: receipt.layerCount,
      weightsMerkleRoot: receipt.weightsMerkleRoot,
      errors
    };
  }

  /**
   * Generates a Merkle inclusion proof for an individual layer in the model.
   */
  public static generateLayerProof(
    layers: any[],
    targetLayerIndex: number
  ): { layer: any; proof: MerkleInclusionProof; root: string } {
    const tree = this.computeWeightsMerkleTree(layers);
    const normalizedLayers = layers.map((l: any, i: number) => ({
      layerIndex: l.layerIndex !== undefined ? l.layerIndex : i,
      layerName: l.layerName || `layer-${i}`,
      tensorShape: l.tensorShape || [],
      dataType: l.dataType || l.quantizationType || 'fp16',
      tensorDigestHex: l.tensorDigestHex || l.weightsDigest || sha256Hex(`LAYER_${i}_DIGEST`)
    }));

    const sorted = [...normalizedLayers].sort((a, b) => a.layerIndex - b.layerIndex);
    const targetIdx = sorted.findIndex(l => l.layerIndex === targetLayerIndex);
    if (targetIdx === -1) {
      throw new Error(`Layer with index ${targetLayerIndex} not found in model layers.`);
    }

    const proof = tree.getProof(targetIdx);
    return {
      layer: sorted[targetIdx],
      proof,
      root: tree.getRoot()
    };
  }

  /**
   * Verifies that an individual tensor layer belongs to the verified weights Merkle root.
   */
  public static verifyLayerProof(
    layer: ModelLayerWeightInfo,
    proof: MerkleInclusionProof,
    weightsMerkleRoot: string
  ): boolean {
    const canonical = canonicalizeJson({
      idx: layer.layerIndex,
      name: layer.layerName,
      shape: layer.tensorShape,
      dtype: layer.dataType,
      hash: layer.tensorDigestHex
    });
    return MerkleTree.verifyProof(canonical, proof, weightsMerkleRoot);
  }
}
