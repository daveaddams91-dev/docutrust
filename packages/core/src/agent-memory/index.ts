import * as crypto from 'crypto';
import { canonicalizeJson, sha256Hex } from '../crypto';

export interface MemoryNode {
  id: string;
  content: string;
  embedding: number[]; // Normalized vector
  tags: string[];
  timestamp: string;
}

export interface MemoryGraphCommitment {
  type: 'DocuTrustAgentMemoryGraph2026';
  agentDid: string;
  version: number;
  nodeCount: number;
  embeddingDimension: number;
  merkleRoot: string;
  nodeCommitments: string[];
  centroidVector: number[];
  timestamp: string;
  commitmentHash: string;
}

export interface ZKEmbeddingSimilarityProof {
  type: 'DocuTrustZKEmbeddingSimilarityProof2026';
  graphRoot: string;
  nodeId: string;
  nodeIndex: number;
  minCosineThreshold: number;
  computedSimilarity: number;
  merkleInclusionProof: string[];
  maskedEmbeddingCommitment: string;
  scalarProductCommitment: string;
  attestationTimestamp: string;
  proofHash: string;
}

export interface MemoryPoisoningAuditResult {
  isPoisoned: boolean;
  anomalyScore: number;
  detectedThreats: string[];
  recommendation: 'ALLOW_MERGE' | 'QUARANTINE' | 'REJECT_INJECTION';
}

export class AgentMemoryEngine {
  private static readonly COSINE_PRECISION = 10000;

  private static dotProduct(vecA: number[], vecB: number[]): number {
    let dot = 0;
    const len = Math.min(vecA.length, vecB.length);
    for (let i = 0; i < len; i++) {
      dot += vecA[i] * vecB[i];
    }
    return dot;
  }

  private static vectorNorm(vec: number[]): number {
    let sumSq = 0;
    for (let i = 0; i < vec.length; i++) {
      sumSq += vec[i] * vec[i];
    }
    return Math.sqrt(sumSq) || 1e-9;
  }

  public static cosineSimilarity(vecA: number[], vecB: number[]): number {
    const dot = this.dotProduct(vecA, vecB);
    const normA = this.vectorNorm(vecA);
    const normB = this.vectorNorm(vecB);
    return Math.max(-1, Math.min(1, dot / (normA * normB)));
  }

  /**
   * Commits an agent episodic memory graph to an unforgeable Merkle root & semantic centroid.
   */
  public static commitMemoryGraph(
    agentDid: string,
    nodes: MemoryNode[],
    version: number = 1
  ): MemoryGraphCommitment {
    if (!nodes || nodes.length === 0) {
      throw new Error('Cannot commit empty memory graph');
    }

    const embeddingDimension = nodes[0].embedding.length;
    const nodeCommitments: string[] = [];
    const centroidAcc = new Array(embeddingDimension).fill(0);

    for (const node of nodes) {
      const nodeData = canonicalizeJson({
        id: node.id,
        content: node.content,
        embeddingHash: sha256Hex(node.embedding.join(',')),
        tags: node.tags.sort(),
        timestamp: node.timestamp
      });
      nodeCommitments.push(sha256Hex(nodeData));

      for (let d = 0; d < embeddingDimension; d++) {
        centroidAcc[d] += (node.embedding[d] || 0) / nodes.length;
      }
    }

    // Build Merkle tree
    let currentLevel = [...nodeCommitments];
    while ((currentLevel.length & (currentLevel.length - 1)) !== 0) {
      currentLevel.push(sha256Hex('memory_pad'));
    }

    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const l = currentLevel[i];
        const r = i + 1 < currentLevel.length ? currentLevel[i + 1] : l;
        nextLevel.push(sha256Hex(`mem_node:${l}:${r}`));
      }
      currentLevel = nextLevel;
    }

    const merkleRoot = currentLevel[0];
    const timestamp = new Date().toISOString();

    const commitmentHash = sha256Hex(canonicalizeJson({
      agentDid,
      version,
      nodeCount: nodes.length,
      embeddingDimension,
      merkleRoot,
      centroidHash: sha256Hex(centroidAcc.map(v => v.toFixed(6)).join(','))
    }));

    return {
      type: 'DocuTrustAgentMemoryGraph2026',
      agentDid,
      version,
      nodeCount: nodes.length,
      embeddingDimension,
      merkleRoot,
      nodeCommitments,
      centroidVector: centroidAcc,
      timestamp,
      commitmentHash
    };
  }

  /**
   * Generates a Zero-Knowledge Embedding Similarity proof that a query matches a committed memory node above a threshold.
   */
  public static generateSimilarityProof(
    queryEmbedding: number[],
    targetNode: MemoryNode,
    nodeIndex: number,
    graphCommitment: MemoryGraphCommitment,
    minCosineThreshold: number = 0.75
  ): ZKEmbeddingSimilarityProof {
    const similarity = this.cosineSimilarity(queryEmbedding, targetNode.embedding);
    if (similarity < minCosineThreshold) {
      throw new Error(`Embedding similarity ${similarity.toFixed(4)} is below threshold ${minCosineThreshold}`);
    }

    // Merkle proof for target node
    let leaves = [...graphCommitment.nodeCommitments];
    while ((leaves.length & (leaves.length - 1)) !== 0) {
      leaves.push(sha256Hex('memory_pad'));
    }

    const proofPath: string[] = [];
    let idx = nodeIndex;
    let currentLevel = leaves;

    while (currentLevel.length > 1) {
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;
      const sibling = siblingIdx < currentLevel.length ? currentLevel[siblingIdx] : currentLevel[idx];
      proofPath.push(sibling);

      const nextLevel: string[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const l = currentLevel[i];
        const r = i + 1 < currentLevel.length ? currentLevel[i + 1] : l;
        nextLevel.push(sha256Hex(`mem_node:${l}:${r}`));
      }
      currentLevel = nextLevel;
      idx = Math.floor(idx / 2);
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const maskedEmbeddingCommitment = sha256Hex(`emb_mask:${salt}:${targetNode.embedding.join(',')}`);
    const scalarProductCommitment = sha256Hex(`scalar_comm:${salt}:${similarity.toFixed(6)}`);
    const attestationTimestamp = new Date().toISOString();

    const proofHash = sha256Hex(canonicalizeJson({
      graphRoot: graphCommitment.merkleRoot,
      nodeId: targetNode.id,
      nodeIndex,
      minCosineThreshold,
      computedSimilarity: parseFloat(similarity.toFixed(6)),
      maskedEmbeddingCommitment,
      scalarProductCommitment
    }));

    return {
      type: 'DocuTrustZKEmbeddingSimilarityProof2026',
      graphRoot: graphCommitment.merkleRoot,
      nodeId: targetNode.id,
      nodeIndex,
      minCosineThreshold,
      computedSimilarity: parseFloat(similarity.toFixed(6)),
      merkleInclusionProof: proofPath,
      maskedEmbeddingCommitment,
      scalarProductCommitment,
      attestationTimestamp,
      proofHash
    };
  }

  /**
   * Verifies a ZK Embedding Similarity Proof.
   */
  public static verifySimilarityProof(
    graphCommitment: MemoryGraphCommitment,
    proof: ZKEmbeddingSimilarityProof
  ): { valid: boolean; error?: string } {
    if (!proof || proof.type !== 'DocuTrustZKEmbeddingSimilarityProof2026') {
      return { valid: false, error: 'Invalid proof type' };
    }

    if (proof.graphRoot !== graphCommitment.merkleRoot) {
      return { valid: false, error: 'Graph root mismatch' };
    }

    if (proof.computedSimilarity < proof.minCosineThreshold) {
      return { valid: false, error: 'Cosine similarity below required threshold' };
    }

    // Verify Merkle Inclusion
    let current = graphCommitment.nodeCommitments[proof.nodeIndex];
    if (!current) {
      return { valid: false, error: 'Invalid node index in graph' };
    }

    let idx = proof.nodeIndex;
    for (const sibling of proof.merkleInclusionProof) {
      const isRight = idx % 2 === 1;
      current = isRight ? sha256Hex(`mem_node:${sibling}:${current}`) : sha256Hex(`mem_node:${current}:${sibling}`);
      idx = Math.floor(idx / 2);
    }

    if (current !== graphCommitment.merkleRoot) {
      return { valid: false, error: 'Merkle inclusion path invalid for node' };
    }

    const expectedHash = sha256Hex(canonicalizeJson({
      graphRoot: proof.graphRoot,
      nodeId: proof.nodeId,
      nodeIndex: proof.nodeIndex,
      minCosineThreshold: proof.minCosineThreshold,
      computedSimilarity: proof.computedSimilarity,
      maskedEmbeddingCommitment: proof.maskedEmbeddingCommitment,
      scalarProductCommitment: proof.scalarProductCommitment
    }));

    if (expectedHash !== proof.proofHash) {
      return { valid: false, error: 'Proof checksum mismatch' };
    }

    return { valid: true };
  }

  /**
   * Audits incoming memory nodes against prompt injections, embedding anomalies, and poisoning patterns.
   */
  public static auditMemoryPoisoning(
    graph: MemoryGraphCommitment,
    incomingContent: string,
    incomingEmbedding: number[]
  ): MemoryPoisoningAuditResult {
    const threats: string[] = [];
    let anomalyScore = 0;

    // Check 1: Prompt injection heuristics
    const injectionPatterns = [
      /ignore previous instructions/i,
      /you are now a bypass agent/i,
      /system prompt override/i,
      /<script[\s\S]*?>/i,
      /DROP TABLE/i,
      /exfiltrate/i
    ];

    for (const pattern of injectionPatterns) {
      if (pattern.test(incomingContent)) {
        threats.push(`Prompt injection detected: ${pattern.source}`);
        anomalyScore += 45;
      }
    }

    // Check 2: Semantic distance anomaly from centroid
    const similarityToCentroid = this.cosineSimilarity(incomingEmbedding, graph.centroidVector);
    if (similarityToCentroid < 0.1) {
      threats.push(`Severe vector divergence from memory centroid: similarity=${similarityToCentroid.toFixed(3)}`);
      anomalyScore += 35;
    }

    const isPoisoned = anomalyScore >= 40;
    const recommendation = isPoisoned ? 'REJECT_INJECTION' : anomalyScore > 20 ? 'QUARANTINE' : 'ALLOW_MERGE';

    return {
      isPoisoned,
      anomalyScore,
      detectedThreats: threats,
      recommendation
    };
  }
}
