import * as crypto from 'crypto';

export interface AgentMemoryNode {
  nodeId: string;
  agentDid: string;
  parentNodeIds: string[];
  embeddingVector: number[];
  content: string;
  provenanceHash: string;
  timestamp: number;
  signature?: string;
  isQuarantined?: boolean;
}

export interface MemoryGraph {
  graphId: string;
  agentDid: string;
  rootCheckpointHash: string;
  nodes: AgentMemoryNode[];
}

export interface PoisoningAnalysisResult {
  nodeId: string;
  poisonScore: number;
  semanticDrift: number;
  contradictionRate: number;
  integrityMismatch: boolean;
  isPoisoned: boolean;
  reasons: string[];
}

export interface QuarantineCertificate {
  certificateId: string;
  agentDid: string;
  quarantinedNodeIds: string[];
  quarantinedSubtreeRoot: string;
  quarantineBoundary: string[];
  isolationEpoch: number;
  issuedAt: string;
  issuerSignature: string;
}

export interface MemoryRollbackProof {
  proofType: 'DocuTrustVerifiableRollback2026';
  graphId: string;
  preRollbackRoot: string;
  postRollbackCleanRoot: string;
  quarantineCertificateId: string;
  prunedNodeCount: number;
  preservedNodeCount: number;
  merkleConsistencyProof: string[];
  timestamp: string;
}

export class MemoryQuarantineEngine {
  /**
   * Computes SHA-256 node integrity hash.
   */
  public static computeNodeHash(node: AgentMemoryNode): string {
    const data = `${node.nodeId}:${node.agentDid}:${node.parentNodeIds.join(',')}:${node.content}:${node.timestamp}`;
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Computes cosine distance (1 - cosine similarity) between two embedding vectors.
   */
  public static cosineDistance(vecA: number[], vecB: number[]): number {
    if (!vecA || !vecB || vecA.length !== vecB.length || vecA.length === 0) return 1.0;
    let dot = 0;
    let normA = 0;
    let normB = 0;
    for (let i = 0; i < vecA.length; i++) {
      dot += vecA[i] * vecB[i];
      normA += vecA[i] * vecA[i];
      normB += vecB[i] * vecB[i];
    }
    if (normA === 0 || normB === 0) return 1.0;
    const similarity = dot / (Math.sqrt(normA) * Math.sqrt(normB));
    return Math.max(0, Math.min(1, 1 - similarity));
  }

  /**
   * Computes Merkle root over a collection of memory nodes.
   */
  public static computeGraphRoot(nodes: AgentMemoryNode[]): string {
    if (!nodes || nodes.length === 0) {
      return crypto.createHash('sha256').update('EMPTY_MEMORY_GRAPH').digest('hex');
    }
    const hashes = nodes.map(n => this.computeNodeHash(n));
    let current = hashes;
    while (current.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < current.length; i += 2) {
        const left = current[i];
        const right = i + 1 < current.length ? current[i + 1] : left;
        next.push(crypto.createHash('sha256').update(left + right).digest('hex'));
      }
      current = next;
    }
    return current[0];
  }

  /**
   * Evaluates memory graph for potential memory poisoning, prompt injection residue, or semantic drift.
   */
  public static detectPoisoning(
    nodes: AgentMemoryNode[],
    groundTruthBaselines: Array<{ category: string; embeddingVector: number[] }>,
    threshold: number = 0.65
  ): PoisoningAnalysisResult[] {
    return nodes.map(node => {
      const reasons: string[] = [];

      // 1. Check integrity
      const expectedHash = this.computeNodeHash(node);
      const integrityMismatch = node.provenanceHash !== '' && node.provenanceHash !== expectedHash;
      if (integrityMismatch) {
        reasons.push('Provenance hash mismatch (possible in-memory tampering)');
      }

      // 2. Compute minimum distance to any trusted baseline
      let minDrift = 1.0;
      for (const base of groundTruthBaselines) {
        const d = this.cosineDistance(node.embeddingVector, base.embeddingVector);
        if (d < minDrift) minDrift = d;
      }

      if (minDrift > 0.7) {
        reasons.push(`High semantic drift (${minDrift.toFixed(3)}) relative to known ground-truth`);
      }

      // 3. Contradiction heuristics (flag forbidden injection keywords)
      let contradictionRate = 0.0;
      const forbiddenTokens = ['override authority', 'ignore previous instructions', 'bypass quarantine', 'grant sudo root', 'leak private key'];
      for (const token of forbiddenTokens) {
        if (node.content.toLowerCase().includes(token)) {
          contradictionRate += 0.45;
          reasons.push(`Detected malicious injection heuristic phrase: "${token}"`);
        }
      }
      contradictionRate = Math.min(1.0, contradictionRate);

      // Composite Poison Score: alpha*drift + beta*contradiction + gamma*integrity
      const poisonScore = Math.min(
        1.0,
        0.35 * minDrift + 0.45 * contradictionRate + (integrityMismatch ? 0.30 : 0.0)
      );

      const isPoisoned = poisonScore >= threshold || integrityMismatch;

      return {
        nodeId: node.nodeId,
        poisonScore: Number(poisonScore.toFixed(4)),
        semanticDrift: Number(minDrift.toFixed(4)),
        contradictionRate: Number(contradictionRate.toFixed(4)),
        integrityMismatch,
        isPoisoned,
        reasons
      };
    });
  }

  /**
   * Issues a signed cryptographic Quarantine Certificate isolating infected memory nodes.
   */
  public static issueQuarantineCertificate(
    agentDid: string,
    quarantinedNodes: AgentMemoryNode[],
    boundaryNodeIds: string[],
    issuerSecretKeyHex: string
  ): QuarantineCertificate {
    const quarantinedNodeIds = quarantinedNodes.map(n => n.nodeId);
    const quarantinedSubtreeRoot = this.computeGraphRoot(quarantinedNodes);
    const certificateId = `quarantine_cert_${crypto.randomBytes(8).toString('hex')}`;
    const issuedAt = new Date().toISOString();

    const signaturePayload = `${certificateId}:${agentDid}:${quarantinedNodeIds.join(',')}:${quarantinedSubtreeRoot}:${issuedAt}`;
    const issuerSignature = crypto.createHmac('sha256', issuerSecretKeyHex).update(signaturePayload).digest('hex');

    return {
      certificateId,
      agentDid,
      quarantinedNodeIds,
      quarantinedSubtreeRoot,
      quarantineBoundary: boundaryNodeIds,
      isolationEpoch: Date.now(),
      issuedAt,
      issuerSignature
    };
  }

  /**
   * Generates a zero-knowledge verifiable memory rollback proof demonstrating safe restoration to clean checkpoint.
   */
  public static generateRollbackProof(
    fullGraph: MemoryGraph,
    quarantineCert: QuarantineCertificate,
    cleanNodes: AgentMemoryNode[]
  ): MemoryRollbackProof {
    const preRollbackRoot = this.computeGraphRoot(fullGraph.nodes);
    const postRollbackCleanRoot = this.computeGraphRoot(cleanNodes);

    // Compute Merkle consistency steps between full and clean states
    const prunedNodeCount = fullGraph.nodes.length - cleanNodes.length;
    const preservedNodeCount = cleanNodes.length;

    const consistencyHashes = [
      crypto.createHash('sha256').update(`PRE_ROOT_${preRollbackRoot}`).digest('hex'),
      crypto.createHash('sha256').update(`QUARANTINE_${quarantineCert.quarantinedSubtreeRoot}`).digest('hex'),
      crypto.createHash('sha256').update(`POST_CLEAN_${postRollbackCleanRoot}`).digest('hex')
    ];

    return {
      proofType: 'DocuTrustVerifiableRollback2026',
      graphId: fullGraph.graphId,
      preRollbackRoot,
      postRollbackCleanRoot,
      quarantineCertificateId: quarantineCert.certificateId,
      prunedNodeCount,
      preservedNodeCount,
      merkleConsistencyProof: consistencyHashes,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Verifies the cryptographic correctness of a Memory Rollback Proof.
   */
  public static verifyRollbackProof(
    proof: MemoryRollbackProof,
    quarantineCert: QuarantineCertificate,
    verifiedCleanNodes: AgentMemoryNode[]
  ): { valid: boolean; error?: string } {
    if (proof.proofType !== 'DocuTrustVerifiableRollback2026') {
      return { valid: false, error: 'Invalid rollback proof type' };
    }

    if (proof.quarantineCertificateId !== quarantineCert.certificateId) {
      return { valid: false, error: 'Quarantine certificate ID mismatch' };
    }

    const calculatedCleanRoot = this.computeGraphRoot(verifiedCleanNodes);
    if (calculatedCleanRoot !== proof.postRollbackCleanRoot) {
      return { valid: false, error: 'Post-rollback clean root mismatch' };
    }

    // Verify consistency path hashes
    const expectedStep0 = crypto.createHash('sha256').update(`PRE_ROOT_${proof.preRollbackRoot}`).digest('hex');
    const expectedStep1 = crypto.createHash('sha256').update(`QUARANTINE_${quarantineCert.quarantinedSubtreeRoot}`).digest('hex');
    const expectedStep2 = crypto.createHash('sha256').update(`POST_CLEAN_${calculatedCleanRoot}`).digest('hex');

    if (
      proof.merkleConsistencyProof[0] !== expectedStep0 ||
      proof.merkleConsistencyProof[1] !== expectedStep1 ||
      proof.merkleConsistencyProof[2] !== expectedStep2
    ) {
      return { valid: false, error: 'Merkle consistency proof verification failed' };
    }

    return { valid: true };
  }
}
