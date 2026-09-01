import * as crypto from 'crypto';

export interface AuctionTaskSpec {
  taskType: string;
  description: string;
  maxBudget: number;
  deadlineEpoch: number;
  requiredCapabilities: string[];
  validationRules?: Record<string, any>;
}

export interface SealedBidCommitment {
  commitmentId: string;
  auctionId: string;
  agentDid: string;
  commitmentHash: string;
  stakeLocked: number;
  committedAt: string;
}

export interface RevealedBid {
  commitmentId: string;
  auctionId: string;
  agentDid: string;
  bidAmount: number;
  stakeAmount: number;
  salt: string;
  qualityMetric?: number;
  revealedAt: string;
}

export interface AuctionClearingResult {
  auctionId: string;
  winnerAgentDid: string;
  winningBid: number;
  clearingPrice: number;
  totalBids: number;
  escrowLocked: number;
  clearingTimestamp: string;
  zkClearingProofHash: string;
}

export interface SettlementReceipt {
  settlementId: string;
  auctionId: string;
  winnerAgentDid: string;
  amountPaid: number;
  stakeReturned: number;
  executionReceiptId: string;
  settledAt: string;
}

export interface AgentAuctionState {
  auctionId: string;
  auctioneerDid: string;
  taskSpec: AuctionTaskSpec;
  status: 'OPEN' | 'BIDDING' | 'REVEAL' | 'CLEARED' | 'SETTLED' | 'SLASHED';
  commitments: SealedBidCommitment[];
  revealedBids: RevealedBid[];
  clearingResult?: AuctionClearingResult;
  settlementReceipt?: SettlementReceipt;
  createdAt: string;
}

export class AgentAuctionEngine {
  /**
   * Generates a sealed-bid commitment hash.
   */
  public static computeCommitmentHash(
    auctionId: string,
    agentDid: string,
    bidAmount: number,
    stakeAmount: number,
    salt: string
  ): string {
    const serialized = `${auctionId}:${agentDid}:${bidAmount}:${stakeAmount}:${salt}`;
    return crypto.createHash('sha256').update(serialized).digest('hex');
  }

  /**
   * Creates an autonomous capability auction.
   */
  public static createAuction(
    auctioneerDid: string,
    taskSpec: AuctionTaskSpec
  ): AgentAuctionState {
    const auctionId = `auction_${crypto.randomBytes(8).toString('hex')}`;
    return {
      auctionId,
      auctioneerDid,
      taskSpec,
      status: 'OPEN',
      commitments: [],
      revealedBids: [],
      createdAt: new Date().toISOString()
    };
  }

  /**
   * Commits a sealed bid with collateral stake.
   */
  public static commitBid(
    auction: AgentAuctionState,
    agentDid: string,
    bidAmount: number,
    stakeAmount: number,
    salt: string
  ): { updatedAuction: AgentAuctionState; commitment: SealedBidCommitment } {
    if (auction.status !== 'OPEN' && auction.status !== 'BIDDING') {
      throw new Error(`Cannot commit bid in status: ${auction.status}`);
    }

    const commitmentHash = this.computeCommitmentHash(auction.auctionId, agentDid, bidAmount, stakeAmount, salt);
    const commitmentId = `commit_${crypto.randomBytes(6).toString('hex')}`;

    const commitment: SealedBidCommitment = {
      commitmentId,
      auctionId: auction.auctionId,
      agentDid,
      commitmentHash,
      stakeLocked: stakeAmount,
      committedAt: new Date().toISOString()
    };

    const updatedAuction: AgentAuctionState = {
      ...auction,
      status: 'BIDDING',
      commitments: [...auction.commitments, commitment]
    };

    return { updatedAuction, commitment };
  }

  /**
   * Reveals a previously committed bid during the reveal window.
   */
  public static revealBid(
    auction: AgentAuctionState,
    commitmentId: string,
    agentDid: string,
    bidAmount: number,
    stakeAmount: number,
    salt: string,
    qualityMetric: number = 1.0
  ): { updatedAuction: AgentAuctionState; revealedBid: RevealedBid } {
    const commitment = auction.commitments.find(c => c.commitmentId === commitmentId && c.agentDid === agentDid);
    if (!commitment) {
      throw new Error(`Commitment ${commitmentId} not found for agent ${agentDid}`);
    }

    const expectedHash = this.computeCommitmentHash(auction.auctionId, agentDid, bidAmount, stakeAmount, salt);
    if (expectedHash !== commitment.commitmentHash) {
      throw new Error('Bid reveal commitment mismatch (tampered bid parameters or invalid salt).');
    }

    const revealedBid: RevealedBid = {
      commitmentId,
      auctionId: auction.auctionId,
      agentDid,
      bidAmount,
      stakeAmount,
      salt,
      qualityMetric,
      revealedAt: new Date().toISOString()
    };

    const updatedAuction: AgentAuctionState = {
      ...auction,
      status: 'REVEAL',
      revealedBids: [...auction.revealedBids.filter(b => b.commitmentId !== commitmentId), revealedBid]
    };

    return { updatedAuction, revealedBid };
  }

  /**
   * Clears the auction using Vickrey (second-price procurement) clearing rules.
   * For reverse auction (procurement), the lowest bid wins, and clearing price is the 2nd lowest bid.
   */
  public static clearAuction(auction: AgentAuctionState): { updatedAuction: AgentAuctionState; result: AuctionClearingResult } {
    if (auction.revealedBids.length === 0) {
      throw new Error('Cannot clear auction with 0 revealed bids.');
    }

    // Sort by bid amount ascending (lowest price first)
    const sorted = [...auction.revealedBids].sort((a, b) => a.bidAmount - b.bidAmount);
    const winner = sorted[0];

    // Second-price rule: if 2+ bids, clearing price = sorted[1].bidAmount; else = winningBid (or maxBudget)
    const secondPrice = sorted.length > 1
      ? Math.min(sorted[1].bidAmount, auction.taskSpec.maxBudget)
      : winner.bidAmount;

    const zkClearingProofHash = crypto.createHash('sha256')
      .update(`${auction.auctionId}:${winner.agentDid}:${winner.bidAmount}:${secondPrice}:${sorted.length}`)
      .digest('hex');

    const result: AuctionClearingResult = {
      auctionId: auction.auctionId,
      winnerAgentDid: winner.agentDid,
      winningBid: winner.bidAmount,
      clearingPrice: secondPrice,
      totalBids: sorted.length,
      escrowLocked: secondPrice,
      clearingTimestamp: new Date().toISOString(),
      zkClearingProofHash
    };

    const updatedAuction: AgentAuctionState = {
      ...auction,
      status: 'CLEARED',
      clearingResult: result
    };

    return { updatedAuction, result };
  }

  /**
   * Settles the auction and distributes payment to winning agent upon task completion receipt.
   */
  public static settleAuction(
    auction: AgentAuctionState,
    clearingResult: AuctionClearingResult,
    executionReceiptId: string
  ): { updatedAuction: AgentAuctionState; receipt: SettlementReceipt } {
    if (auction.status !== 'CLEARED') {
      throw new Error(`Cannot settle auction in state: ${auction.status}`);
    }

    const winnerBid = auction.revealedBids.find(b => b.agentDid === clearingResult.winnerAgentDid);
    const stakeToReturn = winnerBid ? winnerBid.stakeAmount : 0;

    const settlementId = `settle_${crypto.randomBytes(6).toString('hex')}`;
    const receipt: SettlementReceipt = {
      settlementId,
      auctionId: auction.auctionId,
      winnerAgentDid: clearingResult.winnerAgentDid,
      amountPaid: clearingResult.clearingPrice,
      stakeReturned: stakeToReturn,
      executionReceiptId,
      settledAt: new Date().toISOString()
    };

    const updatedAuction: AgentAuctionState = {
      ...auction,
      status: 'SETTLED',
      settlementReceipt: receipt
    };

    return { updatedAuction, receipt };
  }

  /**
   * Slashes winning agent collateral if fraud proof is upheld.
   */
  public static slashAuction(
    auction: AgentAuctionState,
    disputeProof: { disputeReason: string; challengerDid: string; evidenceHash: string }
  ): { updatedAuction: AgentAuctionState; slashedAmount: number; slashingReceipt: any } {
    const winnerBid = auction.revealedBids.find(b => b.agentDid === auction.clearingResult?.winnerAgentDid);
    const slashedAmount = winnerBid ? winnerBid.stakeAmount : 0;

    const slashingReceipt = {
      slashingId: `slash_${crypto.randomBytes(6).toString('hex')}`,
      auctionId: auction.auctionId,
      slashedAgentDid: auction.clearingResult?.winnerAgentDid,
      slashedAmount,
      challengerDid: disputeProof.challengerDid,
      disputeReason: disputeProof.disputeReason,
      timestamp: new Date().toISOString()
    };

    const updatedAuction: AgentAuctionState = {
      ...auction,
      status: 'SLASHED'
    };

    return { updatedAuction, slashedAmount, slashingReceipt };
  }
}
