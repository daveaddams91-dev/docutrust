import { describe, it, expect } from 'vitest';
import { AgentContractEngine } from '../src/agent-contract';

describe('AgentContractEngine (v19.0.0)', () => {
  const principalDid = 'did:docutrust:enterprise:principal';
  const agentDid = 'did:docutrust:agent:deep_reasoner';

  it('should create verifiable agent task escrow contract', () => {
    const contract = AgentContractEngine.createContract(
      principalDid,
      agentDid,
      { taskType: 'ORACLE_PRICE_ATTESTATION', symbol: 'ETH/USD' },
      1000,
      500,
      3600
    );
    expect(contract.contractId.startsWith('agent_escrow_')).toBe(true);
    expect(contract.status).toBe('ACTIVE');
    expect(contract.bountyAmount).toBe(1000);
    expect(contract.agentStakeAmount).toBe(500);
  });

  it('should submit execution receipt and settle contract if unchallenged', () => {
    const contract = AgentContractEngine.createContract(
      principalDid,
      agentDid,
      { taskType: 'ORACLE_PRICE_ATTESTATION', symbol: 'ETH/USD' },
      1000,
      500,
      3600
    );

    const steps = [
      { action: 'QUERY_DEX_1', stateHash: '0x1111' },
      { action: 'QUERY_DEX_2', stateHash: '0x2222' },
      { action: 'AGGREGATE_MEDIAN', stateHash: '0x3333' }
    ];

    const { updatedContract, receipt } = AgentContractEngine.submitExecution(
      contract,
      { price: 3450.25, timestamp: 1770000000 },
      steps
    );

    expect(updatedContract.status).toBe('PENDING_CHALLENGE');
    expect(receipt.traceCommitmentHash).toBeDefined();

    const settlement = AgentContractEngine.settleContract(updatedContract, receipt);
    expect(settlement.settled).toBe(true);
    expect(settlement.updatedContract.status).toBe('SETTLED');
    expect(settlement.settledAmount).toBe(1000);
  });

  it('should detect fraud proof, slash agent stake and distribute to challenger', () => {
    const contract = AgentContractEngine.createContract(
      principalDid,
      agentDid,
      { taskType: 'ORACLE_PRICE_ATTESTATION', symbol: 'ETH/USD' },
      1000,
      500,
      3600
    );

    const steps = [
      { action: 'QUERY_DEX_1', stateHash: '0x1111' },
      { action: 'QUERY_DEX_2', stateHash: '0x2222' }
    ];

    const { updatedContract, receipt } = AgentContractEngine.submitExecution(
      contract,
      { price: 999999.00 },
      steps
    );

    // Challenger challenges step 1 with fraudulent expected state
    const dispute = {
      disputerDid: 'did:docutrust:challenger:watchdog',
      disputedStepIndex: 1,
      expectedStateHash: '0xCORRECT_LEGITIMATE_STATE',
      challengerBond: 100
    };

    const slashingResult = AgentContractEngine.verifyAndSlash(updatedContract, receipt, dispute);
    expect(slashingResult.slashed).toBe(true);
    expect(slashingResult.updatedContract.status).toBe('SLASHED');
    expect(slashingResult.slashingReceipt?.slashedAmount).toBe(500);
    expect(slashingResult.slashingReceipt?.slashedTo).toBe(dispute.disputerDid);
  });
});
