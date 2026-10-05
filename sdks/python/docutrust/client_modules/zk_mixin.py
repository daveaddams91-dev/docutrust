from typing import Dict, Any, List, Optional, Union, Set, Tuple
import base64
import json

class ZkMixin:

    def zk_rollup_create_batch(
        self,
        initial_accounts: List[Dict[str, Any]],
        transactions: List[Dict[str, Any]],
        block_number: int = 1
    ) -> Dict[str, Any]:
        """Creates a compressed state diff rollup batch with a STARK validium proof."""
        from .zk_rollup import ZKRollupEngine
        return ZKRollupEngine.create_batch(initial_accounts, transactions, block_number)

    def zk_rollup_verify_batch(
        self,
        batch: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verifies the Validium ZK-Rollup batch state transition and STARK proof."""
        from .zk_rollup import ZKRollupEngine
        return ZKRollupEngine.verify_batch(batch)

    def zk_statemachine_create(
        self,
        creator_key_pair: Dict[str, str],
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Defines and initializes a verifiable ZK state machine specification."""
        from .zk_statemachine import ZKStateMachineEngine
        return ZKStateMachineEngine.create_state_machine(creator_key_pair, options)

    def zk_statemachine_execute_transition(
        self,
        spec: Dict[str, Any],
        current_state: Dict[str, Any],
        action: str,
        next_state: Dict[str, Any],
        prover_key_pair: Dict[str, str]
    ) -> Dict[str, Any]:
        """Executes a verifiable state transition with Fiat-Shamir execution trace ZK proof."""
        from .zk_statemachine import ZKStateMachineEngine
        return ZKStateMachineEngine.execute_transition(spec, current_state, action, next_state, prover_key_pair)

    def zk_statemachine_verify_transition(
        self,
        spec: Dict[str, Any],
        transition_record: Dict[str, Any],
        prover_public_key_hex: str
    ) -> bool:
        """Verifies zero-knowledge transition validity, signature, and state root consistency."""
        from .zk_statemachine import ZKStateMachineEngine
        return ZKStateMachineEngine.verify_transition(spec, transition_record, prover_public_key_hex)

    def zk_statemachine_dispute_transition(
        self,
        spec: Dict[str, Any],
        transition_record: Dict[str, Any],
        challenger_key_pair: Dict[str, str],
        dispute_reason: str = "INVALID_STATE_PRECONDITION"
    ) -> Dict[str, Any]:
        """Arbitrates an optimistic state transition challenge against the state machine rules."""
        from .zk_statemachine import ZKStateMachineEngine
        return ZKStateMachineEngine.dispute_transition(spec, transition_record, challenger_key_pair, dispute_reason)

    def zk_statemachine_settle_escrow(
        self,
        spec: Dict[str, Any],
        final_state_root: str,
        executor_did: str
    ) -> Dict[str, Any]:
        """Settles escrow balance and generates on-chain calldata."""
        from .zk_statemachine import ZKStateMachineEngine
        return ZKStateMachineEngine.settle_escrow(spec, final_state_root, executor_did)
