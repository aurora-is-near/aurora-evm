use crate::block::BlockEnv;
use crate::errors::InvalidTransaction;
use crate::evm_context::{EvmContext, InvalidEvmContext};
use crate::spec::Spec;
use crate::transaction::{Transaction, TxKind};

use aurora_evm::backend::{ApplyBackend, MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{
    MemoryStackState, PrecompileSet, StackExecutor, StackSubstateMetadata,
};
use primitive_types::{H160, U256};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Evm<'p, P: PrecompileSet> {
    block: BlockEnv,
    chain_id: Option<u64>,
    precompiles: &'p P,
    spec: Spec,
    state: BTreeMap<H160, MemoryAccount>,
    transactions: Vec<Transaction>,
}

impl<'p, P: PrecompileSet> Evm<'p, P> {
    #[must_use]
    pub const fn new(
        chain_id: Option<u64>,
        block: BlockEnv,
        transactions: Vec<Transaction>,
        spec: Spec,
        precompiles: &'p P,
        state: BTreeMap<H160, MemoryAccount>,
    ) -> Self {
        Self {
            block,
            chain_id,
            precompiles,
            spec,
            state,
            transactions,
        }
    }

    /// Get current EVM context for transaction
    #[must_use]
    pub fn get_current_context<'tx>(&self, tx: &'tx Transaction) -> EvmContext<'_, 'tx> {
        EvmContext::new(self.chain_id, &self.block, tx, &self.spec, None)
    }

    /// Get Environment EVM data in Memory - `MemoryVicinity`
    #[must_use]
    fn get_vicinity(&self, ctx: &EvmContext) -> MemoryVicinity {
        MemoryVicinity {
            gas_price: ctx.get_gas_price(),
            effective_gas_price: ctx.get_effective_gas_price(),
            origin: ctx.tx.caller,
            block_hashes: self.block.block_hashes.clone(),
            block_number: self.block.block_number,
            block_coinbase: self.block.block_coinbase,
            block_timestamp: self.block.block_timestamp,
            block_difficulty: self.block.block_difficulty,
            block_gas_limit: U256::from(self.block.block_gas_limit.unwrap_or_default()),
            chain_id: self.chain_id.map(U256::from).unwrap_or_default(),
            block_base_fee_per_gas: self.block.block_base_fee_per_gas,
            block_randomness: self.block.block_randomness,
            blob_gas_price: self
                .block
                .blob_excess_gas_and_price
                .map(|bgp| bgp.blob_gas_price),
            blob_hashes: ctx.tx.blob_versioned_hashes.clone(),
        }
    }

    /// Run EVM
    ///
    /// ## Errors
    /// Return EVM validation and run errors
    pub fn run(&mut self) -> Result<(), InvalidEvmContext> {
        let transactions = core::mem::take(&mut self.transactions);

        for tx in &transactions {
            let caller =
                self.state
                    .get(&tx.caller)
                    .ok_or(InvalidEvmContext::InvalidTransaction(
                        InvalidTransaction::CallerNotFound,
                    ))?;
            let ctx = self.get_current_context(tx);
            ctx.validate_tx()?.validate_required_funds(caller.balance)?;

            let vicinity = self.get_vicinity(&ctx);
            // TODO: extend results and error handling
            let _res = self.execute(&vicinity, tx);
        }

        self.transactions = transactions;
        Ok(())
    }

    /// Execute EVM
    ///
    /// ## Errors
    /// Return execution error
    ///
    /// TODO: manage EVM Exit reason and return it as part of the result
    pub fn execute(&mut self, vicinity: &MemoryVicinity, tx: &Transaction) -> Result<(), String> {
        let state = core::mem::take(&mut self.state);

        let mut backend = MemoryBackend::new(vicinity, state);
        let ctx = self.get_current_context(tx);

        let executor_state = MemoryStackState::new(
            StackSubstateMetadata::new(tx.gas_limit, &ctx.gas_config),
            &backend,
        );
        let mut executor =
            StackExecutor::new_with_precompiles(executor_state, &ctx.gas_config, self.precompiles);

        // Upfront gas reservation: `effective_gas_price * gas_limit` (+ blob data fee). The value
        // transfer is handled by `transact_*` below, so it is NOT part of the reservation.
        let data_fee = ctx.calc_data_fee();
        let total_fee = ctx.calc_total_charge_fee();
        executor
            .state_mut()
            .withdraw(tx.caller, total_fee)
            .map_err(|err| format!("fee withdrawal failed: {err:?}"))?;

        match tx.tx_kind {
            TxKind::Call(to) => {
                let _reason = executor.transact_call(
                    tx.caller,
                    to,
                    tx.value,
                    tx.data.clone(),
                    tx.gas_limit,
                    tx.access_list.flattened(),
                    tx.authorization_list.clone(),
                );
            }
            TxKind::Create => {
                let _reason = executor.transact_create(
                    tx.caller,
                    tx.value,
                    tx.data.clone(),
                    tx.gas_limit,
                    tx.access_list.flattened(),
                );
            }
        }

        // Settle gas after execution:
        // 1. Pay the coinbase; from London onward (EIP-1559) the base fee is burned, so it receives
        //    only the priority tip (`used_gas * (effective_gas_price - base_fee)`).
        // 2. Refund the caller the unused part of the reservation
        //    (`total_fee - actual_fee [- blob data fee]`).
        let effective_gas_price = vicinity.effective_gas_price;
        let actual_fee = executor.fee(effective_gas_price);
        let miner_reward = if self.spec > Spec::Berlin {
            let coinbase_gas_price =
                effective_gas_price.saturating_sub(vicinity.block_base_fee_per_gas);
            executor.fee(coinbase_gas_price)
        } else {
            actual_fee
        };
        executor
            .state_mut()
            .deposit(vicinity.block_coinbase, miner_reward);

        let caller_refund = data_fee.map_or(total_fee - actual_fee, |data_fee| {
            total_fee - actual_fee - data_fee
        });
        executor.state_mut().deposit(tx.caller, caller_refund);

        let (values, logs) = executor.into_state().deconstruct();
        backend.apply(values, logs, true);

        self.state = core::mem::take(backend.state_mut());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Evm;
    use crate::block::BlockEnv;
    use crate::precompiles::Precompiles;
    use crate::spec::Spec;
    use crate::transaction::{AccessList, Transaction, TxKind, TxType};
    use aurora_evm::backend::MemoryAccount;
    use primitive_types::{H160, H256, U256};
    use std::collections::BTreeMap;

    fn addr(byte: u8) -> H160 {
        H160::repeat_byte(byte)
    }

    fn account_with_balance(balance: u64) -> MemoryAccount {
        MemoryAccount {
            nonce: U256::zero(),
            balance: U256::from(balance),
            storage: BTreeMap::new(),
            code: vec![],
        }
    }

    fn london_block(base_fee: u64, coinbase: H160) -> BlockEnv {
        BlockEnv {
            block_hashes: vec![],
            block_number: U256::from(1u64),
            block_coinbase: coinbase,
            block_timestamp: U256::from(1u64),
            block_difficulty: U256::zero(),
            block_gas_limit: Some(30_000_000),
            block_base_fee_per_gas: U256::from(base_fee),
            block_randomness: Some(H256::zero()),
            blob_excess_gas_and_price: None,
            blob_hashes: vec![],
            parent_hash: H256::zero(),
            parent_beacon_block_root: None,
            withdrawals: vec![],
        }
    }

    /// A minimal EIP-1559 value transfer (empty calldata → a plain 21 000-gas send).
    fn transfer_tx(
        caller: H160,
        to: H160,
        value: U256,
        max_fee: u64,
        max_priority: Option<u64>,
    ) -> Transaction {
        Transaction {
            tx_type: TxType::Eip1559,
            tx_kind: TxKind::Call(to),
            caller,
            gas_limit: 100_000,
            value,
            data: vec![],
            nonce: U256::zero(),
            chain_id: Some(1),
            gas_price: None,
            max_fee_per_gas: Some(U256::from(max_fee)),
            max_priority_fee_per_gas: max_priority.map(U256::from),
            access_list: AccessList(vec![]),
            blob_versioned_hashes: vec![],
            max_fee_per_blob_gas: 0,
            authorization_list: vec![],
        }
    }

    fn balance_of(state: &BTreeMap<H160, MemoryAccount>, who: H160) -> U256 {
        state.get(&who).map(|acc| acc.balance).unwrap_or_default()
    }

    /// Executes a single transfer through `execute` and returns
    /// `(caller, to, coinbase, post_execution_state)`.
    fn run_transfer(
        base_fee: u64,
        max_fee: u64,
        max_priority: Option<u64>,
        value: U256,
        caller_balance: u64,
    ) -> (H160, H160, H160, BTreeMap<H160, MemoryAccount>) {
        const CHAIN_ID: u64 = 1;

        let caller = addr(0xca);
        let to = addr(0x2e);
        let coinbase = addr(0xcb);

        let mut state: BTreeMap<H160, MemoryAccount> = BTreeMap::new();
        state.insert(caller, account_with_balance(caller_balance));

        let block = london_block(base_fee, coinbase);
        let tx = transfer_tx(caller, to, value, max_fee, max_priority);
        let precompiles = Precompiles::new(&Spec::London);
        let mut evm = Evm::new(
            Some(CHAIN_ID),
            block,
            vec![tx.clone()],
            Spec::London,
            &precompiles,
            state,
        );

        // `get_vicinity` is private, so build it here (mirrors what `run` does per transaction).
        let vicinity = evm.get_vicinity(&evm.get_current_context(&tx));
        evm.execute(&vicinity, &tx).unwrap();

        (caller, to, coinbase, evm.state.clone())
    }

    #[test]
    fn execute_refunds_unused_gas_and_pays_coinbase() {
        // With `base_fee = 0` nothing is burned, so the balances are exactly conserved and the
        // coinbase receives the whole gas fee — this lets us assert the settlement without
        // depending on the exact `used_gas`.
        let transfer_amount = U256::from(1_000);
        let caller_balance = 10_000_000;
        // effective_gas_price = 12 (no base fee, no priority cap)
        let max_fee = 12;

        let (caller, to, coinbase, state) =
            run_transfer(0, max_fee, None, transfer_amount, caller_balance);

        let caller_final_balance = balance_of(&state, caller);
        let to_final_balance = balance_of(&state, to);
        let coinbase_final_balance = balance_of(&state, coinbase);
        let caller_initial_balance = U256::from(caller_balance);

        assert_eq!(to_final_balance, transfer_amount);
        // base_fee = 0, no burn - total balance is conserved.
        assert_eq!(
            caller_final_balance + to_final_balance + coinbase_final_balance,
            caller_initial_balance
        );
        // The coinbase is actually paid its gas fee.
        let gas_fee = U256::from(21000 * max_fee);
        assert_eq!(coinbase_final_balance, gas_fee);
        assert_eq!(
            caller_final_balance,
            caller_initial_balance - transfer_amount - gas_fee
        );
    }

    #[test]
    fn execute_burns_base_fee_london() {
        // effective = min(max_fee = 12, priority = 2 + base = 3) = 5; the coinbase receives only
        // the priority tip `used_gas * (5 - 3)`, while `used_gas * 3` is burned.
        let transfer_amount = U256::from(1_000);
        let caller_balance = 10_000_000;
        let max_fee = 12;
        let base_fee = 3;
        let max_priority = 2;

        let (caller, to, coinbase, state) = run_transfer(
            base_fee,
            max_fee,
            Some(max_priority),
            transfer_amount,
            caller_balance,
        );

        let caller_final_balance = balance_of(&state, caller);
        let to_final_balance = balance_of(&state, to);
        let coinbase_final_balance = balance_of(&state, coinbase);
        let caller_initial_balance = U256::from(caller_balance);

        assert_eq!(to_final_balance, transfer_amount);
        // The priority tip is paid to the coinbase.
        assert_eq!(coinbase_final_balance, U256::from(21000 * max_priority));
        // The caller pays the full effective gas fee `used_gas * effective_gas_price`, where
        // `effective_gas_price = min(max_fee, base_fee + max_priority)`. The coinbase keeps only
        // the priority tip (asserted above); the base-fee part (`used_gas * base_fee`) is burned.
        let effective_gas_price = base_fee + max_priority;
        let caller_gas_cost = U256::from(21000 * effective_gas_price);
        assert_eq!(
            caller_final_balance,
            caller_initial_balance - transfer_amount - caller_gas_cost
        );
    }

    /// A minimal *legacy* value transfer (carries `gas_price`, no EIP-1559 fee fields).
    fn legacy_transfer_tx(caller: H160, to: H160, value: U256, gas_price: u64) -> Transaction {
        Transaction {
            tx_type: TxType::Legacy,
            tx_kind: TxKind::Call(to),
            caller,
            gas_limit: 100_000,
            value,
            data: vec![],
            nonce: U256::zero(),
            chain_id: None,
            gas_price: Some(U256::from(gas_price)),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: AccessList(vec![]),
            blob_versioned_hashes: vec![],
            max_fee_per_blob_gas: 0,
            authorization_list: vec![],
        }
    }

    #[test]
    fn execute_charges_legacy_tx_on_london() {
        // Regression for fork-vs-type gas-price selection: on London+ a legacy tx carries
        // `gas_price`, not `max_fee_per_gas`. The old fork-only path returned `max_fee_per_gas`
        // (`None` → 0) for it, so the transaction was charged no gas at all.
        let caller = addr(0xca);
        let to = addr(0x2e);
        let coinbase = addr(0xcb);
        let transfer_amount = U256::from(1_000);
        let caller_balance = 10_000_000;
        let gas_price = 10;

        let mut state: BTreeMap<H160, MemoryAccount> = BTreeMap::new();
        state.insert(caller, account_with_balance(caller_balance));
        // base_fee = 0 - the coinbase receives the whole gas fee, so a non-zero balance there
        // proves gas was actually charged.
        let block = london_block(0, coinbase);
        let tx = legacy_transfer_tx(caller, to, transfer_amount, gas_price);
        let precompiles = Precompiles::new(&Spec::London);
        let mut evm = Evm::new(
            Some(1),
            block,
            vec![tx.clone()],
            Spec::London,
            &precompiles,
            state,
        );

        let vicinity = {
            let ctx = evm.get_current_context(&tx);
            evm.get_vicinity(&ctx)
        };
        evm.execute(&vicinity, &tx).unwrap();
        let state = evm.state.clone();

        let caller_final_balance = balance_of(&state, caller);
        let coinbase_final_balance = balance_of(&state, coinbase);
        let initial_caller_balance = U256::from(caller_balance);

        assert_eq!(balance_of(&state, to), transfer_amount);
        // A plain transfer costs the 21 000 intrinsic gas at the legacy `gas_price`; with
        // base_fee = 0 nothing is burned, so the coinbase collects the whole fee and the caller
        // pays exactly `transfer_amount + gas_cost`. (Under the old fork-only bug a London legacy
        // tx resolved to `max_fee_per_gas` = 0, so it would pay no gas and the coinbase would be 0.)
        let gas_cost = U256::from(21_000 * gas_price);
        assert_eq!(coinbase_final_balance, gas_cost);
        assert_eq!(
            caller_final_balance,
            initial_caller_balance - transfer_amount - gas_cost
        );
    }
}
