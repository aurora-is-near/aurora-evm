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
        let transactions = std::mem::take(&mut self.transactions);

        for tx in &transactions {
            let caller =
                self.state
                    .get(&tx.caller)
                    .ok_or(InvalidEvmContext::InvalidTransaction(
                        InvalidTransaction::CallerNotFound,
                    ))?;
            let ctx = self.get_current_context(tx);
            ctx.validate_tx()?;
            ctx.validate_required_funds(caller.balance)?;

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
        let state = std::mem::take(&mut self.state);

        let mut backend = MemoryBackend::new(vicinity, state);
        let ctx = self.get_current_context(tx);

        let executor_state = MemoryStackState::new(
            StackSubstateMetadata::new(tx.gas_limit, &ctx.gas_config),
            &backend,
        );
        let mut executor =
            StackExecutor::new_with_precompiles(executor_state, &ctx.gas_config, self.precompiles);

        let charge_fee = ctx.calc_total_charge_fee();
        // TODO: handle results and errors
        let _res = executor.state_mut().withdraw(tx.caller, charge_fee);

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

        let (values, logs) = executor.into_state().deconstruct();
        backend.apply(values, logs, true);

        self.state = std::mem::take(backend.state_mut());
        Ok(())
    }
}
