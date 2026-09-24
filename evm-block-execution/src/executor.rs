//! Ethereum block execution over witness-backed state.
//!
//! [`BlockExecutor`] owns a block's execution inputs and its [`WitnessBackend`]. It runs the
//! pre-execution system calls, executes every transaction in order, gathers the EIP-7685 requests
//! and credits withdrawals, creating an [`aurora_evm`] executor for each step. Consuming it keeps a
//! failed block's partial state inaccessible.
//!
//! Consensus structure and senders must already be validated.
//!
//! Each transaction is validated, executed and fee-settled before its typed [`Receipt`] advances
//! the block totals.

use crate::block::{BlockEnv, post_block_balance_increments};
use crate::chain_spec::{ActiveSpec, ChainSpec};
use crate::eips::eip4844::DATA_GAS_PER_BLOB;
use crate::eips::eip6110::{MAINNET_DEPOSIT_CONTRACT_ADDRESS, parse_deposits_from_receipts};
use crate::eips::eip7840::BlobParams;
use crate::errors::BlockExecutionError;
use crate::errors::InvalidTransaction;
use crate::evm_context::{EvmContext, InvalidEvmContext};
use crate::execution_types::execution::{BlockExecutionOutput, BlockExecutionResult};
use crate::precompiles::Precompiles;
use crate::receipt::Receipt;
use crate::requests::{Requests, request_type};
use crate::spec::Spec;
use crate::system_calls::{
    self, BEACON_ROOTS_ADDRESS, CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS, HISTORY_STORAGE_ADDRESS,
    SYSTEM_ADDRESS, SystemCallOutcome, WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
};
use crate::transaction::{TxEnv, TxKind};
use crate::witness_backend::WitnessBackend;
use aurora_evm::ExitReason;
use aurora_evm::backend::{ApplyBackend, Backend, Log, MemoryVicinity};
use aurora_evm::executor::stack::{
    Authorization, MemoryStackState, StackExecutor, StackSubstateMetadata,
};

use primitive_types::{H160, H256, U256};

#[cfg(test)]
mod tests;

/// EIP-3860 maximum init-code size (`2 * MAX_CODE_SIZE`, where `MAX_CODE_SIZE = 24576`).
const MAX_INITCODE_SIZE: usize = 2 * 0x6000;

/// Executes one block against witness-backed state.
pub struct BlockExecutor {
    block: BlockEnv,
    chain: ChainSpec,
    /// Execution fork resolved from the block timestamp within the configured boundary.
    active_spec: Spec,
    precompiles: Precompiles,
    /// The [`BlobParams`] resolved once from the chain schedule for this block.
    blob_params: Option<BlobParams>,
    backend: WitnessBackend,
    transactions: Vec<TxEnv>,
}

/// Result of executing one transaction, before it becomes a [`Receipt`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxExecutionOutcome {
    /// The EVM exit reason (`Succeed`/`Revert`/`Error`; `Fatal` aborts the block instead).
    pub reason: ExitReason,
    /// Gas used by the transaction.
    pub gas_used: u64,
    /// Logs emitted by the transaction (empty on revert).
    pub logs: Vec<Log>,
}

/// Receipts and gas totals produced by the block's transaction phase.
struct BlockTransactionsResult {
    /// Per-transaction receipts, in block order.
    receipts: Vec<Receipt>,
    /// Total gas used by the block (final `cumulative_gas_used`).
    gas_used: u64,
    /// Total blob gas used by the block.
    blob_gas_used: u64,
}

/// Running gas and blob totals for transactions already executed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BlockExecutionCounters {
    /// Gas consumed by the transactions executed so far.
    gas_used: u64,
    /// Blobs carried by the transactions executed so far.
    blob_count: u64,
}

/// A validated transaction with values reused during execution.
struct ValidatedTransaction {
    tx: TxEnv,
    gas_price: U256,
    effective_gas_price: U256,
    data_fee: Option<U256>,
    blob_count: u64,
}

impl BlockExecutor {
    /// Builds an executor and resolves the active fork and [`BlobParams`] from the block timestamp.
    ///
    /// The backend's block-level environment is set from `block`; only its state is taken as given.
    ///
    /// # Errors
    /// [`BlockExecutionError::InvalidBlockTimestamp`] if the timestamp does not fit in `u64`, or
    /// [`BlockExecutionError::ActiveSpecUnavailable`] if a Cancun-or-later configuration has no
    /// supported fork active at that timestamp.
    pub fn new(
        chain: ChainSpec,
        block: BlockEnv,
        transactions: Vec<TxEnv>,
        backend: WitnessBackend,
    ) -> Result<Self, BlockExecutionError> {
        let (active_spec, blob_params) = resolve_execution_context(&chain, &block)?;
        Ok(Self::new_with_execution_context(
            chain,
            block,
            transactions,
            backend,
            active_spec,
            blob_params,
        ))
    }

    /// Builds an executor for a fork the consensus validation has already resolved.
    #[must_use]
    pub fn new_with_active_spec(
        chain: ChainSpec,
        block: BlockEnv,
        transactions: Vec<TxEnv>,
        backend: WitnessBackend,
        active_spec: ActiveSpec,
    ) -> Self {
        Self::new_with_execution_context(
            chain,
            block,
            transactions,
            backend,
            active_spec.spec(),
            Some(active_spec.blob_params()),
        )
    }

    fn new_with_execution_context(
        chain: ChainSpec,
        block: BlockEnv,
        transactions: Vec<TxEnv>,
        mut backend: WitnessBackend,
        active_spec: Spec,
        blob_params: Option<BlobParams>,
    ) -> Self {
        // One source for the block-level environment: the backend serves what `block` says.
        *backend.vicinity_mut() = block.vicinity(chain.chain_id);
        let precompiles = Precompiles::new(&active_spec);
        Self {
            block,
            chain,
            active_spec,
            precompiles,
            blob_params,
            backend,
            transactions,
        }
    }

    /// Executes the block: system calls, every transaction in order, requests and withdrawals.
    ///
    /// Consuming `self` prevents observing the partial state of a failed block. The state is only
    /// handed out if every read it was derived from was proven by the witness.
    ///
    /// # Errors
    /// Returns [`BlockExecutionError`] for the first invalid or fatally failing transaction, a
    /// failed request contract call, an invalid deposit log or an unproven state read, and aborts
    /// the block.
    pub fn execute(mut self) -> Result<BlockExecutionOutput, BlockExecutionError> {
        let result = self.execute_one();
        // An unproven read explains every later failure (a zero balance, an empty contract), so the
        // witness gap is reported first: the block is unprovable, not known to be invalid.
        let unproven = self.backend.missing();
        let result = match (result, unproven) {
            (_, Some(missing)) => return Err(missing.into()),
            (Err(error), None) => return Err(error),
            (Ok(result), None) => result,
        };
        let state = self.backend.try_into_state()?;
        Ok(BlockExecutionOutput { result, state })
    }

    /// The phases in protocol order; `execute` decides how a failure is reported.
    fn execute_one(&mut self) -> Result<BlockExecutionResult, BlockExecutionError> {
        self.apply_pre_execution_changes()?;

        let block_txs_result = self.execute_transactions()?;
        let requests = self.apply_post_execution_changes(&block_txs_result.receipts)?;
        let increments = post_block_balance_increments(self.active_spec, &self.block.withdrawals);
        self.backend.increment_balances(&increments);

        Ok(BlockExecutionResult {
            receipts: block_txs_result.receipts,
            requests,
            gas_used: block_txs_result.gas_used,
            blob_gas_used: block_txs_result.blob_gas_used,
        })
    }

    /// EIP-2935 and EIP-4788 calls; ordinary EVM failures are ignored, fatal errors are not.
    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        // Genesis has no parent to record.
        if self.block.block_number.is_zero() {
            return Ok(());
        }

        self.apply_blockhashes_contract_call()?;
        self.apply_beacon_root_contract_call()?;
        self.check_witness()
    }

    /// EIP-2935: stores the parent hash in the history contract (Prague+).
    fn apply_blockhashes_contract_call(&mut self) -> Result<(), BlockExecutionError> {
        if self.active_spec >= Spec::Prague {
            let parent_hash = self.block.parent_hash;
            let outcome =
                self.transact_system_call(HISTORY_STORAGE_ADDRESS, parent_hash.as_bytes().to_vec());
            self.check_pre_execution_outcome(outcome)?;
        }
        Ok(())
    }

    /// EIP-4788: stores the parent beacon block root in the beacon-roots contract (Cancun+).
    fn apply_beacon_root_contract_call(&mut self) -> Result<(), BlockExecutionError> {
        if self.active_spec < Spec::Cancun {
            return Ok(());
        }
        let root = self
            .block
            .parent_beacon_block_root
            .ok_or(BlockExecutionError::MissingParentBeaconBlockRoot)?;
        let outcome = self.transact_system_call(BEACON_ROOTS_ADDRESS, root.as_bytes().to_vec());
        self.check_pre_execution_outcome(outcome)
    }

    /// Rejects internal EVM failures while preserving the first witness error.
    fn check_pre_execution_outcome(
        &self,
        outcome: SystemCallOutcome,
    ) -> Result<(), BlockExecutionError> {
        self.check_witness()?;
        if outcome.reason.is_fatal() {
            return Err(BlockExecutionError::ExecutionFailed(outcome.reason));
        }
        Ok(())
    }

    /// Executes every transaction in order and returns receipts and totals.
    fn execute_transactions(&mut self) -> Result<BlockTransactionsResult, BlockExecutionError> {
        // Taken out rather than destructured, because the two stages below are methods: everything
        // they read stays behind `self`, and only the list being walked has to move.
        let transactions = core::mem::take(&mut self.transactions);

        let mut receipts = Vec::with_capacity(transactions.len());
        let mut counters = BlockExecutionCounters::default();

        for (index, tx) in transactions.into_iter().enumerate() {
            // Both stages are tagged with the position, because "this block is invalid" without
            // saying *which* transaction made it so is almost useless when reconciling with another
            // client.
            let validated_tx = self
                .validate_transaction_for_block(tx, counters)
                .map_err(|source| BlockExecutionError::at_transaction(index, source))?;
            self.check_witness()?;
            let tx_type = validated_tx.tx.tx_type;
            let tx_blob_count = validated_tx.blob_count;

            let outcome = self
                .execute_validated_tx(validated_tx)
                .map_err(|source| BlockExecutionError::at_transaction(index, source))?;
            self.check_witness()?;

            // Validation and the executor's gas-limit contract bound this sum for valid input;
            // saturation keeps a broken upstream invariant from wrapping the block total.
            counters.gas_used = counters.gas_used.saturating_add(outcome.gas_used);
            // The trusted schedule keeps `max_blob_count` below `u64::MAX`; validation has bounded
            // this sum by that maximum before execution.
            counters.blob_count += tx_blob_count;

            // `Fatal` was already turned into an error inside `execute_validated_tx`; here `reason`
            // is `Succeed`/`Revert`/`Error`, and only `Succeed` yields a success receipt.
            let success = outcome.reason.is_succeed();
            receipts.push(Receipt::new(
                tx_type,
                success,
                counters.gas_used,
                outcome.logs,
            ));
        }

        Ok(BlockTransactionsResult {
            receipts,
            gas_used: counters.gas_used,
            blob_gas_used: counters.blob_count.saturating_mul(DATA_GAS_PER_BLOB),
        })
    }

    /// EIP-7685 requests (Prague+): deposits parsed from the receipts, then the EIP-7002 and
    /// EIP-7251 contract calls.
    fn apply_post_execution_changes(
        &mut self,
        receipts: &[Receipt],
    ) -> Result<Requests, BlockExecutionError> {
        let mut requests = Requests::new();
        if self.active_spec < Spec::Prague {
            return Ok(requests);
        }

        let deposit_contract = self
            .chain
            .deposit_contract_address
            .unwrap_or(MAINNET_DEPOSIT_CONTRACT_ADDRESS);
        let deposit_requests = parse_deposits_from_receipts(receipts, deposit_contract)?;
        if !deposit_requests.is_empty() {
            requests.push_request_with_type(request_type::DEPOSIT, deposit_requests);
        }

        let withdrawal_requests = self.apply_withdrawal_requests_contract_call()?;
        if !withdrawal_requests.is_empty() {
            requests.push_request_with_type(request_type::WITHDRAWAL, withdrawal_requests);
        }

        let consolidation_requests = self.apply_consolidation_requests_contract_call()?;
        if !consolidation_requests.is_empty() {
            requests.push_request_with_type(request_type::CONSOLIDATION, consolidation_requests);
        }

        Ok(requests)
    }

    /// EIP-7002: calls the withdrawal-requests contract; its output is the request data.
    fn apply_withdrawal_requests_contract_call(&mut self) -> Result<Vec<u8>, BlockExecutionError> {
        self.apply_requests_contract_call(WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS, |reason| {
            BlockExecutionError::WithdrawalRequestsContractCall { reason }
        })
    }

    /// EIP-7251: calls the consolidation-requests contract; its output is the request data.
    fn apply_consolidation_requests_contract_call(
        &mut self,
    ) -> Result<Vec<u8>, BlockExecutionError> {
        self.apply_requests_contract_call(CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS, |reason| {
            BlockExecutionError::ConsolidationRequestsContractCall { reason }
        })
    }

    /// Calls a request contract. Unlike the pre-execution calls it must succeed: an empty
    /// contract or a reverted, halted or fatally failing call invalidates the block.
    fn apply_requests_contract_call(
        &mut self,
        address: H160,
        failure: fn(ExitReason) -> BlockExecutionError,
    ) -> Result<Vec<u8>, BlockExecutionError> {
        if self.backend.code(address).is_empty() {
            // An unrevealed contract also reads as empty; the witness gap is the real cause.
            self.check_witness()?;
            return Err(BlockExecutionError::SystemContractEmpty { address });
        }

        let outcome = self.transact_system_call(address, Vec::new());
        self.check_witness()?;
        if !outcome.reason.is_succeed() {
            return Err(failure(outcome.reason));
        }

        Ok(outcome.output)
    }

    /// Runs one system call with the protocol's caller and fee-less environment.
    fn transact_system_call(&mut self, target: H160, data: Vec<u8>) -> SystemCallOutcome {
        TxVicinity {
            gas_price: U256::zero(),
            effective_gas_price: U256::zero(),
            origin: SYSTEM_ADDRESS,
            blob_hashes: Vec::new(),
        }
        .apply(self.backend.vicinity_mut());
        system_calls::transact_system_call(
            &mut self.backend,
            &self.precompiles,
            self.active_spec,
            target,
            data,
        )
    }

    /// Fails as soon as a phase has read state the witness did not prove.
    fn check_witness(&self) -> Result<(), BlockExecutionError> {
        self.backend
            .missing()
            .map_or(Ok(()), |missing| Err(missing.into()))
    }

    /// Validates a transaction against the current block, chain and sender state.
    ///
    /// # Errors
    /// [`BlockExecutionError`] naming the rule the transaction breaks.
    fn validate_transaction_for_block(
        &self,
        tx: TxEnv,
        counters: BlockExecutionCounters,
    ) -> Result<ValidatedTransaction, BlockExecutionError> {
        // 1. Sender snapshot. An absent account is the protocol-empty account (nonce 0, balance 0, no
        //    code) — not an error. (Missing *witness* data is recorded by the backend.)
        let sender = self.backend.basic(tx.caller);
        let sender_code = self.backend.code(tx.caller);
        let sender_is_delegated = is_delegated_sender(&sender_code, self.active_spec);

        // 2. Nonce equality. EIP-2681 also rejects `u64::MAX`: it could never be incremented.
        if tx.nonce != sender.nonce || tx.nonce >= U256::from(u64::MAX) {
            return Err(BlockExecutionError::InvalidNonce {
                tx: tx.nonce,
                state: sender.nonce,
            });
        }

        // 3. EIP-3607: the sender must not have non-delegation code.
        if !sender_code.is_empty() && !sender_is_delegated {
            return Err(BlockExecutionError::SenderHasCode);
        }

        // 4. EIP-3860 (Shanghai+): a contract-creation transaction's init code is size-capped. This is
        //    a transaction-validity rule, distinct from the in-EVM `CREATE` init-code halt.
        if self.active_spec >= Spec::Shanghai
            && tx.tx_kind.is_create()
            && tx.data.len() > MAX_INITCODE_SIZE
        {
            return Err(BlockExecutionError::InitCodeTooLarge);
        }

        // 5. Cheap per-transaction blob-count gate BEFORE the O(N) version-hash loop inside
        //    `validate_tx` (defense-in-depth on adversarial input). The active limit exists only when
        //    blob parameters resolve; a blob transaction without them is rejected below.

        // adversarially large input is a block failure, not a panic
        let blob_count = u64::try_from(tx.blob_versioned_hashes.len()).unwrap_or(u64::MAX);
        if blob_count > 0
            && let Some(params) = self.blob_params
            && blob_count > params.max_blobs_per_tx
        {
            return Err(BlockExecutionError::TooManyBlobsInTransaction {
                count: blob_count,
                max: params.max_blobs_per_tx,
            });
        }

        // 6. Full per-transaction context validation (including intrinsic / floor gas) and
        //    required-funds (reserved by the *maximum* fee).
        let ctx = EvmContext::new(
            self.chain.chain_id,
            &self.block,
            &tx,
            &self.active_spec,
            None,
        );
        ctx.validate_tx()?;
        ctx.validate_required_funds(sender.balance)?;

        // 7. The transaction's gas limit must fit in the block's remaining gas. `block_gas_limit` is a
        //    mandatory `u64`, so this consensus check is always enforced (no fail-open).
        let available_gas = self.block.block_gas_limit.saturating_sub(counters.gas_used);
        if tx.gas_limit > available_gas {
            return Err(BlockExecutionError::BlockGasLimitExceeded {
                tx_gas_limit: tx.gas_limit,
                available_gas,
            });
        }

        // 8. Per-block blob limit against the active `BlobParams`.
        //
        //    A blob transaction without resolved parameters is rejected rather than silently
        //    skipping the block limit. This covers both pre-Cancun input and an incomplete trusted
        //    Cancun-and-later configuration.
        if blob_count > 0 {
            let params = self.blob_params.ok_or(BlockExecutionError::InvalidContext(
                InvalidEvmContext::InvalidTransaction(InvalidTransaction::Eip4844NotSupported),
            ))?;
            let next_blob_count = counters.blob_count.saturating_add(blob_count);
            if next_blob_count > params.max_blob_count {
                return Err(BlockExecutionError::BlockBlobLimitExceeded {
                    count: next_blob_count,
                    max: params.max_blob_count,
                });
            }
        }

        let gas_price = ctx.get_gas_price();
        let effective_gas_price = ctx.get_effective_gas_price();
        let data_fee = ctx.calc_data_fee();

        Ok(ValidatedTransaction {
            tx,
            gas_price,
            effective_gas_price,
            data_fee,
            blob_count,
        })
    }

    /// Executes one validated transaction and settles its fees.
    ///
    /// # Errors
    /// [`BlockExecutionError`] if fee reservation fails or the executor exits fatally.
    fn execute_validated_tx(
        &mut self,
        validated_tx: ValidatedTransaction,
    ) -> Result<TxExecutionOutcome, BlockExecutionError> {
        let ValidatedTransaction {
            tx,
            effective_gas_price,
            data_fee,
            gas_price,
            ..
        } = validated_tx;
        // Destructured rather than read field by field, so the owned parts the executor consumes
        // (`data`, the access list, blob hashes and authorizations) move out instead of being cloned.
        let TxEnv {
            caller,
            value,
            gas_limit,
            tx_kind,
            data,
            access_list,
            blob_versioned_hashes,
            authorization_list,
            ..
        } = tx;

        TxVicinity {
            gas_price,
            effective_gas_price,
            origin: caller,
            blob_hashes: blob_versioned_hashes,
        }
        .apply(self.backend.vicinity_mut());

        let exec = TxExec {
            caller,
            value,
            gas_limit,
            tx_kind,
            data,
            access_list,
            authorization_list,
            effective_gas_price,
            reserve_fee: reserve_fee(effective_gas_price, gas_limit, data_fee),
            data_fee,
            base_fee: self.block.block_base_fee_per_gas,
            coinbase: self.block.block_coinbase,
            spec: self.active_spec,
            precompiles: &self.precompiles,
        };

        // On any error the executor substate is dropped without `apply`, so the backend still holds
        // the untouched pre-transaction state; on success `apply` has written the post-transaction
        // state.
        exec_tx_with_backend(&mut self.backend, exec)
    }
}

/// Resolves the execution fork and blob parameters without truncating the block timestamp.
///
/// # Errors
/// [`BlockExecutionError::InvalidBlockTimestamp`] if the timestamp does not fit in `u64`, or
/// [`BlockExecutionError::ActiveSpecUnavailable`] when a Cancun-or-later configuration has no
/// supported fork active at that timestamp.
fn resolve_execution_context(
    chain: &ChainSpec,
    block: &BlockEnv,
) -> Result<(Spec, Option<BlobParams>), BlockExecutionError> {
    let timestamp = u64::try_from(block.block_timestamp)
        .map_err(|_| BlockExecutionError::InvalidBlockTimestamp)?;
    if chain.spec < Spec::Cancun {
        return Ok((chain.spec, None));
    }
    chain
        .active_spec_at_timestamp(timestamp)
        .map(|active| (active.spec(), Some(active.blob_params())))
        .ok_or(BlockExecutionError::ActiveSpecUnavailable { timestamp })
}

/// Whether Prague permits the sender's EIP-7702 delegation code (`0xef0100 || address`).
fn is_delegated_sender(code: &[u8], spec: Spec) -> bool {
    spec >= Spec::Prague && Authorization::is_delegated(code)
}

/// Owned inputs one validated transaction hands to [`exec_tx_with_backend`].
struct TxExec<'a> {
    caller: H160,
    value: U256,
    gas_limit: u64,
    tx_kind: TxKind,
    data: Vec<u8>,
    access_list: Vec<(H160, Vec<H256>)>,
    authorization_list: Vec<Authorization>,
    effective_gas_price: U256,
    reserve_fee: U256,
    data_fee: Option<U256>,
    base_fee: U256,
    coinbase: H160,
    spec: Spec,
    precompiles: &'a Precompiles,
}

/// Up-front fee reservation: gas fee at the effective price plus any blob data fee (never `value`).
fn reserve_fee(effective_gas_price: U256, gas_limit: u64, data_fee: Option<U256>) -> U256 {
    let gas_fee = effective_gas_price.saturating_mul(U256::from(gas_limit));
    data_fee.map_or(gas_fee, |fee| gas_fee.saturating_add(fee))
}

/// Caller gas refund: reserved fee minus the fee actually charged minus the non-refundable blob fee.
fn caller_refund(reserve_fee: U256, actual_fee: U256, data_fee: Option<U256>) -> U256 {
    reserve_fee
        .saturating_sub(actual_fee)
        .saturating_sub(data_fee.unwrap_or_default())
}

/// Reserves fees, executes one validated transaction, settles fees and applies its state diff.
fn exec_tx_with_backend<B: Backend + ApplyBackend>(
    backend: &mut B,
    exec: TxExec<'_>,
) -> Result<TxExecutionOutcome, BlockExecutionError> {
    let gas_config = exec.spec.get_gasometer_config();
    let metadata = StackSubstateMetadata::new(exec.gas_limit, &gas_config);
    let executor_state = MemoryStackState::new(metadata, backend);
    let mut executor =
        StackExecutor::new_with_precompiles(executor_state, &gas_config, exec.precompiles);

    // Reserve the fee. Balance was already validated by the maximum fee, so a failure here is a
    // broken invariant rather than a user error.
    executor
        .state_mut()
        .withdraw(exec.caller, exec.reserve_fee)
        .map_err(|err| BlockExecutionError::ExecutionFailed(err.into()))?;

    let (reason, _) = match exec.tx_kind {
        TxKind::Call(to) => executor.transact_call(
            exec.caller,
            to,
            exec.value,
            exec.data,
            exec.gas_limit,
            exec.access_list,
            exec.authorization_list,
        ),
        TxKind::Create => executor.transact_create(
            exec.caller,
            exec.value,
            exec.data,
            exec.gas_limit,
            exec.access_list,
        ),
    };

    // A `Fatal` exit (or any broken internal invariant) aborts the whole block.
    if reason.is_fatal() {
        return Err(BlockExecutionError::ExecutionFailed(reason));
    }

    // Settle after execution: pay the coinbase the priority tip (from London the base fee is
    // burned), refund the caller its unused gas, burn the blob fee.
    let gas_used = executor.used_gas();
    let actual_fee = executor.fee(exec.effective_gas_price);
    let miner_reward = if exec.spec >= Spec::London {
        executor.fee(exec.effective_gas_price.saturating_sub(exec.base_fee))
    } else {
        actual_fee
    };
    executor.state_mut().deposit(exec.coinbase, miner_reward);

    let refund = caller_refund(exec.reserve_fee, actual_fee, exec.data_fee);
    executor.state_mut().deposit(exec.caller, refund);

    let (values, logs) = executor.into_state().deconstruct();
    // Collect receipt logs before applying state changes to the backend.
    let logs: Vec<Log> = logs.into_iter().collect();
    backend.apply(values, core::iter::empty::<Log>(), true);

    Ok(TxExecutionOutcome {
        reason,
        gas_used,
        logs,
    })
}

/// Per-transaction [`MemoryVicinity`] fields overwritten before every execution.
///
/// Grouping and exhaustively applying them prevents values, notably blob hashes, leaking from the
/// previous transaction into the next one or into a system call.
struct TxVicinity {
    /// Price the caller offered (`gas_price`, or `max_fee_per_gas` for the dynamic-fee types).
    gas_price: U256,
    /// Price actually charged, after the base fee.
    effective_gas_price: U256,
    /// `ORIGIN`: the transaction's sender.
    origin: H160,
    /// EIP-4844 blob versioned hashes, which `BLOBHASH` indexes.
    blob_hashes: Vec<U256>,
}

impl TxVicinity {
    /// Overwrites every per-transaction field of `vicinity`.
    fn apply(self, vicinity: &mut MemoryVicinity) {
        let Self {
            gas_price,
            effective_gas_price,
            origin,
            blob_hashes,
        } = self;
        vicinity.gas_price = gas_price;
        vicinity.effective_gas_price = effective_gas_price;
        vicinity.origin = origin;
        vicinity.blob_hashes = blob_hashes;
    }
}
