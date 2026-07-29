//! Block-level transaction execution: validation, fee settlement and the transaction loop.
//!
//! [`Evm`] owns the block environment, the resolved precompile set and the world state, and runs
//! every transaction in order through [`Evm::execute_transactions`]. Each transaction goes through
//! three stages:
//!
//! 1. **Validation against state** ([`validate_transaction_against_state`]) — nonce equality,
//!    EIP-3607 (sender not a contract), EIP-3860 (init-code size), the per-transaction
//!    [`EvmContext`] checks and required-funds (by the *maximum* fee), remaining block gas, and the
//!    per-transaction / per-block blob limits from the active [`BlobParams`](crate::blob::BlobParams).
//!    An invalid transaction fails the whole block; no state is mutated.
//! 2. **Execution + fee settlement** — the gas fee is reserved up front (`effective * gas_limit`
//!    plus the blob fee, **without** `value`), the call/create runs (the value transfer happens
//!    there), then the coinbase receives the priority tip, the caller is refunded the unused gas,
//!    and the base fee and blob fee are burned. This mirrors the proven `evm-tests` model.
//! 3. **Accounting + receipt** — cumulative gas / blob counts are updated with checked arithmetic
//!    and a typed [`Receipt`] is built from the execution outcome.
//!
//! The driver consumes `self` and keeps the world state in a local owned map, so a failed block
//! never leaves an observable half-executed `Evm`.

use crate::blob::{BlobSchedule, GAS_PER_BLOB};
use crate::block::BlockEnv;
use crate::errors::BlockExecutionError;
use crate::evm_context::EvmContext;
use crate::precompiles::Precompiles;
use crate::receipt::Receipt;
use crate::spec::Spec;
use crate::transaction::{Transaction, TxKind};
use aurora_evm::ExitReason;
use aurora_evm::backend::{ApplyBackend, Log, MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{
    Authorization, MemoryStackState, StackExecutor, StackSubstateMetadata,
};

use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

/// EIP-3860 maximum init-code size (`2 * MAX_CODE_SIZE`, where `MAX_CODE_SIZE = 24576`).
const MAX_INITCODE_SIZE: usize = 2 * 0x6000;

/// Block execution engine over a concrete precompile set and an in-memory world state.
pub struct Evm {
    block: BlockEnv,
    chain_id: Option<u64>,
    precompiles: Precompiles,
    spec: Spec,
    state: BTreeMap<H160, MemoryAccount>,
    transactions: Vec<Transaction>,
}

/// Outcome of the transaction loop: the collected receipts, block gas / blob-gas totals and the
/// post-execution world state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionExecutionResult {
    /// Per-transaction receipts, in block order.
    pub receipts: Vec<Receipt>,
    /// Total gas used by the block (final `cumulative_gas_used`).
    pub gas_used: u64,
    /// Total blob gas used by the block.
    pub blob_gas_used: u64,
    /// Post-execution world state.
    pub state: BTreeMap<H160, MemoryAccount>,
}

/// Result of executing one transaction, before it becomes a [`Receipt`]. Internal to the
/// crate (never part of the public API).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxExecutionOutcome {
    /// The EVM exit reason (`Succeed`/`Revert`/`Error`; `Fatal` aborts the block instead).
    pub reason: ExitReason,
    /// Gas used by the transaction.
    pub gas_used: u64,
    /// Logs emitted by the transaction (empty on revert).
    pub logs: Vec<Log>,
}

/// A transaction that passed [`validate_transaction_against_state`], carrying the values the
/// execution stage would otherwise recompute (fees, flattened access list, blob count).
struct ValidatedTransaction {
    tx: Transaction,
    access_list: Vec<(H160, Vec<H256>)>,
    gas_price: U256,
    effective_gas_price: U256,
    /// Blob data fee at the block's *current* blob price (burned, never refunded); `None` if not a
    /// blob transaction.
    data_fee: Option<U256>,
    blob_count: u64,
}

impl Evm {
    /// Builds an engine for one block, resolving the active [`BlobParams`](crate::blob::BlobParams)
    /// from the blob schedule by the block timestamp.
    ///
    /// The blob schedule is expected to be already validated — it can only be built via
    /// [`BlobSchedule::try_new`] — so this does not re-validate it.
    ///
    /// # Errors
    /// [`BlockExecutionError::InvalidBlockTimestamp`] if the block timestamp does not fit in `u64`;
    /// [`BlockExecutionError::MissingBlobParams`] if a Cancun-or-later block's blob schedule does
    /// not resolve any parameters (blob limits must be enforceable for such a block).
    pub fn new(
        chain_id: Option<u64>,
        mut block: BlockEnv,
        transactions: Vec<Transaction>,
        spec: Spec,
        state: BTreeMap<H160, MemoryAccount>,
        blob_schedule: &BlobSchedule,
    ) -> Result<Self, BlockExecutionError> {
        let timestamp = u64::try_from(block.block_timestamp)
            .map_err(|_| BlockExecutionError::InvalidBlockTimestamp)?;
        // Resolve this block's blob parameters. They are a block-level property gated purely by
        // hardfork — required from Cancun on, absent before it. `Spec` is authoritative for the
        // fork, so a pre-Cancun block ignores the schedule entirely: a stray active entry cannot
        // turn it into a "blob block". The schedule was already validated by `BlobSchedule::try_new`
        // (once, at config-construction time), so any resolved params are known well-formed here.
        block.blob_params = if spec >= Spec::Cancun {
            Some(
                blob_schedule
                    .blob_params_for_timestamp(timestamp)
                    .ok_or(BlockExecutionError::MissingBlobParams)?,
            )
        } else {
            None
        };
        let precompiles = Precompiles::new(&spec);
        Ok(Self {
            block,
            chain_id,
            precompiles,
            spec,
            state,
            transactions,
        })
    }

    /// Runs every transaction in order and returns the receipts, gas/blob totals and post-state.
    ///
    /// Consumes `self`: the world state lives in a local owned map for the whole loop, so a block
    /// that fails validation or execution never leaves a half-mutated engine observable.
    ///
    /// # Errors
    /// The first invalid or fatally-failing transaction aborts the block with a
    /// [`BlockExecutionError`]; nothing after it runs.
    pub fn execute_transactions(self) -> Result<TransactionExecutionResult, BlockExecutionError> {
        let Self {
            block,
            chain_id,
            precompiles,
            spec,
            mut state,
            transactions,
        } = self;

        let (receipts, gas_used, blob_gas_used) = run_transaction_loop(
            &block,
            chain_id,
            &precompiles,
            &spec,
            &mut state,
            transactions,
        )?;

        Ok(TransactionExecutionResult {
            receipts,
            gas_used,
            blob_gas_used,
            state,
        })
    }
}

/// Runs the transaction loop over a mutable world state, returning the receipts and the block gas /
/// blob-gas totals.
///
/// The first invalid or fatally-failing transaction aborts the loop; because the caller owns
/// `state`, a partially-mutated state is never published on the error path.
fn run_transaction_loop(
    block: &BlockEnv,
    chain_id: Option<u64>,
    precompiles: &Precompiles,
    spec: &Spec,
    state: &mut BTreeMap<H160, MemoryAccount>,
    transactions: Vec<Transaction>,
) -> Result<(Vec<Receipt>, u64, u64), BlockExecutionError> {
    // Built once per block; only per-transaction fields are updated in the loop (never cloning the
    // potentially large `block_hashes` window again).
    let base_fee = block.block_base_fee_per_gas;
    let coinbase = block.block_coinbase;

    let mut receipts = Vec::with_capacity(transactions.len());
    let mut cumulative_gas_used: u64 = 0;
    let mut cumulative_blob_count: u64 = 0;

    for tx in transactions {
        let validated_tx = validate_transaction_against_state(
            tx,
            state,
            block,
            spec,
            chain_id,
            cumulative_gas_used,
            cumulative_blob_count,
        )?;
        let tx_type = validated_tx.tx.tx_type;
        let blob_count = validated_tx.blob_count;

        // TODO
        let mut vicinity = block_vicinity(block, chain_id, &validated_tx);
        vicinity.gas_price = validated_tx.gas_price;
        vicinity.effective_gas_price = validated_tx.effective_gas_price;
        vicinity.origin = validated_tx.tx.caller;
        // vicinity.blob_hashes = validated.tx.blob_versioned_hashes;

        let outcome = execute_validated_tx(
            state,
            vicinity,
            precompiles,
            spec,
            base_fee,
            coinbase,
            validated_tx,
        )?;

        cumulative_gas_used = cumulative_gas_used
            .checked_add(outcome.gas_used)
            .ok_or(BlockExecutionError::ArithmeticOverflow)?;
        cumulative_blob_count = cumulative_blob_count
            .checked_add(blob_count)
            .ok_or(BlockExecutionError::ArithmeticOverflow)?;

        // `Fatal` was already turned into an error inside `execute_validated_tx`; here `reason` is
        // `Succeed`/`Revert`/`Error`, and only `Succeed` yields a success receipt.
        let success = outcome.reason.is_succeed();
        receipts.push(Receipt::new(
            tx_type,
            success,
            cumulative_gas_used,
            outcome.logs,
        ));
    }

    let blob_gas_used = cumulative_blob_count
        .checked_mul(GAS_PER_BLOB)
        .ok_or(BlockExecutionError::ArithmeticOverflow)?;

    Ok((receipts, cumulative_gas_used, blob_gas_used))
}

/// Whether `code` is an EIP-7702 delegation designation (`0xef0100 || address`), which lets an
/// account with code still originate transactions from Prague onward.
fn is_delegated_sender(code: &[u8], spec: &Spec) -> bool {
    *spec >= Spec::Prague && Authorization::is_delegated(code)
}

/// Validates one transaction against the current world state and block, returning the values the
/// execution stage needs. Performs no mutation.
///
/// # Errors
/// Returns the first failing check as a [`BlockExecutionError`]; an invalid transaction makes the
/// whole block invalid.
fn validate_transaction_against_state(
    tx: Transaction,
    state: &BTreeMap<H160, MemoryAccount>,
    block: &BlockEnv,
    spec: &Spec,
    chain_id: Option<u64>,
    cumulative_gas_used: u64,
    cumulative_blob_count: u64,
) -> Result<ValidatedTransaction, BlockExecutionError> {
    // 1. Sender snapshot. An absent account is the protocol-empty account (nonce 0, balance 0, no
    //    code) — not an error. (Missing *witness* data is a separate backend concern.)
    let sender = state.get(&tx.caller);
    let sender_nonce = sender.map(|account| account.nonce).unwrap_or_default();
    let sender_balance = sender.map(|account| account.balance).unwrap_or_default();
    let sender_code_empty = sender.is_none_or(|account| account.code.is_empty());
    let sender_is_delegated =
        sender.is_some_and(|account| is_delegated_sender(&account.code, spec));

    // 2. Nonce equality.
    if tx.nonce != sender_nonce {
        return Err(BlockExecutionError::InvalidNonce {
            tx: tx.nonce,
            state: sender_nonce,
        });
    }

    // 3. EIP-3607: the sender must not have non-delegation code.
    if !sender_code_empty && !sender_is_delegated {
        return Err(BlockExecutionError::SenderHasCode);
    }

    // 4. EIP-3860 (Shanghai+): a contract-creation transaction's init code is size-capped. This is
    //    a transaction-validity rule, distinct from the in-EVM `CREATE` init-code halt.
    if *spec >= Spec::Shanghai && tx.tx_kind.is_create() && tx.data.len() > MAX_INITCODE_SIZE {
        return Err(BlockExecutionError::InitCodeTooLarge);
    }

    // 5. Cheap per-transaction blob-count gate BEFORE the O(N) version-hash loop inside
    //    `validate_tx` (defense-in-depth on adversarial input). Gated on *resolved* blob params,
    //    which `Evm::new` sets exactly from Cancun on. A pre-Cancun blob transaction therefore
    //    skips this gate and is rejected by `validate_tx` itself (`Eip4844NotSupported`).
    let blob_count = u64::try_from(tx.blob_versioned_hashes.len())
        .map_err(|_| BlockExecutionError::ArithmeticOverflow)?;
    if blob_count > 0
        && let Some(params) = block.blob_params
        && blob_count > params.max_blobs_per_transaction
    {
        return Err(BlockExecutionError::TooManyBlobsInTransaction {
            count: blob_count,
            max: params.max_blobs_per_transaction,
        });
    }

    // 6. Full per-transaction context validation (including intrinsic / floor gas) and
    //    required-funds (reserved by the *maximum* fee). The access list is flattened exactly once
    //    here and reused for both the intrinsic-gas check inside `validate_tx` and execution.
    let ctx = EvmContext::new(chain_id, block, &tx, spec, None);
    let access_list = tx.access_list.flattened();
    ctx.validate_tx(&access_list)?;
    ctx.validate_required_funds(sender_balance)?;

    // 7. The transaction's gas limit must fit in the block's remaining gas. `block_gas_limit` is a
    //    mandatory `u64`, so this consensus check is always enforced (no fail-open).
    let available_gas = block.block_gas_limit.saturating_sub(cumulative_gas_used);
    if tx.gas_limit > available_gas {
        return Err(BlockExecutionError::BlockGasLimitExceeded {
            tx_gas_limit: tx.gas_limit,
            available_gas,
        });
    }

    // 8. Per-block blob limit against the active `BlobParams`. A blob transaction REQUIRES resolved
    //    params (the per-transaction cap was gated in step 5); their absence is an invalid block.
    if blob_count > 0 {
        let params = block
            .blob_params
            .ok_or(BlockExecutionError::MissingBlobParams)?;
        let total_blob_count = cumulative_blob_count
            .checked_add(blob_count)
            .ok_or(BlockExecutionError::ArithmeticOverflow)?;
        if total_blob_count > params.max_blobs_per_block {
            return Err(BlockExecutionError::BlockBlobLimitExceeded {
                count: total_blob_count,
                max: params.max_blobs_per_block,
            });
        }
    }

    let gas_price = ctx.get_gas_price();
    let effective_gas_price = ctx.get_effective_gas_price();
    let data_fee = ctx.calc_data_fee();

    Ok(ValidatedTransaction {
        tx,
        access_list,
        gas_price,
        effective_gas_price,
        data_fee,
        blob_count,
    })
}

/// Owned inputs one validated transaction hands to [`run_tx_in_backend`].
struct TxExec {
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
}

/// Up-front fee reservation: gas fee at the effective price plus any blob data fee (never `value`).
fn reserve_fee(
    effective_gas_price: U256,
    gas_limit: u64,
    data_fee: Option<U256>,
) -> Result<U256, BlockExecutionError> {
    let gas_fee = effective_gas_price
        .checked_mul(U256::from(gas_limit))
        .ok_or(BlockExecutionError::ArithmeticOverflow)?;
    data_fee.map_or(Ok(gas_fee), |fee| {
        gas_fee
            .checked_add(fee)
            .ok_or(BlockExecutionError::ArithmeticOverflow)
    })
}

/// Caller gas refund: reserved fee minus the fee actually charged minus the non-refundable blob fee.
fn caller_refund(
    reserve_fee: U256,
    actual_fee: U256,
    data_fee: Option<U256>,
) -> Result<U256, BlockExecutionError> {
    reserve_fee
        .checked_sub(actual_fee)
        .ok_or(BlockExecutionError::ArithmeticOverflow)?
        .checked_sub(data_fee.unwrap_or_default())
        .ok_or(BlockExecutionError::ArithmeticOverflow)
}

/// Runs one validated transaction against `backend`: reserve, run call/create, settle fees, apply the diff.
fn run_tx_in_backend(
    backend: &mut MemoryBackend<'_>,
    precompiles: &Precompiles,
    spec: &Spec,
    base_fee: U256,
    coinbase: H160,
    exec: TxExec,
) -> Result<TxExecutionOutcome, BlockExecutionError> {
    let gas_config = spec.get_gasometer_config();
    let metadata = StackSubstateMetadata::new(exec.gas_limit, &gas_config);
    let executor_state = MemoryStackState::new(metadata, &*backend);
    let mut executor =
        StackExecutor::new_with_precompiles(executor_state, &gas_config, precompiles);

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
    let miner_reward = if *spec > Spec::Berlin {
        executor.fee(exec.effective_gas_price.saturating_sub(base_fee))
    } else {
        actual_fee
    };
    executor.state_mut().deposit(coinbase, miner_reward);

    let refund = caller_refund(exec.reserve_fee, actual_fee, exec.data_fee)?;
    executor.state_mut().deposit(exec.caller, refund);

    let (values, logs) = executor.into_state().deconstruct();
    // Take the transaction's logs for the receipt; the backend's own log history is unused.
    let logs: Vec<Log> = logs.into_iter().collect();
    backend.apply(values, core::iter::empty::<Log>(), true);

    Ok(TxExecutionOutcome {
        reason,
        gas_used,
        logs,
    })
}

/// Executes a validated transaction and returns its outcome plus the reusable `MemoryVicinity`.
fn execute_validated_tx(
    state: &mut BTreeMap<H160, MemoryAccount>,
    mut vicinity: MemoryVicinity,
    precompiles: &Precompiles,
    spec: &Spec,
    base_fee: U256,
    coinbase: H160,
    validated_tx: ValidatedTransaction,
) -> Result<TxExecutionOutcome, BlockExecutionError> {
    let ValidatedTransaction {
        tx,
        access_list,
        effective_gas_price,
        data_fee,
        ..
    } = validated_tx;
    // Destructured rather than read through `Deref`, so the owned fields the executor consumes
    // (`data`, the blob hashes) move out instead of being cloned.
    let Transaction {
        payload,
        caller,
        authorization_list,
    } = tx;

    vicinity.blob_hashes = payload.blob_versioned_hashes;

    let exec = TxExec {
        caller,
        value: payload.value,
        gas_limit: payload.gas_limit,
        tx_kind: payload.tx_kind,
        data: payload.data,
        access_list,
        authorization_list,
        effective_gas_price,
        reserve_fee: reserve_fee(effective_gas_price, payload.gas_limit, data_fee)?,
        data_fee,
    };

    // Move the world state into a backend for execution; `*state` is restored UNCONDITIONALLY below.
    // On any error the executor substate is dropped without `apply`, so `backend` still holds the
    // untouched pre-transaction world; on success `apply` has written the post-transaction state.
    let taken_state = core::mem::take(state);
    let mut backend = MemoryBackend::new(&vicinity, taken_state);
    let outcome = run_tx_in_backend(&mut backend, precompiles, spec, base_fee, coinbase, exec);
    // Restore the world state on every path: pre-transaction on error, post-transaction on success.
    *state = core::mem::take(backend.state_mut());
    // `backend`'s shared borrow of `vicinity` has ended, so it can move back out for the next tx.
    outcome
}

/// Builds the block-level [`MemoryVicinity`]; per-transaction fields (`gas_price`,
/// `effective_gas_price`, `origin`, `blob_hashes`) are overwritten before each execution.
fn block_vicinity(
    block: &BlockEnv,
    chain_id: Option<u64>,
    validated_tx: &ValidatedTransaction,
) -> MemoryVicinity {
    MemoryVicinity {
        gas_price: validated_tx.gas_price,
        effective_gas_price: validated_tx.effective_gas_price,
        origin: validated_tx.tx.caller,
        block_hashes: block.block_hashes.clone(),
        block_number: block.block_number,
        block_coinbase: block.block_coinbase,
        block_timestamp: block.block_timestamp,
        block_difficulty: block.block_difficulty,
        block_gas_limit: U256::from(block.block_gas_limit),
        chain_id: chain_id.map(U256::from).unwrap_or_default(),
        block_base_fee_per_gas: block.block_base_fee_per_gas,
        block_randomness: block.block_randomness,
        blob_gas_price: block
            .blob_excess_gas_and_price
            .map(|blob| blob.blob_gas_price),
        blob_hashes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Evm, TransactionExecutionResult, validate_transaction_against_state};
    use crate::blob::{BlobExcessGasAndPrice, BlobParams, BlobSchedule, BlobScheduleEntry};
    use crate::block::BlockEnv;
    use crate::errors::BlockExecutionError;
    use crate::spec::Spec;
    use crate::transaction::{AccessList, Transaction, TxKind, TxPayload, TxType};
    use aurora_evm::backend::MemoryAccount;
    use primitive_types::{H160, H256, U256};
    use std::collections::BTreeMap;

    fn addr(byte: u8) -> H160 {
        H160::repeat_byte(byte)
    }

    fn account(balance: u64, nonce: u64, code: Vec<u8>) -> MemoryAccount {
        MemoryAccount {
            nonce: U256::from(nonce),
            balance: U256::from(balance),
            storage: BTreeMap::new(),
            code,
        }
    }

    fn empty_blob_schedule() -> BlobSchedule {
        BlobSchedule::default()
    }

    fn block(spec_base_fee: u64, coinbase: H160) -> BlockEnv {
        BlockEnv {
            block_hashes: vec![],
            block_number: U256::from(1u64),
            block_coinbase: coinbase,
            block_timestamp: U256::from(1_000u64),
            block_difficulty: U256::zero(),
            block_gas_limit: 30_000_000,
            block_base_fee_per_gas: U256::from(spec_base_fee),
            block_randomness: Some(H256::zero()),
            blob_excess_gas_and_price: None,
            blob_hashes: vec![],
            blob_params: None,
            parent_hash: H256::zero(),
            parent_beacon_block_root: None,
            withdrawals: vec![],
        }
    }

    /// A payload with the fields no test varies already filled in.
    fn payload(tx_type: TxType, to: H160, nonce: u64) -> TxPayload {
        TxPayload {
            tx_type,
            tx_kind: TxKind::Call(to),
            gas_limit: 100_000,
            value: U256::zero(),
            data: vec![],
            nonce: U256::from(nonce),
            chain_id: None,
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: AccessList(vec![]),
            blob_versioned_hashes: vec![],
            max_fee_per_blob_gas: 0,
        }
    }

    /// Wraps a payload into the execution form with the given sender.
    fn transaction(payload: TxPayload, caller: H160) -> Transaction {
        Transaction {
            payload,
            caller,
            authorization_list: vec![],
        }
    }

    fn eip1559_transfer(
        caller: H160,
        to: H160,
        value: U256,
        nonce: u64,
        max_fee: u64,
        max_priority: u64,
    ) -> Transaction {
        let mut payload = payload(TxType::Eip1559, to, nonce);
        payload.value = value;
        payload.chain_id = Some(1);
        payload.max_fee_per_gas = Some(U256::from(max_fee));
        payload.max_priority_fee_per_gas = Some(U256::from(max_priority));
        transaction(payload, caller)
    }

    fn legacy_transfer(
        caller: H160,
        to: H160,
        value: U256,
        nonce: u64,
        gas_price: u64,
    ) -> Transaction {
        let mut payload = payload(TxType::Legacy, to, nonce);
        payload.value = value;
        payload.gas_price = Some(U256::from(gas_price));
        transaction(payload, caller)
    }

    fn balance_of(state: &BTreeMap<H160, MemoryAccount>, who: H160) -> U256 {
        state
            .get(&who)
            .map(|account| account.balance)
            .unwrap_or_default()
    }

    fn run(
        spec: Spec,
        base_fee: u64,
        state: BTreeMap<H160, MemoryAccount>,
        txs: Vec<Transaction>,
        blob_schedule: &BlobSchedule,
    ) -> Result<TransactionExecutionResult, BlockExecutionError> {
        let evm = Evm::new(
            Some(1),
            block(base_fee, addr(0xcb)),
            txs,
            spec,
            state,
            blob_schedule,
        )?;
        evm.execute_transactions()
    }

    #[test]
    fn transfer_conserves_balances_with_zero_base_fee() {
        let caller = addr(0xca);
        let to = addr(0x2e);
        let coinbase = addr(0xcb);
        let value = U256::from(1_000u64);
        let initial = 10_000_000u64;
        let mut state = BTreeMap::new();
        state.insert(caller, account(initial, 0, vec![]));

        // effective = min(max_fee 10, priority 10 + base 0) = 10; base_fee 0 → nothing burned.
        let tx = eip1559_transfer(caller, to, value, 0, 10, 10);
        let result = run(Spec::London, 0, state, vec![tx], &empty_blob_schedule()).unwrap();

        let caller_final = balance_of(&result.state, caller);
        let to_final = balance_of(&result.state, to);
        let coinbase_final = balance_of(&result.state, coinbase);
        assert_eq!(to_final, value);
        assert_eq!(
            caller_final + to_final + coinbase_final,
            U256::from(initial)
        );
        assert_eq!(coinbase_final, U256::from(21_000u64 * 10)); // whole fee (no burn)
        assert_eq!(result.receipts.len(), 1);
        assert!(result.receipts[0].success);
        assert_eq!(result.gas_used, 21_000);
    }

    #[test]
    fn base_fee_is_burned_from_london() {
        let caller = addr(0xca);
        let coinbase = addr(0xcb);
        let initial = 10_000_000u64;
        let mut state = BTreeMap::new();
        state.insert(caller, account(initial, 0, vec![]));

        // effective = min(max_fee 12, priority 2 + base 3) = 5; coinbase gets tip = used * 2.
        let tx = eip1559_transfer(caller, addr(0x2e), U256::from(1_000u64), 0, 12, 2);
        let result = run(Spec::London, 3, state, vec![tx], &empty_blob_schedule()).unwrap();

        let coinbase_final = balance_of(&result.state, coinbase);
        assert_eq!(coinbase_final, U256::from(21_000u64 * 2));
        // Total supply strictly decreases (base fee burned).
        let caller_final = balance_of(&result.state, caller);
        let to_final = balance_of(&result.state, addr(0x2e));
        assert!(caller_final + to_final + coinbase_final < U256::from(initial));
    }

    #[test]
    fn legacy_tx_is_charged_gas_on_london() {
        // Regression: on London a legacy tx pays via `gas_price`, not `max_fee_per_gas`.
        let caller = addr(0xca);
        let coinbase = addr(0xcb);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, vec![]));
        let tx = legacy_transfer(caller, addr(0x2e), U256::from(1_000u64), 0, 10);
        let result = run(Spec::London, 0, state, vec![tx], &empty_blob_schedule()).unwrap();
        assert_eq!(
            balance_of(&result.state, coinbase),
            U256::from(21_000u64 * 10)
        );
    }

    #[test]
    fn multiple_transactions_accumulate_gas_and_nonce() {
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, vec![]));
        let txs = vec![
            eip1559_transfer(caller, addr(0x2e), U256::from(1u64), 0, 10, 1),
            eip1559_transfer(caller, addr(0x2e), U256::from(1u64), 1, 10, 1),
        ];
        let result = run(Spec::London, 0, state, txs, &empty_blob_schedule()).unwrap();
        assert_eq!(result.receipts.len(), 2);
        assert_eq!(result.receipts[0].cumulative_gas_used, 21_000);
        assert_eq!(result.receipts[1].cumulative_gas_used, 42_000);
        assert_eq!(result.gas_used, 42_000);
        // Sender nonce advanced by two.
        assert_eq!(result.state.get(&caller).unwrap().nonce, U256::from(2u64));
    }

    #[test]
    fn absent_sender_is_treated_as_empty_account() {
        // Empty caller, zero fee and value: valid, executes, no `CallerNotFound`.
        let caller = addr(0xca);
        let tx = eip1559_transfer(caller, addr(0x2e), U256::zero(), 0, 0, 0);
        let result = run(
            Spec::London,
            0,
            BTreeMap::new(),
            vec![tx],
            &empty_blob_schedule(),
        );
        assert!(result.is_ok());
    }

    // --- validation-only cases (drive the private validator directly) ---

    #[allow(clippy::needless_pass_by_value)] // test helper: callers pass owned `Spec` literals
    fn validate(
        tx: Transaction,
        state: &BTreeMap<H160, MemoryAccount>,
        spec: Spec,
        block: &BlockEnv,
        cumulative_gas_used: u64,
        cumulative_blob_count: u64,
    ) -> Result<(), BlockExecutionError> {
        validate_transaction_against_state(
            tx,
            state,
            block,
            &spec,
            Some(1),
            cumulative_gas_used,
            cumulative_blob_count,
        )
        .map(|_| ())
    }

    #[test]
    fn nonce_mismatch_is_rejected() {
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 5, vec![]));
        let blk = block(0, addr(0xcb));

        let high = eip1559_transfer(caller, addr(0x2e), U256::zero(), 7, 10, 1);
        assert!(matches!(
            validate(high, &state, Spec::London, &blk, 0, 0),
            Err(BlockExecutionError::InvalidNonce { .. })
        ));
    }

    #[test]
    fn sender_with_code_is_rejected_eip3607() {
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, vec![0x60, 0x00])); // arbitrary code
        let blk = block(0, addr(0xcb));
        let tx = eip1559_transfer(caller, addr(0x2e), U256::zero(), 0, 10, 1);
        assert!(matches!(
            validate(tx, &state, Spec::London, &blk, 0, 0),
            Err(BlockExecutionError::SenderHasCode)
        ));
    }

    #[test]
    fn delegated_sender_may_originate_from_prague() {
        // EIP-7702 delegation designation: 0xef0100 || 20-byte address (23 bytes).
        let caller = addr(0xca);
        let mut code = vec![0xef, 0x01, 0x00];
        code.extend_from_slice(addr(0x99).as_bytes());
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, code));
        let tx = eip1559_transfer(caller, addr(0x2e), U256::zero(), 0, 10, 1);

        // Before Prague, a code-bearing sender is rejected outright (EIP-3607).
        let london_blk = block(0, addr(0xcb));
        assert!(matches!(
            validate(tx.clone(), &state, Spec::London, &london_blk, 0, 0),
            Err(BlockExecutionError::SenderHasCode)
        ));

        // From Prague the delegation designation lets it originate. (Prague >= Cancun requires the
        // blob header field to be present.)
        let mut prague_blk = block(0, addr(0xcb));
        prague_blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
        assert!(validate(tx, &state, Spec::Prague, &prague_blk, 0, 0).is_ok());
    }

    #[test]
    fn eip3860_init_code_size_boundary() {
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(1_000_000_000_000u64, 0, vec![]));
        let blk = block(0, addr(0xcb));

        let mut create = legacy_transfer(caller, addr(0x2e), U256::zero(), 0, 0);
        create.payload.tx_kind = TxKind::Create;
        create.payload.gas_limit = 20_000_000;

        // 49153 bytes → invalid (EIP-3860); exactly 49152 → not an InitCodeTooLarge error.
        let mut too_large = create.clone();
        too_large.payload.data = vec![0x00; 49_153];
        assert!(matches!(
            validate(too_large, &state, Spec::Shanghai, &blk, 0, 0),
            Err(BlockExecutionError::InitCodeTooLarge)
        ));

        let mut at_limit = create;
        at_limit.payload.data = vec![0x00; 49_152];
        assert!(!matches!(
            validate(at_limit, &state, Spec::Shanghai, &blk, 0, 0),
            Err(BlockExecutionError::InitCodeTooLarge)
        ));
    }

    #[test]
    fn block_gas_limit_remaining_is_enforced() {
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, vec![]));
        let blk = block(0, addr(0xcb)); // block_gas_limit 30_000_000
        let tx = eip1559_transfer(caller, addr(0x2e), U256::zero(), 0, 10, 1); // gas_limit 100_000
        // Only 50_000 gas remains in the block → the 100_000-gas tx does not fit.
        assert!(matches!(
            validate(tx, &state, Spec::London, &blk, 29_950_000, 0),
            Err(BlockExecutionError::BlockGasLimitExceeded { .. })
        ));
    }

    fn blob_tx(caller: H160, blobs: usize, nonce: u64) -> Transaction {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = 0x01; // VERSIONED_HASH_VERSION_KZG
        let versioned = U256::from_big_endian(&hash_bytes);
        let mut payload = payload(TxType::Eip4844, addr(0x2e), nonce);
        payload.gas_limit = 1_000_000;
        payload.chain_id = Some(1);
        payload.max_fee_per_gas = Some(U256::from(100u64));
        payload.max_priority_fee_per_gas = Some(U256::one());
        payload.blob_versioned_hashes = vec![versioned; blobs];
        payload.max_fee_per_blob_gas = 1_000_000;
        transaction(payload, caller)
    }

    fn osaka_blob_schedule() -> BlobSchedule {
        // Osaka blob params active from timestamp 0 (per-tx cap 6, per-block max 9).
        BlobSchedule::try_new(vec![BlobScheduleEntry {
            activation_timestamp: 0,
            params: BlobParams::osaka(),
        }])
        .unwrap()
    }

    fn cancun_blob_block() -> BlockEnv {
        let mut blk = block(0, addr(0xcb));
        blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
        blk.blob_params = Some(BlobParams::osaka());
        blk
    }

    #[test]
    fn per_transaction_blob_cap_is_enforced() {
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(u64::MAX, 0, vec![]));
        let blk = cancun_blob_block();
        // Osaka per-tx cap is 6: 6 blobs ok, 7 rejected.
        assert!(validate(blob_tx(caller, 6, 0), &state, Spec::Osaka, &blk, 0, 0).is_ok());
        assert!(matches!(
            validate(blob_tx(caller, 7, 0), &state, Spec::Osaka, &blk, 0, 0),
            Err(BlockExecutionError::TooManyBlobsInTransaction { count: 7, max: 6 })
        ));
    }

    #[test]
    fn per_block_blob_cap_is_enforced() {
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(u64::MAX, 0, vec![]));
        let blk = cancun_blob_block(); // Osaka: max_blobs_per_block = 9
        // 6 blobs already used; a further 6 would total 12 > 9.
        assert!(matches!(
            validate(blob_tx(caller, 6, 0), &state, Spec::Osaka, &blk, 0, 6),
            Err(BlockExecutionError::BlockBlobLimitExceeded { count: 12, max: 9 })
        ));
        // 3 more fits exactly (6 + 3 = 9).
        assert!(validate(blob_tx(caller, 3, 0), &state, Spec::Osaka, &blk, 0, 6).is_ok());
    }

    #[test]
    fn invalid_block_timestamp_is_rejected() {
        let mut blk = block(0, addr(0xcb));
        blk.block_timestamp = U256::MAX; // does not fit in u64
        let result = Evm::new(
            Some(1),
            blk,
            vec![],
            Spec::London,
            BTreeMap::new(),
            &empty_blob_schedule(),
        );
        assert!(matches!(
            result,
            Err(BlockExecutionError::InvalidBlockTimestamp)
        ));
    }

    #[test]
    fn blob_tx_without_resolved_blob_params_is_rejected() {
        // Regression: a blob transaction whose block has no resolved `blob_params` must be
        // rejected, not silently accepted with the blob limits skipped.
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(u64::MAX, 0, vec![]));
        let mut blk = block(0, addr(0xcb));
        blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
        blk.blob_params = None; // e.g. an empty blob schedule
        assert!(matches!(
            validate(blob_tx(caller, 1, 0), &state, Spec::Osaka, &blk, 0, 0),
            Err(BlockExecutionError::MissingBlobParams)
        ));
    }

    #[test]
    fn caller_equals_coinbase_settles_once() {
        // With coinbase == caller and base_fee 0, the caller gets its whole gas fee back (as the
        // coinbase tip plus the refund), so its net change is exactly the transferred value.
        let caller = addr(0xca);
        let to = addr(0x2e);
        let initial = 10_000_000u64;
        let value = U256::from(1_000u64);
        let mut state = BTreeMap::new();
        state.insert(caller, account(initial, 0, vec![]));
        let tx = eip1559_transfer(caller, to, value, 0, 10, 10);
        let evm = Evm::new(
            Some(1),
            block(0, caller), // coinbase == caller
            vec![tx],
            Spec::London,
            state,
            &empty_blob_schedule(),
        )
        .unwrap();
        let result = evm.execute_transactions().unwrap();
        assert_eq!(
            balance_of(&result.state, caller),
            U256::from(initial) - value
        );
        assert_eq!(balance_of(&result.state, to), value);
    }

    #[test]
    fn reverting_call_pays_gas_without_transfer_or_logs() {
        let caller = addr(0xca);
        let target = addr(0x2e);
        let coinbase = addr(0xcb);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, vec![]));
        // PUSH1 0x00 PUSH1 0x00 REVERT — reverts immediately with empty data.
        state.insert(target, account(500, 0, vec![0x60, 0x00, 0x60, 0x00, 0xfd]));
        let tx = eip1559_transfer(caller, target, U256::from(1_000u64), 0, 10, 10);
        let result = run(Spec::London, 0, state, vec![tx], &empty_blob_schedule()).unwrap();

        assert_eq!(result.receipts.len(), 1);
        assert!(!result.receipts[0].success); // reverted
        assert!(result.receipts[0].logs.is_empty()); // logs rolled back
        // The value transfer is rolled back: the target keeps exactly its pre-state balance.
        assert_eq!(balance_of(&result.state, target), U256::from(500u64));
        // Gas was still paid (base_fee 0 → the whole fee went to the coinbase).
        assert!(balance_of(&result.state, coinbase) > U256::zero());
    }

    #[test]
    fn out_of_gas_call_still_pays_full_gas() {
        let caller = addr(0xca);
        let target = addr(0x2e);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, vec![]));
        // JUMPDEST PUSH1 0x00 JUMP — an infinite loop that consumes all gas.
        state.insert(target, account(0, 0, vec![0x5b, 0x60, 0x00, 0x56]));
        let mut tx = eip1559_transfer(caller, target, U256::zero(), 0, 10, 10);
        tx.payload.gas_limit = 100_000;
        let result = run(Spec::London, 0, state, vec![tx], &empty_blob_schedule()).unwrap();

        assert!(!result.receipts[0].success);
        // Out-of-gas consumes the entire gas limit.
        assert_eq!(result.gas_used, 100_000);
    }

    #[test]
    fn create_transaction_executes() {
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000_000u64, 0, vec![]));
        let mut tx = legacy_transfer(caller, addr(0x2e), U256::zero(), 0, 10);
        tx.payload.tx_kind = TxKind::Create;
        // PUSH1 0x00 PUSH1 0x00 RETURN — deploys empty runtime code.
        tx.payload.data = vec![0x60, 0x00, 0x60, 0x00, 0xf3];
        tx.payload.gas_limit = 200_000;
        let result = run(Spec::London, 0, state, vec![tx], &empty_blob_schedule()).unwrap();

        assert!(result.receipts[0].success);
        // Creation pays the 32000 create cost on top of the 21000 transaction base.
        assert!(result.gas_used >= 53_000);
    }

    #[test]
    fn invalid_transaction_aborts_the_block() {
        // A valid tx followed by an invalid one (bad nonce): the whole block fails, and no partial
        // result is returned.
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, vec![]));
        let txs = vec![
            eip1559_transfer(caller, addr(0x2e), U256::from(1u64), 0, 10, 1), // valid, nonce 0
            eip1559_transfer(caller, addr(0x2e), U256::from(1u64), 5, 10, 1), // nonce 5 != 1
        ];
        let result = run(Spec::London, 0, state, txs, &empty_blob_schedule());
        assert!(matches!(
            result,
            Err(BlockExecutionError::InvalidNonce { .. })
        ));
    }

    #[test]
    fn per_block_blob_limit_enforced_through_driver() {
        // End-to-end: the blob schedule is resolved by `Evm::new`, the first 5-blob tx executes,
        // and the second pushes the cumulative count to 10 > the Osaka per-block max of 9.
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(u64::MAX, 0, vec![]));
        let mut blk = block(0, addr(0xcb));
        blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
        let txs = vec![blob_tx(caller, 5, 0), blob_tx(caller, 5, 1)];
        let evm = Evm::new(
            Some(1),
            blk,
            txs,
            Spec::Osaka,
            state,
            &osaka_blob_schedule(),
        )
        .unwrap();
        let result = evm.execute_transactions();
        assert!(matches!(
            result,
            Err(BlockExecutionError::BlockBlobLimitExceeded { count: 10, max: 9 })
        ));
    }

    #[test]
    fn typed_tx_with_gas_price_is_rejected() {
        // A flattened EIP-1559 transaction that also carries a legacy `gas_price` is invalid — the
        // fee source must be unambiguous (this previously let it execute at gas price 0).
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, vec![]));
        let blk = block(0, addr(0xcb));
        let mut tx = eip1559_transfer(caller, addr(0x2e), U256::zero(), 0, 10, 1);
        tx.payload.gas_price = Some(U256::zero());
        let err = validate(tx, &state, Spec::London, &blk, 0, 0).unwrap_err();
        assert!(err.to_string().contains("gas_price"));
    }

    #[test]
    fn non_blob_tx_with_blob_hashes_is_rejected() {
        // Blob versioned hashes on a non-EIP-4844 transaction are invalid (they would otherwise
        // reach BLOBHASH and the block blob count while paying no blob fee).
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, vec![]));
        let blk = block(0, addr(0xcb));
        let mut tx = eip1559_transfer(caller, addr(0x2e), U256::zero(), 0, 10, 1);
        tx.payload.blob_versioned_hashes = vec![U256::one()];
        let err = validate(tx, &state, Spec::London, &blk, 0, 0).unwrap_err();
        assert!(err.to_string().contains("blob versioned hashes"));
    }

    #[test]
    fn blob_fee_is_burned() {
        // With base_fee 0 the only burn is the blob fee: the whole supply drop equals
        // current_blob_price * total_blob_gas, and the coinbase does not receive it.
        let caller = addr(0xca);
        let to = addr(0x2e);
        let coinbase = addr(0xcb);
        let initial = 1_000_000_000_000_000u64;
        let mut state = BTreeMap::new();
        state.insert(caller, account(initial, 0, vec![]));
        let mut blk = block(0, coinbase);
        blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice {
            excess_blob_gas: 0,
            blob_gas_price: 2,
        });
        let tx = blob_tx(caller, 1, 0); // one blob
        let evm = Evm::new(
            Some(1),
            blk,
            vec![tx],
            Spec::Osaka,
            state,
            &osaka_blob_schedule(),
        )
        .unwrap();
        let result = evm.execute_transactions().unwrap();

        assert!(result.receipts[0].success);
        let sum_after = balance_of(&result.state, caller)
            + balance_of(&result.state, to)
            + balance_of(&result.state, coinbase);
        let blob_fee = U256::from(2u64) * U256::from(crate::blob::GAS_PER_BLOB); // 1 blob @ price 2
        assert_eq!(sum_after, U256::from(initial) - blob_fee);
    }

    #[test]
    fn cancun_block_without_blob_params_rejected_at_new() {
        // A Cancun+ block with an empty blob schedule cannot enforce blob limits → rejected at
        // construction, even with no transactions.
        let result = Evm::new(
            Some(1),
            block(0, addr(0xcb)),
            vec![],
            Spec::Cancun,
            BTreeMap::new(),
            &empty_blob_schedule(),
        );
        assert!(matches!(
            result,
            Err(BlockExecutionError::MissingBlobParams)
        ));
    }

    #[test]
    fn pre_cancun_block_ignores_blob_schedule() {
        // `Spec` is authoritative for the fork: a pre-Cancun block ignores the blob schedule
        // entirely (even one active at its timestamp), so construction succeeds and no blob
        // parameters are resolved — the schedule cannot turn it into a "blob block".
        let evm = Evm::new(
            Some(1),
            block(0, addr(0xcb)),
            vec![],
            Spec::London,
            BTreeMap::new(),
            &osaka_blob_schedule(),
        );
        assert!(evm.is_ok());
    }
}
