//! [`BlockExecutor`] — the transaction phase of executing a block.
//!
//! # What it is, and what it is not
//!
//! This is the layer *above* the EVM, not the EVM. The interpreter is [`aurora_evm`]'s, and it is
//! built fresh for every transaction — a [`MemoryBackend`], a [`MemoryStackState`] and a
//! [`StackExecutor`]. What lives here is the Ethereum block logic around those: which transactions
//! are admissible in this block, what each one costs, who is paid, and what the block accumulated.
//!
//! It is one block's executor, not a reusable service: it is constructed with that block's
//! environment, transactions and world state, and [`BlockExecutor::execute_transactions`] consumes
//! it. State is kept in an owned map, so a block that fails part-way leaves no half-executed value
//! behind for anyone to read.
//!
//! # The phase this covers
//!
//! The block pipeline is wider than this type. Ahead of it: the header's fork fields, the body
//! commitments the header claims, and the sender of every transaction
//! ([`recover_block`](crate::block::recover_block)). Behind it: the state root and the
//! post-execution header comparison.
//!
//! Deliberately **not** here yet, and named so the gap is not mistaken for a decision that they
//! belong elsewhere: the EIP-2935 and EIP-4788 pre-execution system calls, EIP-4895 withdrawals,
//! EIP-7685 requests, and the post-state / receipts / bloom roots. They are part of executing a
//! block, so they belong to this type once they exist — not to a layer above it.
//!
//! # Per transaction, in order
//!
//! 1. **Validation against state** — nonce equality, EIP-3607 (sender not a contract), EIP-3860
//!    (init-code size), the per-transaction [`EvmContext`] checks and required funds (reserved at the
//!    *maximum* fee), remaining block gas, and the per-transaction / per-block blob limits from the
//!    active [`BlobParams`]. An invalid transaction fails the whole block, and no state is mutated:
//!    a block is valid or it is not, so there is nothing to salvage from a partial run.
//! 2. **Execution and fee settlement** — the gas fee is reserved up front (`effective * gas_limit`
//!    plus the blob fee, **without** `value`), the call or create runs (the value transfer happens
//!    there), then the coinbase receives the priority tip, the caller is refunded the unused gas, and
//!    the base fee and the blob fee are burned. This mirrors the proven `evm-tests` model.
//! 3. **Accounting and receipt** — the block's running totals are advanced and a typed [`Receipt`] is
//!    built from the outcome.

use crate::block::BlockEnv;
use crate::chain_spec::ChainSpec;
use crate::eips::eip4844::DATA_GAS_PER_BLOB;
use crate::eips::eip7840::BlobParams;
use crate::errors::BlockExecutionError;
use crate::errors::InvalidTransaction;
use crate::evm_context::{EvmContext, InvalidEvmContext};
use crate::precompiles::Precompiles;
use crate::receipt::Receipt;
use crate::spec::Spec;
use crate::transaction::{TxEnv, TxKind};
use aurora_evm::ExitReason;
use aurora_evm::backend::{ApplyBackend, Log, MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{
    Authorization, MemoryStackState, StackExecutor, StackSubstateMetadata,
};

use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

/// EIP-3860 maximum init-code size (`2 * MAX_CODE_SIZE`, where `MAX_CODE_SIZE = 24576`).
const MAX_INITCODE_SIZE: usize = 2 * 0x6000;

/// One block's transaction phase: its environment, its chain configuration, its world state and the
/// transactions to run against them.
///
/// Everything the phase needs is supplied at construction and owned from then on, so nothing has to
/// be applied to it afterwards and nothing can be observed part-way. See the module docs for which
/// stages of block execution this covers and which are still absent.
pub struct BlockExecutor {
    block: BlockEnv,
    chain: ChainSpec,
    precompiles: Precompiles,
    /// The [`BlobParams`] active for this block, resolved once from the chain's schedule.
    ///
    /// Held here rather than in [`BlockEnv`] so that the environment is complete the moment it is
    /// built: a `BlockEnv` that still needed a schedule applied to it would have a valid-looking but
    /// unusable intermediate state, and only this constructor could fix it.
    blob_params: Option<BlobParams>,
    state: BTreeMap<H160, MemoryAccount>,
    transactions: Vec<TxEnv>,
}

/// What the transaction phase produced: the receipts in block order, the block's gas and blob-gas
/// totals, and the world state as the last transaction left it.
///
/// Not a block result — the state root, the receipts root and the bloom are derived from this by the
/// post-execution stage, and the header comparison happens there.
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

/// The block's running totals, as of the transactions already executed.
///
/// One value rather than two `u64` arguments: they are the same width and always travel together, so
/// a swapped pair would compile and then quietly mis-enforce both limits it feeds — the block gas
/// limit against the blob count, and the per-block blob limit against the gas.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BlockExecutionCounters {
    /// Gas consumed by the transactions executed so far.
    gas_used: u64,
    /// Blobs carried by the transactions executed so far.
    blob_count: u64,
}

/// A transaction that passed validation flow, carrying the values the
/// execution stage would otherwise recompute (fees, flattened access list, blob count).
struct ValidatedTransaction {
    tx: TxEnv,
    access_list: Vec<(H160, Vec<H256>)>,
    gas_price: U256,
    effective_gas_price: U256,
    data_fee: Option<U256>,
    blob_count: u64,
}

impl BlockExecutor {
    /// Builds the executor for one block, resolving the active [`BlobParams`] from the chain's blob
    /// schedule by the block timestamp — once, here, so that nothing downstream has to carry the
    /// schedule or resolve it again.
    ///
    /// The schedule was already validated when it was built, so it is not re-validated.
    ///
    /// ## Errors
    /// [`BlockExecutionError::InvalidBlockTimestamp`] if the block timestamp does not fit in `u64`.
    pub fn new(
        chain: ChainSpec,
        block: BlockEnv,
        transactions: Vec<TxEnv>,
        state: BTreeMap<H160, MemoryAccount>,
    ) -> Result<Self, BlockExecutionError> {
        let blob_params = resolve_blob_params(&chain, &block)?;
        let precompiles = Precompiles::new(&chain.spec);
        Ok(Self {
            block,
            chain,
            precompiles,
            blob_params,
            state,
            transactions,
        })
    }

    /// Runs every transaction in order and returns the receipts, the gas and blob totals, and the
    /// post-execution state.
    ///
    /// Consumes `self`: the world state lives in a local owned map for the whole loop, so a block
    /// that fails validation or execution leaves no half-mutated value behind to be read.
    ///
    /// ## Errors
    /// The first invalid or fatally-failing transaction aborts the block with a
    /// [`BlockExecutionError`]; nothing after it runs.
    pub fn execute_transactions(
        mut self,
    ) -> Result<TransactionExecutionResult, BlockExecutionError> {
        // Taken out rather than destructured, because the two stages below are methods: everything
        // they read stays behind `self`, and only the list being walked has to move.
        let transactions = core::mem::take(&mut self.transactions);

        // Built once per block; only per-transaction fields are updated in the loop, so the
        // potentially large `block_hashes` window is never cloned again.
        let mut block_vicinity = block_vicinity(&self.block, self.chain.chain_id);

        let mut receipts = Vec::with_capacity(transactions.len());
        let mut counters = BlockExecutionCounters::default();

        for (index, tx) in transactions.into_iter().enumerate() {
            // Both stages are tagged with the position, because "this block is invalid" without
            // saying *which* transaction made it so is almost useless when reconciling with another
            // client.
            let validated_tx = self
                .validate_transaction_for_block(tx, counters)
                .map_err(|source| BlockExecutionError::at_transaction(index, source))?;
            let tx_type = validated_tx.tx.tx_type;
            let tx_blob_count = validated_tx.blob_count;

            let outcome = self
                .execute_validated_tx(&mut block_vicinity, validated_tx)
                .map_err(|source| BlockExecutionError::at_transaction(index, source))?;

            // Checked, because its bound leans on the executor never reporting more gas than the
            // limit it was given — a property of `aurora-evm`, not of a check in this file.
            counters.gas_used = counters.gas_used.saturating_add(outcome.gas_used);
            // Unchecked, because step 8 has already computed this exact sum from these exact operands
            // and refused the transaction if it overflowed. A second check here could not fire.
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

        Ok(TransactionExecutionResult {
            receipts,
            gas_used: counters.gas_used,
            blob_gas_used: counters.blob_count.saturating_mul(DATA_GAS_PER_BLOB),
            state: self.state,
        })
    }

    /// Everything a transaction must satisfy against *this block's* state and configuration, before
    /// any of it is executed.
    ///
    /// Reads the block, the chain and the world state through `&self`; the two arguments are what
    /// changes from one transaction to the next.
    ///
    /// ## Errors
    /// [`BlockExecutionError`] naming the rule the transaction breaks.
    fn validate_transaction_for_block(
        &self,
        tx: TxEnv,
        counters: BlockExecutionCounters,
    ) -> Result<ValidatedTransaction, BlockExecutionError> {
        // 1. Sender snapshot. An absent account is the protocol-empty account (nonce 0, balance 0, no
        //    code) — not an error. (Missing *witness* data is a separate backend concern.)
        let sender = self.state.get(&tx.caller);
        let sender_nonce = sender.map(|account| account.nonce).unwrap_or_default();
        let sender_balance = sender.map(|account| account.balance).unwrap_or_default();
        let sender_code_empty = sender.is_none_or(|account| account.code.is_empty());
        let sender_is_delegated =
            sender.is_some_and(|account| is_delegated_sender(&account.code, self.chain.spec));

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
        if self.chain.spec >= Spec::Shanghai
            && tx.tx_kind.is_create()
            && tx.data.len() > MAX_INITCODE_SIZE
        {
            return Err(BlockExecutionError::InitCodeTooLarge);
        }

        // 5. Cheap per-transaction blob-count gate BEFORE the O(N) version-hash loop inside
        //    `validate_tx` (defense-in-depth on adversarial input). Gated on *resolved* blob params,
        //    which `BlockExecutor::new` sets exactly from Cancun on. A pre-Cancun blob transaction therefore
        //    skips this gate and is rejected by `validate_tx` itself (`Eip4844NotSupported`).

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
        //    required-funds (reserved by the *maximum* fee). The access list is flattened exactly once
        //    here and reused for both the intrinsic-gas check inside `validate_tx` and execution.
        let ctx = EvmContext::new(
            self.chain.chain_id,
            &self.block,
            &tx,
            &self.chain.spec,
            None,
        );
        let access_list = tx.access_list.flattened();
        ctx.validate_tx(&access_list)?;
        ctx.validate_required_funds(sender_balance)?;

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
        //    Absent parameters mean the fork has no blob market, which step 6 has already rejected for a
        //    blob-carrying transaction (`Eip4844NotSupported`), so this cannot fire. It is written as a
        //    rejection rather than as `if let Some(..)` on purpose: should the earlier guard ever move or
        //    weaken, this fails **closed** — the per-block blob limit is never silently skipped. The
        //    verdict is the same one step 6 would have given, so the two can never disagree.
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
            access_list,
            gas_price,
            effective_gas_price,
            data_fee,
            blob_count,
        })
    }

    /// Executes one already-validated transaction and settles its fees.
    ///
    /// Takes the world state, the precompiles, the fork and the block's fee parameters through
    /// `&mut self`; `vicinity` is the per-block environment the loop carries, rewritten with this
    /// transaction's fields on the way in.
    ///
    /// ## Errors
    /// [`BlockExecutionError`] if the executor halts fatally or the fee arithmetic overflows.
    fn execute_validated_tx(
        &mut self,
        vicinity: &mut MemoryVicinity,
        validated_tx: ValidatedTransaction,
    ) -> Result<TxExecutionOutcome, BlockExecutionError> {
        let ValidatedTransaction {
            tx,
            access_list,
            effective_gas_price,
            data_fee,
            gas_price,
            ..
        } = validated_tx;
        // Destructured rather than read field by field, so the owned parts the executor consumes
        // (`data`, the blob hashes, the authorizations) move out instead of being cloned.
        let TxEnv {
            caller,
            value,
            gas_limit,
            tx_kind,
            data,
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
        .apply(vicinity);

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
            spec: self.chain.spec,
            precompiles: &self.precompiles,
        };

        // Move the world state into a backend for execution; `*state` is restored UNCONDITIONALLY below.
        // On any error the executor substate is dropped without `apply`, so `backend` still holds the
        // untouched pre-transaction world; on success `apply` has written the post-transaction state.
        let taken_state = core::mem::take(&mut self.state);
        let mut backend = MemoryBackend::new(vicinity, taken_state);
        let outcome = exec_tx_with_backend(&mut backend, exec);
        // Restore the world state on every path: pre-transaction on error, post-transaction on success.
        self.state = core::mem::take(backend.state_mut());
        // `backend`'s shared borrow of `vicinity` has ended, so it can move back out for the next tx.
        outcome
    }
}

/// Resolves the block's blob parameters after narrowing its untrusted timestamp without truncation.
///
/// `BlockEnv` uses the EVM-native [`U256`] timestamp, while chain schedules use `u64`. A direct
/// `as_u64` conversion would either truncate or panic (depending on the API used) for an adversarial
/// value above `u64::MAX`, so the execution boundary performs one checked conversion instead.
fn resolve_blob_params(
    chain: &ChainSpec,
    block: &BlockEnv,
) -> Result<Option<BlobParams>, BlockExecutionError> {
    let timestamp = u64::try_from(block.block_timestamp)
        .map_err(|_| BlockExecutionError::InvalidBlockTimestamp)?;
    Ok(chain.blob_params_at_timestamp(timestamp))
}

/// Whether `code` is an EIP-7702 delegation designation (`0xef0100 || address`), which lets an
/// account with code still originate transactions from Prague onward.
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

/// Runs one validated transaction against `backend`: reserve, run call/create, settle fees, apply the diff.
fn exec_tx_with_backend(
    backend: &mut MemoryBackend<'_>,
    exec: TxExec,
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
    // Take the transaction's logs for the receipt; the backend's own log history is unused.
    let logs: Vec<Log> = logs.into_iter().collect();
    backend.apply(values, core::iter::empty::<Log>(), true);

    Ok(TxExecutionOutcome {
        reason,
        gas_used,
        logs,
    })
}

/// The [`MemoryVicinity`] fields that belong to a *transaction* rather than to the block.
///
/// The vicinity is built once per block ([`block_vicinity`]) and reused, so every one of these has to
/// be overwritten before each transaction: a field left alone keeps the *previous* transaction's
/// value. Collecting them in one struct is what makes that checkable — [`Self::apply`] destructures
/// exhaustively, so adding a field here without assigning it there does not compile, and dropping an
/// assignment leaves an unused binding, which `warnings = deny` rejects. That is the mistake this
/// struct exists to prevent: `blob_hashes` was once dropped from the assignments it replaces, which
/// left `BLOBHASH` reading a block-level list.
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

/// Builds the block-level [`MemoryVicinity`]. The per-transaction fields are left at their defaults
/// and are set by [`TxVicinity::apply`] before every transaction.
fn block_vicinity(block: &BlockEnv, chain_id: u64) -> MemoryVicinity {
    MemoryVicinity {
        gas_price: U256::zero(),
        effective_gas_price: U256::zero(),
        origin: H160::zero(),
        block_hashes: block.block_hashes.clone(),
        block_number: block.block_number,
        block_coinbase: block.block_coinbase,
        block_timestamp: block.block_timestamp,
        block_difficulty: block.block_difficulty,
        block_gas_limit: U256::from(block.block_gas_limit),
        chain_id: U256::from(chain_id),
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
    use super::{BlockExecutionCounters, BlockExecutor, Precompiles, TransactionExecutionResult};
    use crate::block::BlobExcessGasAndPrice;
    use crate::block::BlockEnv;
    use crate::chain_spec::ChainSpec;
    use crate::eips::eip1559::BaseFeeParams;
    use crate::eips::eip7840::BlobParams;
    use crate::eips::eip7892::BlobScheduleBlobParams;
    use crate::errors::{BlockExecutionError, InvalidTransaction};
    use crate::evm_context::InvalidEvmContext;
    use crate::spec::Spec;
    use crate::transaction::{AccessList, AccessListItem, TxEnv, TxKind, TxType};
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

    /// A schedule with no timestamp-scheduled BPO entries; the fork defaults still apply.
    fn empty_blob_schedule() -> BlobScheduleBlobParams {
        BlobScheduleBlobParams::mainnet()
    }

    /// A trusted test configuration whose supported timestamp forks are active from genesis.
    fn chain_spec(spec: Spec, blob_schedule: BlobScheduleBlobParams) -> ChainSpec {
        ChainSpec {
            chain_id: 1,
            spec,
            hard_forks_timestamps: BTreeMap::from([
                (Spec::Cancun, 0),
                (Spec::Prague, 0),
                (Spec::Osaka, 0),
            ]),
            deposit_contract_address: None,
            base_fee_params: BaseFeeParams::ethereum(),
            blob_schedule,
        }
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
            parent_hash: H256::zero(),
            parent_beacon_block_root: None,
            withdrawals: vec![],
        }
    }

    /// A payload with the fields no test varies already filled in.
    fn payload(tx_type: TxType, to: H160, nonce: u64) -> TxEnv {
        TxEnv {
            caller: H160::zero(),
            authorization_list: vec![],
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
    fn transaction(mut env: TxEnv, caller: H160) -> TxEnv {
        env.caller = caller;
        env
    }

    fn eip1559_transfer(
        caller: H160,
        to: H160,
        value: U256,
        nonce: u64,
        max_fee: u64,
        max_priority: u64,
    ) -> TxEnv {
        let mut payload = payload(TxType::Eip1559, to, nonce);
        payload.value = value;
        payload.chain_id = Some(1);
        payload.max_fee_per_gas = Some(U256::from(max_fee));
        payload.max_priority_fee_per_gas = Some(U256::from(max_priority));
        transaction(payload, caller)
    }

    fn legacy_transfer(caller: H160, to: H160, value: U256, nonce: u64, gas_price: u64) -> TxEnv {
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
        txs: Vec<TxEnv>,
        blob_schedule: &BlobScheduleBlobParams,
    ) -> Result<TransactionExecutionResult, BlockExecutionError> {
        let executor = BlockExecutor::new(
            chain_spec(spec, blob_schedule.clone()),
            block(base_fee, addr(0xcb)),
            txs,
            state,
        )?;
        executor.execute_transactions()
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
        tx: TxEnv,
        state: &BTreeMap<H160, MemoryAccount>,
        spec: Spec,
        block: &BlockEnv,
        totals: BlockExecutionCounters,
    ) -> Result<(), BlockExecutionError> {
        validate_with(
            tx,
            state,
            &chain_spec(spec, osaka_blob_schedule()),
            block,
            totals,
        )
    }

    /// Validation as the loop performs it: through a real executor, so the blob parameters are the
    /// ones its constructor resolves rather than a value the test chose.
    fn validate_with(
        tx: TxEnv,
        state: &BTreeMap<H160, MemoryAccount>,
        chain: &ChainSpec,
        block: &BlockEnv,
        totals: BlockExecutionCounters,
    ) -> Result<(), BlockExecutionError> {
        BlockExecutor::new(chain.clone(), block.clone(), Vec::new(), state.clone())?
            .validate_transaction_for_block(tx, totals)
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
            validate(
                high,
                &state,
                Spec::London,
                &blk,
                BlockExecutionCounters::default()
            ),
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
            validate(
                tx,
                &state,
                Spec::London,
                &blk,
                BlockExecutionCounters::default()
            ),
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
            validate(
                tx.clone(),
                &state,
                Spec::London,
                &london_blk,
                BlockExecutionCounters::default()
            ),
            Err(BlockExecutionError::SenderHasCode)
        ));

        // From Prague the delegation designation lets it originate. (Prague >= Cancun requires the
        // blob header field to be present.)
        let mut prague_blk = block(0, addr(0xcb));
        prague_blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
        assert!(
            validate(
                tx,
                &state,
                Spec::Prague,
                &prague_blk,
                BlockExecutionCounters::default()
            )
            .is_ok()
        );
    }

    #[test]
    fn eip3860_init_code_size_boundary() {
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(1_000_000_000_000u64, 0, vec![]));
        let blk = block(0, addr(0xcb));

        let mut create = legacy_transfer(caller, addr(0x2e), U256::zero(), 0, 0);
        create.tx_kind = TxKind::Create;
        create.gas_limit = 20_000_000;

        // 49153 bytes → invalid (EIP-3860); exactly 49152 → not an InitCodeTooLarge error.
        let mut too_large = create.clone();
        too_large.data = vec![0x00; 49_153];
        assert!(matches!(
            validate(
                too_large,
                &state,
                Spec::Shanghai,
                &blk,
                BlockExecutionCounters::default()
            ),
            Err(BlockExecutionError::InitCodeTooLarge)
        ));

        let mut at_limit = create;
        at_limit.data = vec![0x00; 49_152];
        assert!(!matches!(
            validate(
                at_limit,
                &state,
                Spec::Shanghai,
                &blk,
                BlockExecutionCounters::default()
            ),
            Err(BlockExecutionError::InitCodeTooLarge)
        ));
    }

    /// EIP-155 replay protection is unconditional: there is no configuration in which a transaction
    /// signed for another chain is accepted, because the chain a block belongs to is a `u64` and not
    /// an `Option`. A typed transaction must also carry its own `chain_id` — it has no unsigned form.
    #[test]
    fn a_foreign_or_absent_chain_id_is_always_rejected() {
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, vec![]));
        let blk = block(0, addr(0xcb));

        let mut foreign = eip1559_transfer(caller, addr(0x2e), U256::zero(), 0, 10, 1);
        foreign.chain_id = Some(999);
        assert!(matches!(
            validate(
                foreign,
                &state,
                Spec::London,
                &blk,
                BlockExecutionCounters::default()
            ),
            Err(BlockExecutionError::InvalidContext(
                InvalidEvmContext::InvalidTransaction(InvalidTransaction::InvalidChainId)
            ))
        ));

        let mut absent = eip1559_transfer(caller, addr(0x2e), U256::zero(), 0, 10, 1);
        absent.chain_id = None;
        assert!(matches!(
            validate(
                absent,
                &state,
                Spec::London,
                &blk,
                BlockExecutionCounters::default()
            ),
            Err(BlockExecutionError::InvalidContext(
                InvalidEvmContext::InvalidTransaction(InvalidTransaction::MissingChainId)
            ))
        ));

        // A legacy transaction may omit it: that choice selects the pre-EIP-155 signing preimage.
        let mut legacy = eip1559_transfer(caller, addr(0x2e), U256::zero(), 0, 10, 1);
        legacy.tx_type = TxType::Legacy;
        legacy.gas_price = Some(U256::from(10u64));
        legacy.max_fee_per_gas = None;
        legacy.max_priority_fee_per_gas = None;
        legacy.chain_id = None;
        assert!(
            validate(
                legacy,
                &state,
                Spec::London,
                &blk,
                BlockExecutionCounters::default()
            )
            .is_ok()
        );
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
            validate(
                tx,
                &state,
                Spec::London,
                &blk,
                BlockExecutionCounters {
                    gas_used: 29_950_000,
                    blob_count: 0
                }
            ),
            Err(BlockExecutionError::BlockGasLimitExceeded { .. })
        ));
    }

    fn blob_tx(caller: H160, blobs: usize, nonce: u64) -> TxEnv {
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

    /// Runs a block against a caller-supplied [`BlockEnv`].
    fn run_in(
        blk: BlockEnv,
        spec: Spec,
        state: BTreeMap<H160, MemoryAccount>,
        txs: Vec<TxEnv>,
        blob_schedule: &BlobScheduleBlobParams,
    ) -> Result<TransactionExecutionResult, BlockExecutionError> {
        BlockExecutor::new(chain_spec(spec, blob_schedule.clone()), blk, txs, state)?
            .execute_transactions()
    }

    /// Osaka blob params scheduled from timestamp 0 (per-tx cap 6, per-block max 9).
    fn osaka_blob_schedule() -> BlobScheduleBlobParams {
        BlobScheduleBlobParams::mainnet().with_scheduled([(0, BlobParams::osaka())])
    }

    fn cancun_blob_block() -> BlockEnv {
        let mut blk = block(0, addr(0xcb));
        blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
        blk
    }

    #[test]
    fn per_transaction_blob_cap_is_enforced() {
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(u64::MAX, 0, vec![]));
        let blk = cancun_blob_block();
        // Osaka per-tx cap is 6: 6 blobs ok, 7 rejected.
        assert!(
            validate(
                blob_tx(caller, 6, 0),
                &state,
                Spec::Osaka,
                &blk,
                BlockExecutionCounters::default()
            )
            .is_ok()
        );
        assert!(matches!(
            validate(
                blob_tx(caller, 7, 0),
                &state,
                Spec::Osaka,
                &blk,
                BlockExecutionCounters::default()
            ),
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
            validate(
                blob_tx(caller, 6, 0),
                &state,
                Spec::Osaka,
                &blk,
                BlockExecutionCounters {
                    gas_used: 0,
                    blob_count: 6
                }
            ),
            Err(BlockExecutionError::BlockBlobLimitExceeded { count: 12, max: 9 })
        ));
        // 3 more fits exactly (6 + 3 = 9).
        assert!(
            validate(
                blob_tx(caller, 3, 0),
                &state,
                Spec::Osaka,
                &blk,
                BlockExecutionCounters {
                    gas_used: 0,
                    blob_count: 6
                }
            )
            .is_ok()
        );
    }

    #[test]
    fn invalid_block_timestamp_is_rejected() {
        let mut blk = block(0, addr(0xcb));
        blk.block_timestamp = U256::MAX; // does not fit in u64
        let result = BlockExecutor::new(
            chain_spec(Spec::Cancun, osaka_blob_schedule()),
            blk,
            vec![],
            BTreeMap::new(),
        );
        assert!(matches!(
            result,
            Err(BlockExecutionError::InvalidBlockTimestamp)
        ));
    }

    #[test]
    fn maximum_u64_block_timestamp_is_accepted() {
        let mut blk = block(0, addr(0xcb));
        blk.block_timestamp = U256::from(u64::MAX);
        let result = BlockExecutor::new(
            chain_spec(Spec::Cancun, empty_blob_schedule()),
            blk,
            vec![],
            BTreeMap::new(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn a_blob_tx_uses_the_fork_default_when_nothing_is_scheduled() {
        // A blob schedule always carries a per-fork default from Cancun on, so "no blob parameters"
        // is not a reachable state: an empty scheduled list falls back to the fork default.
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(u64::MAX, 0, vec![]));
        let mut blk = block(0, addr(0xcb));
        blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
        assert!(
            validate_with(
                blob_tx(caller, 1, 0),
                &state,
                &chain_spec(Spec::Osaka, empty_blob_schedule()),
                &blk,
                BlockExecutionCounters::default()
            )
            .is_ok()
        );
    }

    /// The redundant guard in step 8 fails **closed**.
    ///
    /// A Cancun chain always resolves blob parameters, so `BlockExecutor::new` cannot produce this
    /// state — the executor is therefore assembled field by field, which is the only way to reach the
    /// branch. The contract still has to hold: absent parameters must reject the block rather than
    /// skip the per-block blob limit. The verdict matches the one step 6 gives for the same input, so
    /// the two guards can never disagree.
    #[test]
    fn a_blob_tx_without_resolved_params_fails_closed() {
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(u64::MAX, 0, vec![]));
        let mut blk = block(0, addr(0xcb));
        blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
        let chain = chain_spec(Spec::Cancun, empty_blob_schedule());

        // Cancun, so the per-type validation in step 6 lets the blob transaction through, yet the
        // parameters are absent — a pairing the constructor refuses to make.
        let executor = BlockExecutor {
            precompiles: Precompiles::new(&chain.spec),
            blob_params: None,
            block: blk,
            chain,
            state,
            transactions: Vec::new(),
        };

        assert!(matches!(
            executor.validate_transaction_for_block(
                blob_tx(caller, 1, 0),
                BlockExecutionCounters::default()
            ),
            Err(BlockExecutionError::InvalidContext(
                InvalidEvmContext::InvalidTransaction(InvalidTransaction::Eip4844NotSupported)
            ))
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
        let executor = BlockExecutor::new(
            chain_spec(Spec::London, empty_blob_schedule()),
            block(0, caller), // coinbase == caller
            vec![tx],
            state,
        )
        .unwrap();
        let result = executor.execute_transactions().unwrap();
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
        tx.gas_limit = 100_000;
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
        tx.tx_kind = TxKind::Create;
        // PUSH1 0x00 PUSH1 0x00 RETURN — deploys empty runtime code.
        tx.data = vec![0x60, 0x00, 0x60, 0x00, 0xf3];
        tx.gas_limit = 200_000;
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
        // The rejection names the offending position, not just the reason: a block is rejected as a
        // whole, so without the index there is nothing to compare against another client.
        match run(Spec::London, 0, state, txs, &empty_blob_schedule()) {
            Err(BlockExecutionError::Transaction { index, source }) => {
                assert_eq!(index, 1);
                assert!(matches!(*source, BlockExecutionError::InvalidNonce { .. }));
            }
            other => panic!("expected a tagged invalid-nonce failure, got {other:?}"),
        }
    }

    /// Tagging is idempotent: an error that already names a position keeps it, so wrapping twice
    /// cannot bury the real cause under a second layer.
    #[test]
    fn tagging_an_already_tagged_error_keeps_the_inner_position() {
        let inner = BlockExecutionError::at_transaction(3, BlockExecutionError::SenderHasCode);
        let outer = BlockExecutionError::at_transaction(9, inner);
        match outer {
            BlockExecutionError::Transaction { index, source } => {
                assert_eq!(index, 3);
                assert!(matches!(*source, BlockExecutionError::SenderHasCode));
            }
            other => panic!("expected a tagged error, got {other:?}"),
        }
    }

    #[test]
    fn per_block_blob_limit_enforced_through_driver() {
        // End-to-end: the blob schedule is resolved by `BlockExecutor::new`, the first 5-blob tx executes,
        // and the second pushes the cumulative count to 10 > the Osaka per-block max of 9.
        let caller = addr(0xca);
        let mut state = BTreeMap::new();
        state.insert(caller, account(u64::MAX, 0, vec![]));
        let mut blk = block(0, addr(0xcb));
        blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
        let txs = vec![blob_tx(caller, 5, 0), blob_tx(caller, 5, 1)];
        let executor = BlockExecutor::new(
            chain_spec(Spec::Osaka, osaka_blob_schedule()),
            blk,
            txs,
            state,
        )
        .unwrap();
        match executor.execute_transactions() {
            Err(BlockExecutionError::Transaction { index, source }) => {
                assert_eq!(index, 1);
                assert!(matches!(
                    *source,
                    BlockExecutionError::BlockBlobLimitExceeded { count: 10, max: 9 }
                ));
            }
            other => panic!("expected a tagged blob-limit failure, got {other:?}"),
        }
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
        tx.gas_price = Some(U256::zero());
        let err = validate(
            tx,
            &state,
            Spec::London,
            &blk,
            BlockExecutionCounters::default(),
        )
        .unwrap_err();
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
        tx.blob_versioned_hashes = vec![U256::one()];
        let err = validate(
            tx,
            &state,
            Spec::London,
            &blk,
            BlockExecutionCounters::default(),
        )
        .unwrap_err();
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
        let executor = BlockExecutor::new(
            chain_spec(Spec::Osaka, osaka_blob_schedule()),
            blk,
            vec![tx],
            state,
        )
        .unwrap();
        let result = executor.execute_transactions().unwrap();

        assert!(result.receipts[0].success);
        let sum_after = balance_of(&result.state, caller)
            + balance_of(&result.state, to)
            + balance_of(&result.state, coinbase);
        let blob_fee = U256::from(2u64) * U256::from(crate::eips::eip4844::DATA_GAS_PER_BLOB); // 1 blob @ price 2
        assert_eq!(sum_after, U256::from(initial) - blob_fee);
    }

    #[test]
    fn a_cancun_block_resolves_the_fork_default_without_a_scheduled_entry() {
        let executor = BlockExecutor::new(
            chain_spec(Spec::Cancun, empty_blob_schedule()),
            block(0, addr(0xcb)),
            vec![],
            BTreeMap::new(),
        );
        assert!(executor.is_ok());
    }

    #[test]
    fn pre_cancun_block_ignores_blob_schedule() {
        // `Spec` is authoritative for the fork: a pre-Cancun block ignores the blob schedule
        // entirely (even one active at its timestamp), so construction succeeds and no blob
        // parameters are resolved — the schedule cannot turn it into a "blob block".
        let executor = BlockExecutor::new(
            chain_spec(Spec::London, osaka_blob_schedule()),
            block(0, addr(0xcb)),
            vec![],
            BTreeMap::new(),
        );
        assert!(executor.is_ok());
    }
    /// `PUSH1 index; BLOBHASH; PUSH1 0; SSTORE; STOP` — records `BLOBHASH(index)` in slot 0.
    fn store_blobhash(index: u8) -> Vec<u8> {
        vec![0x60, index, 0x49, 0x60, 0x00, 0x55, 0x00]
    }

    /// A KZG versioned hash whose last byte is `tag`.
    fn versioned_hash(tag: u8) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x01; // VERSIONED_HASH_VERSION_KZG
        bytes[31] = tag;
        U256::from_big_endian(&bytes)
    }

    /// A blob transaction carrying `hashes`, calling `to`.
    fn blob_tx_to(caller: H160, to: H160, hashes: Vec<U256>, nonce: u64) -> TxEnv {
        let mut payload = payload(TxType::Eip4844, to, nonce);
        payload.gas_limit = 1_000_000;
        payload.chain_id = Some(1);
        payload.max_fee_per_gas = Some(U256::from(100u64));
        payload.max_priority_fee_per_gas = Some(U256::one());
        payload.blob_versioned_hashes = hashes;
        payload.max_fee_per_blob_gas = 1_000_000;
        transaction(payload, caller)
    }

    fn slot_zero(state: &BTreeMap<H160, MemoryAccount>, who: H160) -> U256 {
        state
            .get(&who)
            .and_then(|account| account.storage.get(&H256::zero()).copied())
            .map(|value| U256::from_big_endian(value.as_bytes()))
            .unwrap_or_default()
    }

    #[test]
    fn blobhash_is_per_transaction() {
        // The regression HIGH-2: the vicinity is reused across the block, so a per-block
        // `blob_hashes` makes both transactions see the same list (or, when empty, no list at all).
        let (caller_a, caller_b) = (addr(0xa1), addr(0xb1));
        let (contract_a, contract_b) = (addr(0xc1), addr(0xc2));
        let mut state = BTreeMap::new();
        state.insert(caller_a, account(u64::MAX, 0, vec![]));
        state.insert(caller_b, account(u64::MAX, 0, vec![]));
        state.insert(contract_a, account(0, 0, store_blobhash(0)));
        state.insert(contract_b, account(0, 0, store_blobhash(0)));

        let result = run_in(
            cancun_blob_block(),
            Spec::Cancun,
            state,
            vec![
                blob_tx_to(caller_a, contract_a, vec![versioned_hash(0xaa)], 0),
                blob_tx_to(caller_b, contract_b, vec![versioned_hash(0xbb)], 0),
            ],
            &osaka_blob_schedule(),
        )
        .unwrap();

        assert!(result.receipts.iter().all(|receipt| receipt.success));
        assert_eq!(slot_zero(&result.state, contract_a), versioned_hash(0xaa));
        assert_eq!(slot_zero(&result.state, contract_b), versioned_hash(0xbb));
    }

    #[test]
    fn blobhash_is_not_stale_for_a_following_non_blob_tx() {
        // Pins the *unconditional* assignment: a fix that only wrote the field for EIP-4844
        // transactions would leave tx1 reading tx0's list.
        let caller = addr(0xa1);
        let (contract_a, contract_b) = (addr(0xc1), addr(0xc2));
        let mut state = BTreeMap::new();
        state.insert(caller, account(u64::MAX, 0, vec![]));
        state.insert(contract_a, account(0, 0, store_blobhash(0)));
        state.insert(contract_b, account(0, 0, store_blobhash(0)));

        let mut plain = payload(TxType::Eip1559, contract_b, 1);
        plain.gas_limit = 1_000_000;
        plain.chain_id = Some(1);
        plain.max_fee_per_gas = Some(U256::from(100u64));
        plain.max_priority_fee_per_gas = Some(U256::one());

        let result = run_in(
            cancun_blob_block(),
            Spec::Cancun,
            state,
            vec![
                blob_tx_to(caller, contract_a, vec![versioned_hash(0xaa)], 0),
                transaction(plain, caller),
            ],
            &osaka_blob_schedule(),
        )
        .unwrap();

        assert_eq!(slot_zero(&result.state, contract_a), versioned_hash(0xaa));
        assert_eq!(slot_zero(&result.state, contract_b), U256::zero());
    }

    #[test]
    fn blobhash_indexes_the_transactions_own_list() {
        // Reading index 1 of a two-hash transaction gives the *second* hash; index 1 of a one-hash
        // transaction gives zero (`unwrap_or(U256_ZERO)` in the interpreter).
        let (caller_a, caller_b) = (addr(0xa1), addr(0xb1));
        let (contract_a, contract_b) = (addr(0xc1), addr(0xc2));
        let mut state = BTreeMap::new();
        state.insert(caller_a, account(u64::MAX, 0, vec![]));
        state.insert(caller_b, account(u64::MAX, 0, vec![]));
        state.insert(contract_a, account(0, 0, store_blobhash(1)));
        state.insert(contract_b, account(0, 0, store_blobhash(1)));

        let result = run_in(
            cancun_blob_block(),
            Spec::Cancun,
            state,
            vec![
                blob_tx_to(
                    caller_a,
                    contract_a,
                    vec![versioned_hash(0xaa), versioned_hash(0xbb)],
                    0,
                ),
                blob_tx_to(caller_b, contract_b, vec![versioned_hash(0xcc)], 0),
            ],
            &osaka_blob_schedule(),
        )
        .unwrap();

        assert_eq!(slot_zero(&result.state, contract_a), versioned_hash(0xbb));
        assert_eq!(slot_zero(&result.state, contract_b), U256::zero());
    }

    #[test]
    fn legacy_tx_with_an_access_list_is_rejected() {
        // The access list is the one off-type field execution *reads*: it feeds intrinsic gas and
        // pre-warms slots, so a legacy transaction carrying one would change gas and the post-state.
        let caller = addr(0xca);
        let to = addr(0x2e);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, vec![]));
        // `PUSH1 1; SLOAD; POP; STOP` — the warming discount is observable.
        state.insert(to, account(0, 0, vec![0x60, 0x01, 0x54, 0x50, 0x00]));

        let mut with_list = legacy_transfer(caller, to, U256::zero(), 0, 10);
        with_list.access_list = AccessList(vec![AccessListItem {
            address: to,
            storage_keys: vec![H256::from_low_u64_be(1)],
        }]);
        let error = run(
            Spec::London,
            0,
            state.clone(),
            vec![with_list],
            &empty_blob_schedule(),
        )
        .unwrap_err();
        assert!(
            format!("{error}").contains("access list on a legacy transaction"),
            "{error}"
        );

        // Same transaction without the list executes, which is what the rejection above prevents
        // from silently costing more gas and warming a slot.
        let clean = legacy_transfer(caller, to, U256::zero(), 0, 10);
        let result = run(Spec::London, 0, state, vec![clean], &empty_blob_schedule()).unwrap();
        assert_eq!(result.gas_used, 23_105);
    }

    #[test]
    fn typed_transactions_keep_their_access_list() {
        // The guard is type-scoped: EIP-2930 and EIP-1559 still charge for and warm their list.
        let caller = addr(0xca);
        let to = addr(0x2e);
        let mut state = BTreeMap::new();
        state.insert(caller, account(10_000_000, 0, vec![]));
        state.insert(to, account(0, 0, vec![0x60, 0x01, 0x54, 0x50, 0x00]));
        let list = AccessList(vec![AccessListItem {
            address: to,
            storage_keys: vec![H256::from_low_u64_be(1)],
        }]);

        for tx_type in [TxType::Eip2930, TxType::Eip1559] {
            let mut payload = payload(tx_type, to, 0);
            payload.chain_id = Some(1);
            if tx_type == TxType::Eip2930 {
                payload.gas_price = Some(U256::from(10u64));
            } else {
                payload.max_fee_per_gas = Some(U256::from(10u64));
                payload.max_priority_fee_per_gas = Some(U256::from(10u64));
            }
            payload.access_list = list.clone();
            let result = run(
                Spec::London,
                0,
                state.clone(),
                vec![transaction(payload, caller)],
                &empty_blob_schedule(),
            )
            .unwrap_or_else(|err| panic!("{tx_type:?}: {err}"));
            // 21000 intrinsic + 2400 address + 1900 key + 3 PUSH + 100 warm SLOAD + 2 POP.
            assert_eq!(result.gas_used, 25_405, "{tx_type:?}");
        }
    }
}
