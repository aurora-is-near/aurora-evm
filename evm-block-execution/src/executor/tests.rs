mod witness_regressions;

use super::{
    BEACON_ROOTS_ADDRESS, BlockExecutionCounters, BlockExecutor,
    CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS, HISTORY_STORAGE_ADDRESS, Precompiles,
    WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
};
use crate::block::BlobExcessGasAndPrice;
use crate::block::BlockEnv;
use crate::chain_spec::ChainSpec;
use crate::eips::eip1559::BaseFeeParams;
use crate::eips::eip7840::BlobParams;
use crate::eips::eip7892::BlobScheduleBlobParams;
use crate::errors::{BlockExecutionError, InvalidTransaction};
use crate::evm_context::InvalidEvmContext;
use crate::execution_types::execution::BlockExecutionOutput;
use crate::receipt::Receipt;
use crate::spec::Spec;
use crate::transaction::{SignedTxEnvelope, TxEnv, TxKind, TxType};
use crate::witness_backend::{RevealedAccount, WitnessAccount, WitnessBackend, WitnessState};
use aurora_evm::backend::MemoryAccount;
use aurora_evm::executor::stack::PrecompileSet as _;
use hex_literal::hex;
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
        block_number: U256::from(1u64),
        block_coinbase: coinbase,
        block_timestamp: U256::from(1_000u64),
        block_difficulty: U256::zero(),
        block_gas_limit: 30_000_000,
        block_base_fee_per_gas: U256::from(spec_base_fee),
        block_randomness: Some(H256::zero()),
        blob_excess_gas_and_price: None,
        parent_hash: H256::zero(),
        parent_beacon_block_root: Some(H256::zero()),
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
        access_list: vec![],
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

/// An executed block: the transaction-phase totals and the state the backend returned.
#[derive(Debug)]
struct Run {
    receipts: Vec<Receipt>,
    gas_used: u64,
    state: WitnessState,
}

fn finish(output: BlockExecutionOutput) -> Run {
    Run {
        receipts: output.result.receipts,
        gas_used: output.result.gas_used,
        state: output.state,
    }
}

/// A complete-state backend over `state` for the block `blk`.
fn backend(blk: &BlockEnv, state: BTreeMap<H160, MemoryAccount>) -> WitnessBackend {
    WitnessBackend::from_full_state(blk.vicinity(1), state, BTreeMap::new())
}

fn present(state: &WitnessState, who: H160) -> Option<&WitnessAccount> {
    match state.accounts.get(&who) {
        Some(RevealedAccount::Present(account)) => Some(account),
        _ => None,
    }
}

fn balance_of(state: &WitnessState, who: H160) -> U256 {
    present(state, who)
        .map(|account| account.balance)
        .unwrap_or_default()
}

fn run(
    spec: Spec,
    base_fee: u64,
    state: BTreeMap<H160, MemoryAccount>,
    txs: Vec<TxEnv>,
    blob_schedule: &BlobScheduleBlobParams,
) -> Result<Run, BlockExecutionError> {
    run_in(block(base_fee, addr(0xcb)), spec, state, txs, blob_schedule)
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
    assert_eq!(
        present(&result.state, caller).unwrap().nonce,
        U256::from(2u64)
    );
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
    BlockExecutor::new(
        chain.clone(),
        block.clone(),
        Vec::new(),
        backend(block, state.clone()),
    )?
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

/// EIP-2681: a nonce of `u64::MAX` could never be incremented, so the transaction is invalid
/// even though it equals the sender's nonce.
#[test]
fn maximal_nonce_is_rejected_eip2681() {
    let caller = addr(0xca);
    let mut state = BTreeMap::new();
    state.insert(caller, account(10_000_000, u64::MAX, vec![]));
    let blk = block(0, addr(0xcb));

    let tx = eip1559_transfer(caller, addr(0x2e), U256::zero(), u64::MAX, 10, 1);
    assert!(matches!(
        validate(
            tx,
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

/// EEST v5.4.0 `test_empty_authorization_list` transaction fixture.
#[test]
fn eest_rejects_an_empty_eip7702_authorization_list() {
    let raw = hex!(
        "04f86401808007830186a09400000000000000000000000000000000000000008080c0c001"
        "a04319a2e8066a9beedd85b227bf40cdecfb6134e6c1254f1e680895bc3131df31a059efad54"
        "e662f062d9af60acca08efb1d3d312742e381a600aac7c7989f892cc"
    );
    let tx = SignedTxEnvelope::decode_2718(&raw)
        .unwrap()
        .into_tx_env(H160::zero());
    let mut blk = block(0, addr(0xcb));
    blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());

    assert!(matches!(
        validate(
            tx,
            &BTreeMap::new(),
            Spec::Prague,
            &blk,
            BlockExecutionCounters::default()
        ),
        Err(BlockExecutionError::InvalidContext(
            InvalidEvmContext::InvalidTransaction(InvalidTransaction::EmptyAuthorizationList)
        ))
    ));
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

/// Typed transactions require the configured chain id; legacy may use the pre-EIP-155 form.
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
) -> Result<Run, BlockExecutionError> {
    let backend = backend(&blk, state);
    BlockExecutor::new(chain_spec(spec, blob_schedule.clone()), blk, txs, backend)?
        .execute()
        .map(finish)
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
        blk.clone(),
        vec![],
        backend(&blk, BTreeMap::new()),
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
        blk.clone(),
        vec![],
        backend(&blk, BTreeMap::new()),
    );
    assert!(result.is_ok());
}

#[test]
fn execution_fork_is_resolved_from_the_block_timestamp() {
    let mut chain = chain_spec(Spec::Osaka, empty_blob_schedule());
    chain.hard_forks_timestamps =
        BTreeMap::from([(Spec::Cancun, 100), (Spec::Prague, 200), (Spec::Osaka, 300)]);
    let mut blk = block(0, addr(0xcb));
    blk.block_timestamp = U256::from(250u64);
    blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());

    let executor = BlockExecutor::new(
        chain.clone(),
        blk.clone(),
        vec![],
        backend(&blk, BTreeMap::new()),
    )
    .unwrap();
    assert_eq!(executor.active_spec, Spec::Prague);
    assert_eq!(executor.blob_params, Some(BlobParams::prague()));
    assert!(
        !executor
            .precompiles
            .is_precompile(H160::from_low_u64_be(0x100))
    );

    let caller = addr(0xca);
    let mut state = BTreeMap::new();
    state.insert(caller, account(u64::MAX, 0, vec![]));
    let mut tx = eip1559_transfer(caller, addr(0x2e), U256::zero(), 0, 0, 0);
    tx.gas_limit = 20_000_000;
    assert!(
        BlockExecutor::new(
            chain.clone(),
            blk.clone(),
            vec![],
            backend(&blk, state.clone())
        )
        .unwrap()
        .validate_transaction_for_block(tx.clone(), BlockExecutionCounters::default())
        .is_ok()
    );

    let mut osaka_block = block(0, addr(0xcb));
    osaka_block.block_timestamp = U256::from(300u64);
    osaka_block.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
    let executor = BlockExecutor::new(
        chain,
        osaka_block.clone(),
        vec![],
        backend(&osaka_block, state),
    )
    .unwrap();
    assert_eq!(executor.active_spec, Spec::Osaka);
    assert!(
        executor
            .precompiles
            .is_precompile(H160::from_low_u64_be(0x100))
    );
    assert!(matches!(
        executor.validate_transaction_for_block(tx, BlockExecutionCounters::default()),
        Err(BlockExecutionError::InvalidContext(
            InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::TxGasLimitGreaterThanCap { .. }
            )
        ))
    ));
}

#[test]
fn cancun_or_later_execution_fails_when_no_supported_fork_is_active() {
    let mut chain = chain_spec(Spec::Osaka, empty_blob_schedule());
    chain.hard_forks_timestamps =
        BTreeMap::from([(Spec::Cancun, 100), (Spec::Prague, 200), (Spec::Osaka, 300)]);
    let mut blk = block(0, addr(0xcb));
    blk.block_timestamp = U256::from(99u64);

    assert!(matches!(
        BlockExecutor::new(chain, blk.clone(), vec![], backend(&blk, BTreeMap::new())),
        Err(BlockExecutionError::ActiveSpecUnavailable { timestamp: 99 })
    ));
}

#[test]
fn a_blob_tx_uses_the_fork_default_when_nothing_is_scheduled() {
    // An active Cancun-or-later fork falls back to its per-fork default when no BPO entry is
    // scheduled.
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

/// Missing blob parameters fail closed even when the executor is assembled outside its
/// constructor.
#[test]
fn a_blob_tx_without_resolved_params_fails_closed() {
    let caller = addr(0xca);
    let mut state = BTreeMap::new();
    state.insert(caller, account(u64::MAX, 0, vec![]));
    let mut blk = block(0, addr(0xcb));
    blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
    let chain = chain_spec(Spec::Cancun, empty_blob_schedule());

    // Cancun context validation accepts the transaction, but the missing schedule parameters
    // must still make the block-level limit fail closed.
    let executor = BlockExecutor {
        active_spec: Spec::Cancun,
        precompiles: Precompiles::new(&Spec::Cancun),
        blob_params: None,
        backend: backend(&blk, state),
        block: blk,
        chain,
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
    let blk = block(0, caller); // coinbase == caller
    let executor = BlockExecutor::new(
        chain_spec(Spec::London, empty_blob_schedule()),
        blk.clone(),
        vec![tx],
        backend(&blk, state),
    )
    .unwrap();
    let result = finish(executor.execute().unwrap());
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

/// Re-tagging an indexed error preserves its original transaction position.
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
        blk.clone(),
        txs,
        backend(&blk, state),
    )
    .unwrap();
    match executor.execute() {
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
    let mut state = system_contracts();
    state.insert(caller, account(initial, 0, vec![]));
    let mut blk = block(0, coinbase);
    blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice {
        excess_blob_gas: 0,
        blob_gas_price: 2,
    });
    let tx = blob_tx(caller, 1, 0); // one blob
    let executor = BlockExecutor::new(
        chain_spec(Spec::Osaka, osaka_blob_schedule()),
        blk.clone(),
        vec![tx],
        backend(&blk, state),
    )
    .unwrap();
    let result = finish(executor.execute().unwrap());

    assert!(result.receipts[0].success);
    let sum_after = balance_of(&result.state, caller)
        + balance_of(&result.state, to)
        + balance_of(&result.state, coinbase);
    let blob_fee = U256::from(2u64) * U256::from(crate::eips::eip4844::DATA_GAS_PER_BLOB); // 1 blob @ price 2
    assert_eq!(sum_after, U256::from(initial) - blob_fee);
}

#[test]
fn a_cancun_block_resolves_the_fork_default_without_a_scheduled_entry() {
    let blk = block(0, addr(0xcb));
    let executor = BlockExecutor::new(
        chain_spec(Spec::Cancun, empty_blob_schedule()),
        blk.clone(),
        vec![],
        backend(&blk, BTreeMap::new()),
    );
    assert!(executor.is_ok());
}

#[test]
fn pre_cancun_block_ignores_blob_schedule() {
    // `Spec` is authoritative for the fork: a pre-Cancun block ignores the blob schedule
    // entirely (even one active at its timestamp), so construction succeeds and no blob
    // parameters are resolved — the schedule cannot turn it into a "blob block".
    let blk = block(0, addr(0xcb));
    let executor = BlockExecutor::new(
        chain_spec(Spec::London, osaka_blob_schedule()),
        blk.clone(),
        vec![],
        backend(&blk, BTreeMap::new()),
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

fn slot_zero(state: &WitnessState, who: H160) -> U256 {
    present(state, who)
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
    with_list.access_list = vec![(to, vec![H256::from_low_u64_be(1)])];
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
    let list = vec![(to, vec![H256::from_low_u64_be(1)])];

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

// --- system calls, requests and withdrawals ---

/// Runtime code of the four protocol system contracts, as deployed on mainnet.
const EIP4788_CODE: &[u8] = &hex!(
    "3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff"
    "810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff0155"
    "00"
);
const EIP2935_CODE: &[u8] = &hex!(
    "3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81"
    "430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500"
);
const EIP7002_CODE: &[u8] = &hex!(
    "3373fffffffffffffffffffffffffffffffffffffffe1460cb5760115f54807fffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffff146101f457600182026001905f5b5f8211156068578101908302848302900491"
    "6001019190604d565b909390049250505036603814608857366101f457346101f4575f5260205ff35b34106101f45760"
    "0154600101600155600354806003026004013381556001015f35815560010160203590553360601b5f5260385f601437"
    "604c5fa0600101600355005b6003546002548082038060101160df575060105b5f5b8181146101835782810160030260"
    "040181604c02815460601b8152601401816001015481526020019060020154807fffffffffffffffffffffffffffffff"
    "ff00000000000000000000000000000000168252906010019060401c908160381c81600701538160301c816006015381"
    "60281c81600501538160201c81600401538160181c81600301538160101c81600201538160081c816001015353600101"
    "60e1565b910180921461019557906002556101a0565b90505f6002555f6003555b5f54807fffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffff14156101cd57505f5b6001546002828201116101e25750505f6101"
    "e8565b01600290035b5f555f600155604c025ff35b5f5ffd"
);
const EIP7251_CODE: &[u8] = &hex!(
    "3373fffffffffffffffffffffffffffffffffffffffe1460d35760115f54807fffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffff1461019a57600182026001905f5b5f8211156068578101908302848302900491"
    "6001019190604d565b9093900492505050366060146088573661019a573461019a575f5260205ff35b341061019a5760"
    "0154600101600155600354806004026004013381556001015f358155600101602035815560010160403590553360601b"
    "5f5260605f60143760745fa0600101600355005b6003546002548082038060021160e7575060025b5f5b818114610129"
    "5782810160040260040181607402815460601b8152601401816001015481526020018160020154815260200190600301"
    "54905260010160e9565b910180921461013b5790600255610146565b90505f6002555f6003555b5f54807fffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffff141561017357505f5b600154600182820111610188"
    "5750505f61018e565b01600190035b5f555f6001556074025ff35b5f5ffd"
);

/// The four system contracts with their mainnet code and no other state.
fn system_contracts() -> BTreeMap<H160, MemoryAccount> {
    [
        (BEACON_ROOTS_ADDRESS, EIP4788_CODE),
        (HISTORY_STORAGE_ADDRESS, EIP2935_CODE),
        (WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS, EIP7002_CODE),
        (CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS, EIP7251_CODE),
    ]
    .into_iter()
    .map(|(address, code)| (address, account(0, 1, code.to_vec())))
    .collect()
}

fn slot_of(state: &WitnessState, who: H160, slot: u64) -> H256 {
    present(state, who)
        .and_then(|account| account.storage.get(&H256::from_low_u64_be(slot)).copied())
        .unwrap_or_default()
}

/// A Prague block at height `number` with the given parent hash and beacon root.
fn prague_block(number: u64, parent_hash: H256, beacon_root: Option<H256>) -> BlockEnv {
    let mut blk = block(0, addr(0xcb));
    blk.block_number = U256::from(number);
    blk.block_timestamp = U256::from(20_000u64);
    blk.parent_hash = parent_hash;
    blk.parent_beacon_block_root = beacon_root;
    blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
    blk
}

fn execute(
    spec: Spec,
    blk: BlockEnv,
    state: BTreeMap<H160, MemoryAccount>,
    txs: Vec<TxEnv>,
) -> Result<BlockExecutionOutput, BlockExecutionError> {
    let backend = backend(&blk, state);
    BlockExecutor::new(chain_spec(spec, osaka_blob_schedule()), blk, txs, backend)?.execute()
}

#[test]
fn pre_execution_calls_record_the_parent_hash_and_beacon_root() {
    let parent_hash = H256::repeat_byte(0x51);
    let beacon_root = H256::repeat_byte(0xbe);
    let blk = prague_block(7, parent_hash, Some(beacon_root));
    let output = execute(Spec::Prague, blk, system_contracts(), vec![]).unwrap();

    // EIP-4788: `timestamp % 8191` holds the timestamp, the slot 8191 above it the root.
    let timestamp_slot = 20_000 % 8191;
    assert_eq!(
        slot_of(&output.state, BEACON_ROOTS_ADDRESS, timestamp_slot),
        H256::from_low_u64_be(20_000)
    );
    assert_eq!(
        slot_of(&output.state, BEACON_ROOTS_ADDRESS, timestamp_slot + 8191),
        beacon_root
    );
    // EIP-2935: `(number - 1) % 8191` holds the parent hash.
    assert_eq!(
        slot_of(&output.state, HISTORY_STORAGE_ADDRESS, 6),
        parent_hash
    );
    // Empty request queues yield no requests, and the call itself costs the block nothing.
    assert!(output.result.requests.is_empty());
    assert_eq!(output.result.gas_used, 0);
    assert!(output.result.receipts.is_empty());
}

#[test]
fn cancun_makes_only_the_beacon_root_call_and_gathers_no_requests() {
    let blk = prague_block(7, H256::repeat_byte(0x51), Some(H256::repeat_byte(0xbe)));
    // No request contracts deployed: Cancun must not need them.
    let mut state = BTreeMap::new();
    state.insert(BEACON_ROOTS_ADDRESS, account(0, 1, EIP4788_CODE.to_vec()));
    state.insert(
        HISTORY_STORAGE_ADDRESS,
        account(0, 1, EIP2935_CODE.to_vec()),
    );
    let output = execute(Spec::Cancun, blk, state, vec![]).unwrap();

    assert_eq!(
        slot_of(&output.state, BEACON_ROOTS_ADDRESS, 20_000 % 8191 + 8191),
        H256::repeat_byte(0xbe)
    );
    assert_eq!(
        slot_of(&output.state, HISTORY_STORAGE_ADDRESS, 6),
        H256::zero(),
        "EIP-2935 starts at Prague"
    );
    assert!(output.result.requests.is_empty());
}

#[test]
fn genesis_makes_no_system_calls() {
    let blk = prague_block(0, H256::repeat_byte(0x51), Some(H256::repeat_byte(0xbe)));
    let output = execute(Spec::Prague, blk, system_contracts(), vec![]).unwrap();
    for address in [BEACON_ROOTS_ADDRESS, HISTORY_STORAGE_ADDRESS] {
        let RevealedAccount::Present(contract) = &output.state.accounts[&address] else {
            panic!("deployed");
        };
        assert!(contract.storage.is_empty(), "{address:?}");
    }
}

#[test]
fn a_missing_beacon_root_is_rejected_from_cancun() {
    let blk = prague_block(7, H256::repeat_byte(0x51), None);
    assert_eq!(
        execute(Spec::Cancun, blk, system_contracts(), vec![]).unwrap_err(),
        BlockExecutionError::MissingParentBeaconBlockRoot
    );
}

/// Before Cancun the beacon-root call does not exist, so a `None` root is fine and an
/// absent contract is never touched.
#[test]
fn pre_cancun_blocks_make_no_system_calls() {
    let mut blk = prague_block(7, H256::repeat_byte(0x51), None);
    blk.blob_excess_gas_and_price = None;
    let output = execute(Spec::Shanghai, blk, BTreeMap::new(), vec![]).unwrap();
    assert!(output.state.accounts.is_empty());
}

#[test]
fn absent_pre_execution_contracts_are_a_no_op_not_an_error() {
    // Cancun with no 4788 contract deployed: the call to an empty account succeeds and leaves
    // nothing behind (EEST `test_no_beacon_root_contract_at_transition`).
    let blk = prague_block(7, H256::repeat_byte(0x51), Some(H256::repeat_byte(0xbe)));
    let output = execute(Spec::Cancun, blk, BTreeMap::new(), vec![]).unwrap();
    // Touched and found EIP-161 empty: proven absent, never present.
    assert!(!matches!(
        output.state.accounts.get(&BEACON_ROOTS_ADDRESS),
        Some(RevealedAccount::Present(_))
    ));
}

#[test]
fn reverted_or_halted_pre_execution_calls_do_not_invalidate_the_block() {
    for target in [HISTORY_STORAGE_ADDRESS, BEACON_ROOTS_ADDRESS] {
        for ending in [vec![0x5f, 0x5f, 0xfd], vec![0xfe]] {
            let mut code = vec![0x60, 0x01, 0x5f, 0x55]; // SSTORE(0, 1)
            code.extend(ending);
            let mut state = system_contracts();
            state.insert(target, account(0, 1, code));
            let blk = prague_block(7, H256::zero(), Some(H256::zero()));
            let output = execute(Spec::Prague, blk, state, vec![]).unwrap();
            assert_eq!(slot_of(&output.state, target, 0), H256::zero());
            assert_eq!(output.result.gas_used, 0);
            assert!(output.result.receipts.is_empty());
        }
    }
}

#[test]
fn request_contracts_must_have_code_from_prague() {
    let blk = prague_block(7, H256::repeat_byte(0x51), Some(H256::repeat_byte(0xbe)));
    let mut state = system_contracts();
    state.remove(&CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS);
    assert_eq!(
        execute(Spec::Prague, blk.clone(), state, vec![]).unwrap_err(),
        BlockExecutionError::SystemContractEmpty {
            address: CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS
        }
    );
    // The withdrawal contract is checked first.
    assert_eq!(
        execute(Spec::Prague, blk, BTreeMap::new(), vec![]).unwrap_err(),
        BlockExecutionError::SystemContractEmpty {
            address: WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS
        }
    );
}

#[test]
fn a_failing_request_contract_invalidates_the_block() {
    let blk = prague_block(7, H256::repeat_byte(0x51), Some(H256::repeat_byte(0xbe)));
    // PUSH0 PUSH0 REVERT
    let mut state = system_contracts();
    state.insert(
        WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
        account(0, 1, vec![0x5f, 0x5f, 0xfd]),
    );
    assert!(matches!(
        execute(Spec::Prague, blk.clone(), state, vec![]).unwrap_err(),
        BlockExecutionError::WithdrawalRequestsContractCall {
            reason: aurora_evm::ExitReason::Revert(_)
        }
    ));
    // JUMPDEST PUSH0 JUMP — out of gas at the 30M system-call limit.
    let mut state = system_contracts();
    state.insert(
        CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
        account(0, 1, vec![0x5b, 0x5f, 0x56]),
    );
    assert!(matches!(
        execute(Spec::Prague, blk, state, vec![]).unwrap_err(),
        BlockExecutionError::ConsolidationRequestsContractCall {
            reason: aurora_evm::ExitReason::Error(_)
        }
    ));
}

/// Bytecode that emits `LOG1(topic, data)` with `data` copied from its own code.
fn log_emitter(topic: H256, data: &[u8]) -> Vec<u8> {
    let size = u16::try_from(data.len()).expect("test data is short");
    let mut code = Vec::new();
    // PUSH2 size, PUSH2 data_offset, PUSH0, CODECOPY
    code.extend([0x61]);
    code.extend(size.to_be_bytes());
    code.extend([0x61, 0x00, 0x00, 0x5f, 0x39]);
    // PUSH32 topic, PUSH2 size, PUSH0, LOG1, STOP
    code.push(0x7f);
    code.extend(topic.as_bytes());
    code.extend([0x61]);
    code.extend(size.to_be_bytes());
    code.extend([0x5f, 0xa1, 0x00]);
    let data_offset = u16::try_from(code.len()).expect("short prelude");
    code[4..6].copy_from_slice(&data_offset.to_be_bytes());
    code.extend_from_slice(data);
    code
}

/// A canonically laid out `DepositEvent` whose five fields are filled with `fill`.
fn deposit_event_data(fill: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(576);
    for offset in [160u64, 256, 320, 384, 512] {
        data.extend(H256::from_low_u64_be(offset).as_bytes());
    }
    for size in [48u64, 32, 8, 96, 8] {
        data.extend(H256::from_low_u64_be(size).as_bytes());
        let padded = usize::try_from(size).unwrap().div_ceil(32) * 32;
        data.extend(core::iter::repeat_n(fill, usize::try_from(size).unwrap()));
        data.extend(core::iter::repeat_n(
            0,
            padded - usize::try_from(size).unwrap(),
        ));
    }
    assert_eq!(data.len(), 576);
    data
}

/// Request contract returning `len` zero bytes: PUSH2 len, PUSH0, RETURN.
fn returning(len: u16) -> Vec<u8> {
    let mut code = vec![0x61];
    code.extend(len.to_be_bytes());
    code.extend([0x5f, 0xf3]);
    code
}

#[test]
fn requests_are_gathered_by_type_in_order() {
    use crate::eips::eip6110::{DEPOSIT_EVENT_SIGNATURE_HASH, MAINNET_DEPOSIT_CONTRACT_ADDRESS};
    use crate::requests::request_type;

    let caller = addr(0xca);
    let blk = prague_block(7, H256::repeat_byte(0x51), Some(H256::repeat_byte(0xbe)));
    let mut state = system_contracts();
    state.insert(caller, account(u64::MAX, 0, vec![]));
    // A deposit-contract stand-in that emits one canonical deposit event per call.
    state.insert(
        MAINNET_DEPOSIT_CONTRACT_ADDRESS,
        account(
            0,
            1,
            log_emitter(DEPOSIT_EVENT_SIGNATURE_HASH, &deposit_event_data(0xab)),
        ),
    );
    // Stand-ins for the request contracts: 76 bytes of withdrawal requests, no consolidations.
    state.insert(
        WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
        account(0, 1, returning(76)),
    );
    state.insert(
        CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS,
        account(0, 1, returning(0)),
    );

    let mut tx = eip1559_transfer(
        caller,
        MAINNET_DEPOSIT_CONTRACT_ADDRESS,
        U256::zero(),
        0,
        10,
        1,
    );
    tx.gas_limit = 1_000_000;
    let output = execute(Spec::Prague, blk, state, vec![tx]).unwrap();

    assert!(output.result.receipts[0].success);
    let requests = output.result.requests.as_slice();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(requests[0][0], request_type::DEPOSIT);
    assert_eq!(requests[0].len(), 1 + 192);
    assert!(requests[0][1..].iter().all(|byte| *byte == 0xab));
    assert_eq!(requests[1][0], request_type::WITHDRAWAL);
    assert_eq!(requests[1].len(), 1 + 76);
}

#[test]
fn a_malformed_deposit_log_invalidates_the_block() {
    use crate::eips::eip6110::{DEPOSIT_EVENT_SIGNATURE_HASH, MAINNET_DEPOSIT_CONTRACT_ADDRESS};

    let caller = addr(0xca);
    let blk = prague_block(7, H256::repeat_byte(0x51), Some(H256::repeat_byte(0xbe)));
    let mut state = system_contracts();
    state.insert(caller, account(u64::MAX, 0, vec![]));
    let mut data = deposit_event_data(0xab);
    data.truncate(575);
    state.insert(
        MAINNET_DEPOSIT_CONTRACT_ADDRESS,
        account(0, 1, log_emitter(DEPOSIT_EVENT_SIGNATURE_HASH, &data)),
    );
    let mut tx = eip1559_transfer(
        caller,
        MAINNET_DEPOSIT_CONTRACT_ADDRESS,
        U256::zero(),
        0,
        10,
        1,
    );
    tx.gas_limit = 1_000_000;
    assert!(matches!(
        execute(Spec::Prague, blk, state, vec![tx]).unwrap_err(),
        BlockExecutionError::DepositRequestDecode(_)
    ));
}

#[test]
fn withdrawals_are_credited_after_the_transactions() {
    use crate::withdrawal::Withdrawal;

    let existing = addr(0xe1);
    let fresh = addr(0xf1);
    let untouched = addr(0x00);
    let withdrawal = |address, amount| Withdrawal {
        index: 0,
        validator_index: 0,
        address,
        amount,
    };
    let empty = addr(0xee);
    let mut blk = prague_block(7, H256::repeat_byte(0x51), Some(H256::repeat_byte(0xbe)));
    blk.withdrawals = vec![
        withdrawal(existing, 2),
        withdrawal(fresh, 3),
        withdrawal(fresh, 4),
        // A zero amount must not create an account ...
        withdrawal(untouched, 0),
        // ... but it touches one, so an EIP-161-empty recipient is cleared.
        withdrawal(empty, 0),
    ];
    let mut state = system_contracts();
    state.insert(existing, account(10, 0, vec![]));
    state.insert(empty, account(0, 0, vec![]));
    let output = execute(Spec::Prague, blk, state, vec![]).unwrap();

    let gwei = U256::from(1_000_000_000u64);
    assert_eq!(
        balance_of(&output.state, existing),
        U256::from(10u64) + gwei * 2
    );
    assert_eq!(balance_of(&output.state, fresh), gwei * 7);
    assert!(present(&output.state, untouched).is_none());
    assert_eq!(
        output.state.accounts.get(&empty),
        Some(&RevealedAccount::Absent)
    );
}

/// Pruning after all withdrawals preserves storage when a zero credit precedes a funding one.
/// Pruning between credits would delete the empty account and recreate it without its storage.
#[test]
fn a_zero_withdrawal_before_a_funding_one_preserves_storage() {
    use crate::withdrawal::Withdrawal;

    let empty = addr(0xee);
    let withdrawal = |amount| Withdrawal {
        index: 0,
        validator_index: 0,
        address: empty,
        amount,
    };
    let mut blk = prague_block(7, H256::repeat_byte(0x51), Some(H256::repeat_byte(0xbe)));
    blk.withdrawals = vec![withdrawal(0), withdrawal(5)];
    let mut state = system_contracts();
    let slot = H256::repeat_byte(0x01);
    let value = H256::repeat_byte(0x42);
    let mut recipient = account(0, 0, vec![]);
    recipient.storage.insert(slot, value);
    state.insert(empty, recipient);

    let output = execute(Spec::Prague, blk, state, vec![]).unwrap();
    let recipient = present(&output.state, empty).expect("the funded recipient must exist");

    assert_eq!(recipient.balance, U256::from(1_000_000_000u64) * 5);
    assert_eq!(recipient.storage.get(&slot), Some(&value));
    assert!(!recipient.storage_wiped);
}

#[test]
fn withdrawals_are_ignored_before_shanghai() {
    use crate::withdrawal::Withdrawal;

    let mut blk = block(0, addr(0xcb));
    blk.withdrawals = vec![Withdrawal {
        index: 0,
        validator_index: 0,
        address: addr(0xe1),
        amount: 5,
    }];
    let output = execute(Spec::London, blk, BTreeMap::new(), vec![]).unwrap();
    assert!(output.state.accounts.is_empty());
}

/// An unrevealed sender reads as an empty account, which validation would call "out of
/// funds"; the witness gap must win, because the block is unprovable, not invalid.
#[test]
fn an_unrevealed_sender_is_a_witness_gap_not_an_invalid_transaction() {
    let caller = addr(0xca);
    let blk = block(0, addr(0xcb));
    let backend = WitnessBackend::try_new(
        blk.vicinity(1),
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
    )
    .unwrap();
    let tx = eip1559_transfer(caller, addr(0x2e), U256::from(1u64), 0, 10, 1);
    let error = BlockExecutor::new(
        chain_spec(Spec::London, empty_blob_schedule()),
        blk,
        vec![tx],
        backend,
    )
    .unwrap()
    .execute()
    .unwrap_err();
    assert_eq!(
        error,
        BlockExecutionError::MissingWitness(crate::witness_backend::WitnessDbError::Account {
            address: caller
        })
    );
}

/// In witness mode every account execution touches must be proven; the recipient here is not.
#[test]
fn an_unrevealed_recipient_fails_the_block() {
    let caller = addr(0xca);
    let to = addr(0x2e);
    let blk = block(0, addr(0xcb));
    let mut revealed = BTreeMap::new();
    revealed.insert(
        caller,
        RevealedAccount::Present(WitnessAccount {
            balance: U256::from(10_000_000u64),
            ..WitnessAccount::empty()
        }),
    );
    revealed.insert(addr(0xcb), RevealedAccount::Absent);
    let backend =
        WitnessBackend::try_new(blk.vicinity(1), revealed, Vec::new(), BTreeMap::new()).unwrap();
    let tx = eip1559_transfer(caller, to, U256::from(1u64), 0, 10, 1);
    let error = BlockExecutor::new(
        chain_spec(Spec::London, empty_blob_schedule()),
        blk,
        vec![tx],
        backend,
    )
    .unwrap()
    .execute()
    .unwrap_err();
    assert!(
        matches!(
            error,
            BlockExecutionError::MissingWitness(crate::witness_backend::WitnessDbError::Account { address }) if address == to
        ),
        "{error:?}"
    );
}
