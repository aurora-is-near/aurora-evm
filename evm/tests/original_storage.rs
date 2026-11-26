//! SSTORE must distinguish the transaction-entry value from later journal writes.

use std::collections::BTreeMap;

use aurora_evm::backend::{ApplyBackend, Backend, MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{
    MemoryStackState, StackExecutor, StackState, StackSubstateMetadata,
};
use aurora_evm::Config;
use primitive_types::{H160, H256, U256};

const ADDRESS: H160 = H160([0xaa; 20]);
const CALLER: H160 = H160([0xca; 20]);
const SLOT: H256 = H256([1; 32]);
const GAS_LIMIT: u64 = 100_000;

fn vicinity() -> MemoryVicinity {
    MemoryVicinity {
        gas_price: U256::one(),
        effective_gas_price: U256::one(),
        origin: CALLER,
        chain_id: U256::one(),
        block_hashes: vec![],
        block_number: U256::one(),
        block_coinbase: H160::zero(),
        block_timestamp: U256::one(),
        block_difficulty: U256::zero(),
        block_randomness: None,
        block_gas_limit: U256::from(30_000_000),
        block_base_fee_per_gas: U256::zero(),
        blob_gas_price: None,
        blob_hashes: vec![],
    }
}

fn backend(vicinity: &MemoryVicinity, code: Vec<u8>) -> MemoryBackend<'_> {
    let contract = MemoryAccount {
        code,
        storage: BTreeMap::from([(SLOT, H256::from_low_u64_be(1))]),
        ..MemoryAccount::default()
    };
    MemoryBackend::new(vicinity, BTreeMap::from([(ADDRESS, contract)]))
}

#[test]
fn original_follows_storage_resets_across_commit_and_revert() {
    let vicinity = vicinity();
    let config = Config::prague();
    let backend = backend(&vicinity, vec![]);
    let mut state = MemoryStackState::new(StackSubstateMetadata::new(GAS_LIMIT, &config), &backend);
    let absent = H256::zero();
    let written = H256::from_low_u64_be(2);
    state.set_storage(ADDRESS, SLOT, written);
    state.set_storage(ADDRESS, absent, written);
    state.set_storage(CALLER, SLOT, written);

    assert_eq!(
        state.original_storage(ADDRESS, SLOT),
        H256::from_low_u64_be(1)
    );
    assert_eq!(state.original_storage(ADDRESS, absent), H256::zero());

    state.enter(0, false);
    state.reset_storage(ADDRESS);
    state.enter(0, false);

    assert_eq!(state.original_storage(ADDRESS, SLOT), H256::zero());

    state.exit_commit().unwrap();
    state.exit_revert().unwrap();

    assert_eq!(
        state.original_storage(ADDRESS, SLOT),
        H256::from_low_u64_be(1)
    );
    assert_eq!(state.storage(ADDRESS, SLOT), written);

    state.enter(0, false);
    state.reset_storage(ADDRESS);
    state.set_storage(ADDRESS, absent, H256::from_low_u64_be(3));
    state.exit_commit().unwrap();

    assert_eq!(state.original_storage(ADDRESS, SLOT), H256::zero());
    assert_eq!(state.storage(ADDRESS, SLOT), H256::zero());
    assert_eq!(state.storage(ADDRESS, absent), H256::from_low_u64_be(3));
    assert_eq!(state.storage(CALLER, SLOT), written);
}

#[test]
fn committing_a_child_touch_preserves_the_parent_reset_and_later_writes() {
    let vicinity = vicinity();
    let config = Config::prague();
    let mut backend = backend(&vicinity, vec![]);
    let mut state = MemoryStackState::new(StackSubstateMetadata::new(GAS_LIMIT, &config), &backend);
    let other_slot = H256::zero();
    let written = H256::from_low_u64_be(7);
    state.reset_storage(ADDRESS);
    state.set_storage(ADDRESS, other_slot, written);
    state.enter(0, false);
    state.touch(ADDRESS);
    state.exit_commit().unwrap();

    assert_eq!(state.original_storage(ADDRESS, SLOT), H256::zero());
    assert_eq!(state.storage(ADDRESS, SLOT), H256::zero());
    assert_eq!(state.storage(ADDRESS, other_slot), written);

    let (updates, logs) = state.deconstruct();
    backend.apply(updates, logs, false);

    assert_eq!(backend.storage(ADDRESS, SLOT), H256::zero());
    assert_eq!(backend.storage(ADDRESS, other_slot), written);
}

#[test]
fn child_nonce_changes_follow_the_frame_outcome_without_undoing_a_parent_reset() {
    let vicinity = vicinity();
    let config = Config::prague();
    let backend = backend(&vicinity, vec![]);
    let mut state = MemoryStackState::new(StackSubstateMetadata::new(GAS_LIMIT, &config), &backend);
    state.reset_storage(ADDRESS);
    state.enter(0, false);
    state.inc_nonce(ADDRESS).unwrap();
    state.exit_revert().unwrap();

    assert_eq!(state.basic(ADDRESS).nonce, U256::zero());
    assert_eq!(state.original_storage(ADDRESS, SLOT), H256::zero());

    state.enter(0, false);
    state.inc_nonce(ADDRESS).unwrap();
    state.exit_commit().unwrap();

    assert_eq!(state.basic(ADDRESS).nonce, U256::one());
    assert_eq!(state.original_storage(ADDRESS, SLOT), H256::zero());
}

#[test]
fn sstore_prices_clean_and_dirty_slots_using_the_original_and_current_values() {
    let vicinity = vicinity();
    let config = Config::prague();

    // EIP-2200/2929/3529: the first slot access is cold; a dirty write costs 100.
    // Restoring the nonzero original refunds 2,800. EIP-7623 floors the final bill at 21,000.
    for (slot, current, writes, gross, refund, billed) in [
        (SLOT, 1, &[2][..], 26_006, 0, 26_006),
        (SLOT, 1, &[0], 26_006, 4_800, 21_206),
        (SLOT, 1, &[2, 1], 26_112, 2_800, 23_312),
        (SLOT, 1, &[0, 1], 26_112, 2_800, 23_312),
        (SLOT, 1, &[2, 0], 26_112, 4_800, 21_312),
        (SLOT, 2, &[1], 23_206, 2_800, 21_000),
        // Restoring an originally empty slot refunds 19,900 before the EIP-3529 cap.
        (H256::zero(), 0, &[2, 0], 43_212, 19_900, 34_570),
    ] {
        let mut code = Vec::new();

        for &value in writes {
            // PUSH1 value, PUSH32 slot, SSTORE. Both pushes cost three gas.
            code.extend_from_slice(&[0x60, value, 0x7f]);
            code.extend_from_slice(slot.as_bytes());
            code.push(0x55);
        }

        let backend = backend(&vicinity, code);
        let metadata = || StackSubstateMetadata::new(GAS_LIMIT, &config);
        let mut lower = MemoryStackState::new(metadata(), &backend);
        // Model writes already seen by the lower layer without charging the measured SSTOREs.
        lower.set_storage(ADDRESS, slot, H256::from_low_u64_be(current));
        let state = MemoryStackState::new(metadata(), &lower);
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
        let (reason, _) = executor.transact_call(
            CALLER,
            ADDRESS,
            U256::zero(),
            vec![],
            GAS_LIMIT,
            vec![],
            vec![],
        );
        let meter = executor.state().metadata().gasometer();

        assert!(reason.is_succeed(), "{reason:?}");
        assert_eq!(
            meter.total_used_gas(),
            gross,
            "current={current}, writes={writes:?}"
        );
        assert_eq!(
            meter.refunded_gas(),
            refund,
            "current={current}, writes={writes:?}"
        );
        assert_eq!(
            executor.used_gas(),
            billed,
            "current={current}, writes={writes:?}"
        );
        assert_eq!(
            executor.state().storage(ADDRESS, slot),
            H256::from_low_u64_be(u64::from(*writes.last().unwrap()))
        );
    }
}
