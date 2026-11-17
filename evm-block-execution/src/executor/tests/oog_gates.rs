//! Opcodes that run out of gas before the reference client loads their target must not read it.
//!
//! EELS Amsterdam checks memory expansion, value transfer and target access before reading a
//! CALL target, and SELFDESTRUCT base/cold gas before its beneficiary. EIP-2200 rejects SSTORE
//! under the stipend before reading its slot. These tests exercise the same access boundaries
//! with Cancun witnesses: unaffordable reads are skipped, affordable reads still require proof.

use super::{
    BlockExecutor, Run, Spec, balance_of, block, chain_spec, empty_blob_schedule, finish,
    legacy_transfer, present,
};
use crate::block::BlobExcessGasAndPrice;
use crate::constants::{EMPTY_ROOT_HASH, KECCAK_EMPTY};
use crate::crypto::keccak256;
use crate::errors::BlockExecutionError;
use crate::witness_backend::{RevealedAccount, WitnessAccount, WitnessBackend, WitnessDbError};
use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

const CALLER: H160 = H160::repeat_byte(0xca);
const PROBER: H160 = H160::repeat_byte(0xc1);
const TARGET: H160 = H160::repeat_byte(0xc2);
const COINBASE: H160 = H160::repeat_byte(0xcb);
/// Runtime of the target when it is revealed: `PUSH1 1, STOP`.
const TARGET_CODE: [u8; 3] = [0x60, 0x01, 0x00];
/// `SSTORE(0, 1), STOP`: 6 gas of pushes before the store.
const SSTORE_ONE: [u8; 6] = [0x60, 1, 0x60, 0, 0x55, 0x00];
const INTRINSIC_GAS: u64 = 21_000;
/// A storage root that is not empty, so an unrevealed slot is a witness gap, not a proven zero.
const CLAIMED_STORAGE_ROOT: H256 = H256::repeat_byte(0x55);

/// A revealed leaf: `storage_root` is what the leaf claims, `storage` what the witness reveals.
fn leaf(
    balance: u64,
    nonce: u64,
    code: &[u8],
    storage_root: H256,
    storage: BTreeMap<H256, H256>,
) -> RevealedAccount {
    RevealedAccount::Present(WitnessAccount {
        nonce: U256::from(nonce),
        balance: U256::from(balance),
        code_hash: if code.is_empty() {
            KECCAK_EMPTY
        } else {
            keccak256(code)
        },
        storage_root,
        storage,
        storage_wiped: false,
    })
}

/// The prober's storage as the witness presents it.
#[derive(Clone, Copy)]
enum Storage {
    /// An empty root: every slot is a proven zero.
    Empty,
    /// A non-empty root with slot 0 revealed as zero.
    SlotRevealed,
    /// A non-empty root with nothing revealed.
    SlotWithheld,
}

/// Executes one legacy transaction from `CALLER` to a prober running `code` on a Cancun block of
/// no system calls. The witness reveals the caller, the prober and the coinbase, and the target
/// only when `target_revealed`.
fn probe(
    code: &[u8],
    gas_limit: u64,
    target_revealed: bool,
    storage: Storage,
) -> Result<Run, BlockExecutionError> {
    let (storage_root, slots) = match storage {
        Storage::Empty => (EMPTY_ROOT_HASH, BTreeMap::new()),
        Storage::SlotRevealed => (
            CLAIMED_STORAGE_ROOT,
            BTreeMap::from([(H256::zero(), H256::zero())]),
        ),
        Storage::SlotWithheld => (CLAIMED_STORAGE_ROOT, BTreeMap::new()),
    };
    let mut accounts = BTreeMap::from([
        (
            CALLER,
            leaf(1_000_000, 0, &[], EMPTY_ROOT_HASH, BTreeMap::new()),
        ),
        (PROBER, leaf(1, 1, code, storage_root, slots)),
        (COINBASE, RevealedAccount::Absent),
    ]);
    let mut codes = vec![code.to_vec()];
    if target_revealed {
        accounts.insert(
            TARGET,
            leaf(0, 1, &TARGET_CODE, EMPTY_ROOT_HASH, BTreeMap::new()),
        );
        codes.push(TARGET_CODE.to_vec());
    }
    let mut blk = block(0, COINBASE);
    blk.block_number = U256::zero();
    blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
    let db = WitnessBackend::try_new(blk.vicinity(1), accounts, codes, BTreeMap::new()).unwrap();
    let mut tx = legacy_transfer(CALLER, PROBER, U256::zero(), 0, 1);
    tx.gas_limit = gas_limit;
    let output = BlockExecutor::new(
        chain_spec(Spec::Cancun, empty_blob_schedule()),
        blk,
        vec![tx],
        db,
    )
    .unwrap()
    .execute()?;
    Ok(finish(output))
}

/// The probe ran out of gas, and that is its only effect: the caller paid `gas_limit` at gas
/// price 1 to the coinbase.
fn assert_burned(run: &Run, gas_limit: u64) {
    assert!(!run.receipts[0].success, "the probe runs out of gas");
    assert_eq!(
        run.gas_used, gas_limit,
        "the probe burns its whole gas limit"
    );
    let caller = present(&run.state, CALLER).unwrap();
    assert_eq!(caller.nonce, U256::one());
    assert_eq!(caller.balance, U256::from(1_000_000 - gas_limit));
    assert_eq!(balance_of(&run.state, COINBASE), U256::from(gas_limit));
}

/// `CALL(target, value 1)` with every other operand zero; 21 gas of pushes precede the call.
fn value_call() -> Vec<u8> {
    let mut code = vec![0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x60, 1, 0x73];
    code.extend_from_slice(TARGET.as_bytes());
    code.extend_from_slice(&[0x60, 0, 0xf1, 0x00]);
    code
}

/// `CALL(target, value 0)` returning 32 bytes at offset 65 536; 21 gas of pushes precede it.
fn call_with_far_output() -> Vec<u8> {
    let mut code = vec![0x60, 32, 0x62, 1, 0, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x73];
    code.extend_from_slice(TARGET.as_bytes());
    code.extend_from_slice(&[0x60, 0, 0xf1, 0x00]);
    code
}

/// `CALL(target, value 0)` with every other operand zero; 21 gas of pushes precede the call.
fn plain_call() -> Vec<u8> {
    let mut code = vec![0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x73];
    code.extend_from_slice(TARGET.as_bytes());
    code.extend_from_slice(&[0x60, 0, 0xf1, 0x00]);
    code
}

/// `SELFDESTRUCT(target)`; 3 gas of pushes precede it.
fn selfdestruct() -> Vec<u8> {
    let mut code = vec![0x73];
    code.extend_from_slice(TARGET.as_bytes());
    code.push(0xff);
    code
}

#[test]
fn a_call_that_cannot_pay_the_value_transfer_leaves_its_target_unread() {
    // 3 979 gas remain at the call: below the 9 000 the transfer costs.
    let gas_limit = 25_000;
    let revealed = probe(&value_call(), gas_limit, true, Storage::Empty).unwrap();
    let withheld = probe(&value_call(), gas_limit, false, Storage::Empty).unwrap();
    assert_burned(&revealed, gas_limit);
    assert_burned(&withheld, gas_limit);
    assert!(!withheld.state.accounts.contains_key(&TARGET));
}

#[test]
fn a_call_that_cannot_pay_its_memory_expansion_leaves_its_target_unread() {
    // 3 979 gas remain at the call: enough for a cold target, not for 2 049 words of memory.
    let gas_limit = 25_000;
    let revealed = probe(&call_with_far_output(), gas_limit, true, Storage::Empty).unwrap();
    let withheld = probe(&call_with_far_output(), gas_limit, false, Storage::Empty).unwrap();
    assert_burned(&revealed, gas_limit);
    assert_burned(&withheld, gas_limit);
}

#[test]
fn a_cold_call_that_cannot_pay_the_access_cost_leaves_its_target_unread() {
    // 2 000 gas remain at the call: below the 2 600 a cold account costs.
    let gas_limit = INTRINSIC_GAS + 21 + 2_000;
    let revealed = probe(&plain_call(), gas_limit, true, Storage::Empty).unwrap();
    let withheld = probe(&plain_call(), gas_limit, false, Storage::Empty).unwrap();
    assert_burned(&revealed, gas_limit);
    assert_burned(&withheld, gas_limit);
}

#[test]
fn a_selfdestruct_that_cannot_pay_the_cold_access_leaves_its_beneficiary_unread() {
    // 7 000 gas remain: below the 5 000 base plus 2 600 for a cold beneficiary.
    let gas_limit = INTRINSIC_GAS + 3 + 7_000;
    let revealed = probe(&selfdestruct(), gas_limit, true, Storage::Empty).unwrap();
    let withheld = probe(&selfdestruct(), gas_limit, false, Storage::Empty).unwrap();
    assert_burned(&revealed, gas_limit);
    assert_burned(&withheld, gas_limit);
}

#[test]
fn an_sstore_under_the_stipend_leaves_its_slot_unread() {
    // Exactly 2 300 gas remain at the store: the EIP-2200 sentry.
    let gas_limit = INTRINSIC_GAS + 6 + 2_300;
    let revealed = probe(&SSTORE_ONE, gas_limit, false, Storage::SlotRevealed).unwrap();
    let withheld = probe(&SSTORE_ONE, gas_limit, false, Storage::SlotWithheld).unwrap();
    assert_burned(&revealed, gas_limit);
    assert_burned(&withheld, gas_limit);
    assert!(present(&withheld.state, PROBER).unwrap().storage.is_empty());
}

/// With gas to spare the same probes read their target, and the witness still owes it: the
/// probes above are discriminating, and the gate narrows nothing the block really needs.
#[test]
fn an_affordable_read_still_fails_on_the_withheld_witness() {
    let unrevealed =
        |address| BlockExecutionError::MissingWitness(WitnessDbError::Account { address });
    for code in [
        value_call(),
        call_with_far_output(),
        plain_call(),
        selfdestruct(),
    ] {
        assert_eq!(
            probe(&code, 100_000, false, Storage::Empty).unwrap_err(),
            unrevealed(TARGET)
        );
    }
    assert_eq!(
        probe(&SSTORE_ONE, 30_000, false, Storage::SlotWithheld).unwrap_err(),
        BlockExecutionError::MissingWitness(WitnessDbError::StorageSlot {
            address: PROBER,
            slot: H256::zero(),
        })
    );
}
