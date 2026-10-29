//! Blocks whose witness omits the code of accounts that execution reads by hash alone.
//!
//! A witness built from the code the reference client loaded carries bytes only for code that was
//! executed, sized, copied or followed as a delegation. `EXTCODEHASH`, the EIP-161 existence of a
//! `SELFDESTRUCT` beneficiary and the EIP-7610 collision check are answered from the account leaf,
//! so such a witness validates the block; omitted code that runs must still fail it.

use super::{
    BlockExecutor, Spec, account, addr, block, chain_spec, empty_blob_schedule, legacy_transfer,
    present,
};
use crate::block::BlobExcessGasAndPrice;
use crate::crypto::keccak256;
use crate::errors::BlockExecutionError;
use crate::execution_types::execution::BlockExecutionOutput;
use crate::test_utils::witness_of;
use crate::transaction::TxEnv;
use crate::trie::{state_root, witness_state_root};
use crate::witness_backend::{WitnessBackend, WitnessDbError};
use aurora_evm::backend::MemoryAccount;
use primitive_types::{H160, H256, U256};
use std::collections::{BTreeMap, BTreeSet};

const COINBASE: H160 = H160::repeat_byte(0xcb);

/// Executes a Cancun block of one transaction over `pre`, proven by a witness that omits the code
/// of every account in `withheld`. The block makes no system calls, so the post-state is the
/// transaction's alone.
fn run_without_codes(
    pre: &BTreeMap<H160, MemoryAccount>,
    tx: TxEnv,
    withheld: &[H160],
) -> Result<BlockExecutionOutput, BlockExecutionError> {
    let (root, mut witness) = witness_of(pre);
    let omitted: BTreeSet<H256> = withheld
        .iter()
        .map(|address| keccak256(&pre[address].code))
        .collect();
    witness
        .contract_codes
        .retain(|code| !omitted.contains(&keccak256(code)));
    let mut blk = block(0, COINBASE);
    blk.block_number = U256::zero();
    blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::default());
    let db = WitnessBackend::from_witness(blk.vicinity(1), witness, root, BTreeMap::new()).unwrap();
    BlockExecutor::new(
        chain_spec(Spec::Cancun, empty_blob_schedule()),
        blk,
        vec![tx],
        db,
    )
    .unwrap()
    .execute()
}

/// `pre` after a successful transaction from `caller` at gas price 1 over a zero base fee: the
/// nonce advances and the fee reaches the coinbase. The contract's own effects are the test's.
fn settled(
    pre: &BTreeMap<H160, MemoryAccount>,
    caller: H160,
    gas_used: u64,
) -> BTreeMap<H160, MemoryAccount> {
    let mut post = pre.clone();
    let sender = post.get_mut(&caller).unwrap();
    sender.nonce += U256::one();
    sender.balance -= U256::from(gas_used);
    post.insert(COINBASE, account(gas_used, 0, vec![]));
    post
}

/// `PUSH20 target; EXTCODEHASH; PUSH1 0; SSTORE; STOP` — records `EXTCODEHASH(target)` in slot 0.
fn store_extcodehash(target: H160) -> Vec<u8> {
    let mut code = vec![0x73];
    code.extend_from_slice(target.as_bytes());
    code.extend_from_slice(&[0x3f, 0x60, 0x00, 0x55, 0x00]);
    code
}

/// `PUSH20 beneficiary; SELFDESTRUCT` — sends the whole balance to `beneficiary`.
fn selfdestruct_to(beneficiary: H160) -> Vec<u8> {
    let mut code = vec![0x73];
    code.extend_from_slice(beneficiary.as_bytes());
    code.push(0xff);
    code
}

/// `PUSH1 salt; PUSH1 0; PUSH1 0; PUSH1 0; CREATE2; PUSH1 0; SSTORE; STOP` — records in slot 0 the
/// address `CREATE2` returns for empty init code and `salt`: zero on a collision.
fn store_create2(salt: u8) -> Vec<u8> {
    vec![
        0x60, salt, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xf5, 0x60, 0x00, 0x55, 0x00,
    ]
}

/// EIP-1014: `keccak256(0xff ++ creator ++ salt ++ keccak256(init_code))[12..]`.
fn create2_address(creator: H160, salt: u8, init_code: &[u8]) -> H160 {
    let mut preimage = vec![0xff];
    preimage.extend_from_slice(creator.as_bytes());
    preimage.extend_from_slice(H256::from_low_u64_be(u64::from(salt)).as_bytes());
    preimage.extend_from_slice(keccak256(init_code).as_bytes());
    H160::from_slice(&keccak256(&preimage).as_bytes()[12..])
}

#[test]
fn extcodehash_of_an_account_whose_code_is_withheld_comes_from_its_leaf() {
    let caller = addr(0xca);
    let prober = addr(0xc1);
    let target = addr(0xc2);
    let target_code = vec![0x60, 0x01, 0x00];
    let pre = BTreeMap::from([
        (caller, account(1_000_000, 0, vec![])),
        (prober, account(0, 1, store_extcodehash(target))),
        (target, account(0, 1, target_code.clone())),
    ]);
    let tx = legacy_transfer(caller, prober, U256::zero(), 0, 1);

    let output = run_without_codes(&pre, tx, &[target]).unwrap();

    // The hash the leaf carries: neither `KECCAK_EMPTY` from empty bytes nor zero from absence.
    let target_hash = keccak256(&target_code);
    let prober_state = present(&output.state, prober).unwrap();
    assert_eq!(prober_state.storage.get(&H256::zero()), Some(&target_hash));
    assert!(!output.state.codes.contains_key(&target_hash));
    let mut expected = settled(&pre, caller, output.result.gas_used);
    expected
        .get_mut(&prober)
        .unwrap()
        .storage
        .insert(H256::zero(), target_hash);
    assert_eq!(witness_state_root(&output.state), Ok(state_root(&expected)));
}

/// The bytes of code that runs are still owed: narrowing what a witness must carry does not
/// weaken the fail-closed report of a genuine omission.
#[test]
fn withheld_code_of_an_executed_contract_still_fails_the_block() {
    let caller = addr(0xca);
    let prober = addr(0xc1);
    let target = addr(0xc2);
    let pre = BTreeMap::from([
        (caller, account(1_000_000, 0, vec![])),
        (prober, account(0, 1, store_extcodehash(target))),
        (target, account(0, 1, vec![0x60, 0x01, 0x00])),
    ]);
    let tx = legacy_transfer(caller, prober, U256::zero(), 0, 1);

    assert_eq!(
        run_without_codes(&pre, tx, &[prober, target]).unwrap_err(),
        BlockExecutionError::MissingWitness(WitnessDbError::Code {
            address: prober,
            code_hash: keccak256(&store_extcodehash(target)),
        })
    );
}

/// The beneficiary has code but neither nonce nor balance, so its EIP-161 existence — which
/// decides the 25 000 gas new-account charge — rests on `has_code` alone, answered from the leaf.
#[test]
fn selfdestruct_to_a_contract_whose_code_is_withheld_sees_it_exist() {
    let caller = addr(0xca);
    let destroyer = addr(0xd0);
    let beneficiary = addr(0xb0);
    let beneficiary_code = vec![0x60, 0x01, 0x00];
    let pre = BTreeMap::from([
        (caller, account(1_000_000, 0, vec![])),
        (destroyer, account(5, 1, selfdestruct_to(beneficiary))),
        (beneficiary, account(0, 0, beneficiary_code.clone())),
    ]);
    let tx = legacy_transfer(caller, destroyer, U256::zero(), 0, 1);

    let output = run_without_codes(&pre, tx, &[beneficiary]).unwrap();

    // Intrinsic gas, `PUSH20`, `SELFDESTRUCT` and a cold beneficiary; no new-account charge.
    assert_eq!(output.result.gas_used, 21_000 + 3 + 5_000 + 2_600);
    assert!(
        !output
            .state
            .codes
            .contains_key(&keccak256(&beneficiary_code))
    );
    // EIP-6780: the destroyer was not created in this transaction, so only its balance moves.
    let mut expected = settled(&pre, caller, output.result.gas_used);
    expected.get_mut(&destroyer).unwrap().balance = U256::zero();
    expected.get_mut(&beneficiary).unwrap().balance = U256::from(5u64);
    assert_eq!(witness_state_root(&output.state), Ok(state_root(&expected)));
}

/// The occupant has code but no nonce and no storage, so the EIP-7610 check rests on `has_code`
/// alone. A missed collision would run the empty init code and rewrite the occupant's leaf.
#[test]
fn create2_collision_with_a_contract_whose_code_is_withheld_is_detected() {
    let caller = addr(0xca);
    let creator = addr(0xc1);
    let salt = 0x5a;
    let occupant = create2_address(creator, salt, &[]);
    let occupant_code = vec![0x60, 0x01, 0x00];
    let pre = BTreeMap::from([
        (caller, account(2_000_000, 0, vec![])),
        (creator, account(0, 1, store_create2(salt))),
        (occupant, account(0, 0, occupant_code.clone())),
    ]);
    // A collision consumes the gas forwarded to the creation; leave enough for the `SSTORE`.
    let mut tx = legacy_transfer(caller, creator, U256::zero(), 0, 1);
    tx.gas_limit = 1_000_000;

    let output = run_without_codes(&pre, tx, &[occupant]).unwrap();

    assert!(output.result.receipts[0].success);
    assert!(!output.state.codes.contains_key(&keccak256(&occupant_code)));
    // `CREATE2` returned zero, so slot 0 stays zero.
    let creator_state = present(&output.state, creator).unwrap();
    assert!(
        creator_state
            .storage
            .get(&H256::zero())
            .is_none_or(H256::is_zero)
    );
    // The creator's nonce advances before the collision is detected; the occupant is untouched.
    let mut expected = settled(&pre, caller, output.result.gas_used);
    expected.get_mut(&creator).unwrap().nonce = U256::from(2u64);
    assert_eq!(witness_state_root(&output.state), Ok(state_root(&expected)));
}
