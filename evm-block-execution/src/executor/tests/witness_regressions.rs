//! Block-level witness failures and preservation of read-only empty accounts.

use super::{
    BlockExecutor, Spec, account, addr, backend, block, chain_spec, empty_blob_schedule,
    legacy_transfer,
};
use crate::constants::EMPTY_ROOT_HASH;
use crate::crypto::keccak256;
use crate::errors::BlockExecutionError;
use crate::execution_types::witness::ExecutionWitness;
use crate::test_utils::witness_of;
use crate::trie::state_root;
use crate::withdrawal::Withdrawal;
use crate::witness_backend::{RevealedAccount, WitnessBackend, WitnessDbError};
use aurora_evm::backend::{Backend, MemoryAccount};
use aurora_evm::{ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed};
use aurora_evm_trie::sparse::reference::hashed_nodes;
use primitive_types::{H256, U256};
use std::collections::BTreeMap;

#[test]
fn pre_execution_rejects_fatal_errors_but_preserves_witness_priority() {
    let blk = block(0, addr(5));
    let db =
        WitnessBackend::try_new(blk.vicinity(1), BTreeMap::new(), vec![], BTreeMap::new()).unwrap();
    let executor = BlockExecutor::new(
        chain_spec(Spec::Cancun, empty_blob_schedule()),
        blk,
        vec![],
        db,
    )
    .unwrap();
    for reason in [
        ExitReason::Succeed(ExitSucceed::Stopped),
        ExitReason::Revert(ExitRevert::Reverted),
        ExitReason::Error(ExitError::OutOfGas),
    ] {
        assert!(
            executor
                .check_pre_execution_outcome(crate::system_calls::SystemCallOutcome {
                    reason,
                    output: vec![],
                })
                .is_ok()
        );
    }
    let fatal = ExitReason::Fatal(ExitFatal::UnhandledInterrupt);
    assert_eq!(
        executor.check_pre_execution_outcome(crate::system_calls::SystemCallOutcome {
            reason: fatal.clone(),
            output: vec![],
        }),
        Err(BlockExecutionError::ExecutionFailed(fatal.clone())),
    );
    executor.backend.basic(addr(1));
    assert_eq!(
        executor.check_pre_execution_outcome(crate::system_calls::SystemCallOutcome {
            reason: fatal,
            output: vec![],
        }),
        Err(BlockExecutionError::MissingWitness(
            WitnessDbError::Account { address: addr(1) }
        )),
    );
}

#[test]
fn an_unproven_storage_read_stops_before_the_next_transaction() {
    let caller = addr(1);
    let contract = addr(2);
    let later = addr(3);
    let mut state = account(0, 1, vec![0x5f, 0x54, 0x50, 0x00]); // SLOAD(0), POP, STOP
    state.storage.insert(H256::zero(), H256::from_low_u64_be(7));
    let pre = BTreeMap::from([
        (caller, account(1_000_000, 0, vec![])),
        (contract, state),
        (later, account(9, 0, vec![])),
    ]);
    let (root, mut witness) = witness_of(&pre);
    let (storage_root, _) = hashed_nodes(&BTreeMap::from([(
        keccak256(H256::zero().as_bytes()).as_bytes().to_vec(),
        rlp::encode(&U256::from(7)).to_vec(),
    )]));
    witness
        .state
        .retain(|node| keccak256(node).0 != storage_root);
    let mut blk = block(0, addr(5));
    blk.block_number = U256::zero();
    blk.blob_excess_gas_and_price = Some(crate::block::BlobExcessGasAndPrice::default());
    let db = WitnessBackend::from_witness(blk.vicinity(1), witness, root, BTreeMap::new()).unwrap();
    let txs = vec![
        legacy_transfer(caller, contract, U256::zero(), 0, 1),
        legacy_transfer(caller, later, U256::one(), 1, 1),
    ];
    let mut executor = BlockExecutor::new(
        chain_spec(Spec::Cancun, empty_blob_schedule()),
        blk,
        txs,
        db,
    )
    .unwrap();
    let Err(error) = executor.execute_transactions() else {
        panic!("an unproven storage read must abort the transaction phase");
    };
    assert_eq!(
        error,
        BlockExecutionError::MissingWitness(WitnessDbError::BlindedNode {
            hash: H256(storage_root)
        }),
    );
    // The first transaction completed, but the second recipient was never even resolved.
    assert_eq!(executor.backend.basic(caller).nonce, U256::one());
    assert!(!executor.backend.accounts().contains_key(&later));
}

#[test]
fn a_block_preserves_read_only_empty_accounts_and_prunes_touched_ones() {
    let keep = addr(1);
    let prune = addr(2);
    let key = H256::repeat_byte(3);
    let value = H256::repeat_byte(4);
    let mut empty = account(0, 0, vec![]);
    empty.storage.insert(key, value);
    let pre = BTreeMap::from([(keep, empty.clone()), (prune, empty.clone())]);
    let expected = BTreeMap::from([(keep, empty)]);
    let (expected_root, _) = witness_of(&expected);
    assert_ne!(expected_root, EMPTY_ROOT_HASH);

    for from_witness in [false, true] {
        let mut blk = block(0, addr(5));
        blk.withdrawals.push(Withdrawal {
            index: 0,
            validator_index: 0,
            address: prune,
            amount: 0,
        });
        let db = if from_witness {
            let (root, witness) = witness_of(&pre);
            WitnessBackend::from_witness(blk.vicinity(1), witness, root, BTreeMap::new()).unwrap()
        } else {
            backend(&blk, pre.clone())
        };
        // Caching a proven read must not turn it into a state-changing touch.
        assert_eq!(db.storage(keep, key), value);
        let output = BlockExecutor::new(
            chain_spec(Spec::Cancun, empty_blob_schedule()),
            blk,
            vec![],
            db,
        )
        .unwrap()
        .execute()
        .unwrap();
        assert_eq!(output.state.accounts[&prune], RevealedAccount::Absent);
        let post: BTreeMap<_, _> = output
            .state
            .accounts
            .into_iter()
            .filter_map(|(address, entry)| {
                let RevealedAccount::Present(account) = entry else {
                    return None;
                };
                Some((
                    address,
                    MemoryAccount {
                        nonce: account.nonce,
                        balance: account.balance,
                        code: vec![],
                        storage: account.storage,
                    },
                ))
            })
            .collect();
        assert_eq!(post, expected);
        assert_eq!(state_root(&post), expected_root);
    }
}

#[test]
fn a_malformed_sender_leaf_takes_priority_over_transaction_failure() {
    let caller = addr(1);
    let leaves = BTreeMap::from([(keccak256(caller.as_bytes()).as_bytes().to_vec(), vec![0xff])]);
    let (root, nodes) = hashed_nodes(&leaves);
    let mut blk = block(0, addr(5));
    blk.block_number = U256::zero();
    let db = WitnessBackend::from_witness(
        blk.vicinity(1),
        ExecutionWitness {
            state: nodes,
            ..ExecutionWitness::default()
        },
        H256(root),
        BTreeMap::new(),
    )
    .unwrap();
    let tx = legacy_transfer(caller, addr(2), U256::one(), 0, 1);
    let error = BlockExecutor::new(
        chain_spec(Spec::Cancun, empty_blob_schedule()),
        blk,
        vec![tx],
        db,
    )
    .unwrap()
    .execute()
    .unwrap_err();
    assert_eq!(
        error,
        BlockExecutionError::MissingWitness(WitnessDbError::AccountLeaf { address: caller })
    );
}
