//! Block-level witness failures and preservation of read-only empty accounts.

use super::{
    BlockExecutor, Spec, account, addr, backend, block, chain_spec, empty_blob_schedule,
    legacy_transfer,
};
use crate::constants::EMPTY_ROOT_HASH;
use crate::crypto::keccak256;
use crate::errors::BlockExecutionError;
use crate::execution_types::witness::ExecutionWitness;
use crate::test_support::witness_of;
use crate::trie::state_root;
use crate::withdrawal::Withdrawal;
use crate::witness_backend::{RevealedAccount, WitnessBackend, WitnessDbError};
use aurora_evm::backend::{Backend, MemoryAccount};
use aurora_evm_trie::sparse::reference::hashed_nodes;
use primitive_types::{H256, U256};
use std::collections::BTreeMap;

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
