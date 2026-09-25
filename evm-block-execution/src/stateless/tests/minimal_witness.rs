//! Hand-built minimal proofs for a block that reads and overwrites beacon-root storage.

use super::{EIP4788_CODE, cancun_child, cancun_parent, chain_spec};
use crate::crypto::keccak256;
use crate::errors::BlockExecutionError;
use crate::execution_types::witness::ExecutionWitness;
use crate::stateless::{StatelessValidationError, stateless_validation};
use crate::system_calls::BEACON_ROOTS_ADDRESS;
use crate::trie::{TrieAccount, state_root, storage_root};
use crate::witness_backend::{RevealedAccount, WitnessDbError, WitnessStateError};
use aurora_evm::backend::MemoryAccount;
use primitive_types::{H160, H256, U256};
use rlp::RlpStream;
use std::collections::BTreeMap;

/// Encodes a hashed leaf below the first branch nibble of a secure key.
fn leaf(key: H256, value: &[u8]) -> Vec<u8> {
    let mut path = key.0;
    path[0] = 0x30 | (path[0] & 0x0f);
    let mut rlp = RlpStream::new_list(2);
    rlp.append(&path.as_slice()).append(&value);
    rlp.out().to_vec()
}

/// Encodes the four Ethereum account fields independently of the witness resolver.
fn account_leaf(account: &MemoryAccount) -> Vec<u8> {
    rlp::encode(&TrieAccount {
        nonce: account.nonce,
        balance: account.balance,
        storage_root: storage_root(&account.storage),
        code_hash: keccak256(&account.code),
        code_version: U256::zero(),
    })
    .to_vec()
}

/// Builds a two-child branch while retaining only one child's preimage.
fn proof(key: H256, value: &[u8], sibling: H256, sibling_value: &[u8]) -> (H256, Vec<Vec<u8>>) {
    assert_ne!(key.0[0] >> 4, sibling.0[0] >> 4);
    let node = leaf(key, value);
    let sibling_hash = keccak256(&leaf(sibling, sibling_value));
    let mut branch = RlpStream::new_list(17);
    for nibble in 0..16 {
        if nibble == key.0[0] >> 4 {
            branch.append(&keccak256(&node));
        } else if nibble == sibling.0[0] >> 4 {
            branch.append(&sibling_hash);
        } else {
            branch.append_empty_data();
        }
    }
    branch.append_empty_data();
    let branch = branch.out().to_vec();
    (keccak256(&branch), vec![branch, node])
}

#[test]
fn a_minimal_witness_proves_storage_presence_and_absence_without_sibling_nodes() {
    let timestamp_slot = H256::from_low_u64_be(20_000 % 8191);
    let root_slot = H256::from_low_u64_be(20_000 % 8191 + 8191);
    let key = keccak256(timestamp_slot.as_bytes());
    let absent = keccak256(root_slot.as_bytes());
    let unrelated_slot = (0..100)
        .map(H256::from_low_u64_be)
        .find(|slot| {
            let nibble = keccak256(slot.as_bytes()).0[0] >> 4;
            nibble != key.0[0] >> 4 && nibble != absent.0[0] >> 4
        })
        .unwrap();
    let storage = BTreeMap::from([
        (timestamp_slot, H256::from_low_u64_be(7)),
        (unrelated_slot, H256::from_low_u64_be(9)),
    ]);
    let (storage_hash, storage_nodes) = proof(
        key,
        &rlp::encode(&7u64),
        keccak256(unrelated_slot.as_bytes()),
        &rlp::encode(&9u64),
    );
    assert_eq!(storage_hash, storage_root(&storage));
    let contract_key = keccak256(BEACON_ROOTS_ADDRESS.as_bytes());
    let holder = (1..100)
        .map(H160::from_low_u64_be)
        .find(|address| keccak256(address.as_bytes()).0[0] >> 4 != contract_key.0[0] >> 4)
        .unwrap();
    let contract = MemoryAccount {
        nonce: U256::one(),
        storage,
        code: EIP4788_CODE.to_vec(),
        ..MemoryAccount::default()
    };
    let holder_account = MemoryAccount {
        balance: U256::one(),
        ..MemoryAccount::default()
    };
    let pre = BTreeMap::from([
        (BEACON_ROOTS_ADDRESS, contract.clone()),
        (holder, holder_account.clone()),
    ]);
    let (root, mut nodes) = proof(
        contract_key,
        &account_leaf(&contract),
        keccak256(holder.as_bytes()),
        &account_leaf(&holder_account),
    );
    assert_eq!(root, state_root(&pre));
    nodes.extend(storage_nodes);
    let parent = cancun_parent(root);
    let beacon_root = H256::repeat_byte(0xbe);
    let witness = ExecutionWitness {
        state: nodes,
        contract_codes: vec![EIP4788_CODE.to_vec()],
        headers: vec![rlp::encode(&parent).to_vec()],
        ..ExecutionWitness::default()
    };
    assert_eq!(witness.state.len(), 4);
    let output = stateless_validation(
        cancun_child(&parent, beacon_root),
        &[],
        witness.clone(),
        chain_spec(),
    )
    .unwrap();
    let RevealedAccount::Present(account) =
        &output.execution_output.state.accounts[&BEACON_ROOTS_ADDRESS]
    else {
        panic!("the beacon contract must be present");
    };
    assert_eq!(
        account.storage[&timestamp_slot],
        H256::from_low_u64_be(20_000)
    );
    assert_eq!(account.storage[&root_slot], beacon_root);
    assert!(!account.storage.contains_key(&unrelated_slot));
    assert!(!output.execution_output.state.accounts.contains_key(&holder));

    // Every supplied trie node is necessary, unlike a full-state witness superset.
    for index in 0..witness.state.len() {
        let mut incomplete = witness.clone();
        let hash = keccak256(&incomplete.state.remove(index));
        let error = stateless_validation(
            cancun_child(&parent, beacon_root),
            &[],
            incomplete,
            chain_spec(),
        )
        .unwrap_err();
        let expected = if hash == root {
            StatelessValidationError::Witness(WitnessStateError::PreStateRootNotRevealed {
                pre_state_root: root,
            })
        } else {
            StatelessValidationError::Execution(BlockExecutionError::MissingWitness(
                WitnessDbError::BlindedNode { hash },
            ))
        };
        assert_eq!(error, expected);
    }
}
