//! Hand-built minimal proofs for a block that reads and overwrites beacon-root storage.

use super::{EIP4788_CODE, cancun_child, cancun_parent, chain_spec};
use crate::block::{Block, Header};
use crate::crypto::keccak256;
use crate::errors::BlockExecutionError;
use crate::execution_types::witness::ExecutionWitness;
use crate::stateless::{StatelessValidationError, stateless_validation};
use crate::system_calls::BEACON_ROOTS_ADDRESS;
use crate::trie::{TrieAccount, state_root, storage_root, witness_state_root};
use crate::witness_backend::{RevealedAccount, WitnessDbError, WitnessStateError};
use aurora_evm::backend::MemoryAccount;
use aurora_evm_trie::sparse::LookupError;
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
    let mut expected = pre;
    let storage = &mut expected.get_mut(&BEACON_ROOTS_ADDRESS).unwrap().storage;
    storage.insert(timestamp_slot, H256::from_low_u64_be(20_000));
    storage.insert(root_slot, beacon_root);
    let mut block = cancun_child(&parent, beacon_root);
    block.header.state_root = state_root(&expected);
    let output = stateless_validation(block, &[], witness.clone(), chain_spec()).unwrap();
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

    // The executor transfers the sparse pre-state trie, not a rebuilt trie of cached writes.
    let trie = output.execution_output.state.trie.as_ref().unwrap();
    assert_eq!(trie.state_root(), root);
    assert_eq!(trie.nodes().len(), witness.state.len());
    assert_eq!(
        trie.nodes().get(storage_hash.0, key.as_bytes()).unwrap(),
        Some(rlp::encode(&7u64).as_ref())
    );
    let holder_key = keccak256(holder.as_bytes());
    let withheld = keccak256(&leaf(holder_key, &account_leaf(&holder_account)));
    assert_eq!(
        trie.nodes().get(root.0, holder_key.as_bytes()),
        Err(LookupError::BlindedNode(withheld.0))
    );

    assert_every_node_is_required(&witness, &parent, beacon_root);

    assert_eq!(
        witness_state_root(&output.execution_output.state),
        Ok(state_root(&expected))
    );
}

/// Every supplied node must be necessary, unlike a full-state witness superset.
fn assert_every_node_is_required(witness: &ExecutionWitness, parent: &Header, beacon_root: H256) {
    for index in 0..witness.state.len() {
        let mut incomplete = witness.clone();
        let hash = keccak256(&incomplete.state.remove(index));
        let error = stateless_validation(
            cancun_child(parent, beacon_root),
            &[],
            incomplete,
            chain_spec(),
        )
        .unwrap_err();
        let expected = if hash == parent.state_root {
            StatelessValidationError::Witness(WitnessStateError::PreStateRootNotRevealed {
                pre_state_root: parent.state_root,
            })
        } else {
            StatelessValidationError::Execution(BlockExecutionError::MissingWitness(
                WitnessDbError::BlindedNode { hash },
            ))
        };
        assert_eq!(error, expected);
    }
}

/// A system-call fixture with a two-slot storage trie. The sibling is untouched by execution
/// but needed to collapse the branch after deletion unless a new slot is inserted first.
fn storage_deletion_fixture(upsert: bool, malformed: bool) -> (Block, ExecutionWitness, Vec<u8>) {
    let mut seen = std::collections::BTreeSet::new();
    let slots: Vec<_> = (0..100)
        .map(H256::from_low_u64_be)
        .filter(|slot| seen.insert(keccak256(slot.as_bytes()).0[0] >> 4))
        .take(3)
        .collect();
    let [removed, sibling, created] = slots.as_slice() else {
        unreachable!()
    };
    // Test runtime: SSTORE(removed, 0), optionally SSTORE(created, 3), STOP.
    let mut code = vec![0x5f, 0x7f];
    code.extend_from_slice(removed.as_bytes());
    code.push(0x55);
    if upsert {
        code.extend_from_slice(&[0x60, 3, 0x7f]);
        code.extend_from_slice(created.as_bytes());
        code.push(0x55);
    }
    code.push(0);
    let removed_key = keccak256(removed.as_bytes());
    let sibling_key = keccak256(sibling.as_bytes());
    let removed_node = leaf(removed_key, &rlp::encode(&7u64));
    let sibling_node = if malformed {
        vec![0xc0]
    } else {
        leaf(sibling_key, &rlp::encode(&9u64))
    };
    let mut branch = RlpStream::new_list(17);
    for nibble in 0..16 {
        if nibble == removed_key.0[0] >> 4 {
            branch.append(&keccak256(&removed_node));
        } else if nibble == sibling_key.0[0] >> 4 {
            branch.append(&keccak256(&sibling_node));
        } else {
            branch.append_empty_data();
        }
    }

    branch.append_empty_data();
    let branch = branch.out().to_vec();
    let account = TrieAccount {
        nonce: U256::one(),
        balance: U256::zero(),
        storage_root: keccak256(&branch),
        code_hash: keccak256(&code),
        code_version: U256::zero(),
    };
    let mut path = vec![0x20];
    path.extend_from_slice(keccak256(BEACON_ROOTS_ADDRESS.as_bytes()).as_bytes());
    let mut root = RlpStream::new_list(2);
    root.append(&path).append(&rlp::encode(&account).as_ref());
    let root = root.out().to_vec();
    let parent = cancun_parent(keccak256(&root));
    let mut block = cancun_child(&parent, H256::zero());
    let mut post_storage = BTreeMap::from([(*sibling, H256::from_low_u64_be(9))]);
    if upsert {
        post_storage.insert(*created, H256::from_low_u64_be(3));
    }
    block.header.state_root = state_root(&BTreeMap::from([(
        BEACON_ROOTS_ADDRESS,
        MemoryAccount {
            nonce: U256::one(),
            code: code.clone(),
            storage: post_storage,
            ..MemoryAccount::default()
        },
    )]));
    let witness = ExecutionWitness {
        state: vec![root, branch, removed_node],
        contract_codes: vec![code],
        headers: vec![rlp::encode(&parent).to_vec()],
        ..ExecutionWitness::default()
    };
    (block, witness, sibling_node)
}

#[test]
fn storage_collapse_needs_exactly_the_untouched_sibling() {
    let (block, mut witness, sibling) = storage_deletion_fixture(false, false);
    let hash = keccak256(&sibling);
    assert_eq!(
        stateless_validation(block.clone(), &[], witness.clone(), chain_spec()),
        Err(StatelessValidationError::Execution(
            BlockExecutionError::MissingWitness(WitnessDbError::BlindedNode { hash })
        ))
    );
    witness.state.push(sibling);
    assert!(stateless_validation(block.clone(), &[], witness.clone(), chain_spec()).is_ok());
    // Every supplied node is required, including the one read only during root reconstruction.
    for index in 0..witness.state.len() {
        let mut incomplete = witness.clone();
        let hash = keccak256(&incomplete.state.remove(index));
        let error = stateless_validation(block.clone(), &[], incomplete, chain_spec()).unwrap_err();
        let expected = if index == 0 {
            StatelessValidationError::Witness(WitnessStateError::PreStateRootNotRevealed {
                pre_state_root: hash,
            })
        } else {
            StatelessValidationError::Execution(BlockExecutionError::MissingWitness(
                WitnessDbError::BlindedNode { hash },
            ))
        };
        assert_eq!(error, expected);
    }
}

#[test]
fn storage_upsert_avoids_a_transient_collapse_with_a_minimal_witness() {
    let (block, witness, _) = storage_deletion_fixture(true, false);
    assert_eq!(witness.state.len(), 3);
    assert!(stateless_validation(block, &[], witness, chain_spec()).is_ok());
}

#[test]
fn malformed_storage_sibling_is_rejected_not_classified_as_missing() {
    let (block, mut witness, malformed) = storage_deletion_fixture(false, true);
    let hash = keccak256(&malformed);
    witness.state.push(malformed);
    assert_eq!(
        stateless_validation(block, &[], witness, chain_spec()),
        Err(StatelessValidationError::Execution(
            BlockExecutionError::MissingWitness(WitnessDbError::MalformedNode { hash })
        ))
    );
}
