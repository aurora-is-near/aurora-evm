//! Ethereum leaf validation through authenticated single-leaf witnesses.

use super::{addr, slot, vicinity};
use crate::constants::{EMPTY_ROOT_HASH, KECCAK_EMPTY};
use crate::crypto::keccak256;
use crate::execution_types::witness::ExecutionWitness;
use crate::trie::TrieAccount;
use crate::witness_backend::{WitnessBackend, WitnessDbError};
use aurora_evm::backend::Backend;
use primitive_types::{H256, U256};
use std::collections::BTreeMap;

/// Encodes a leaf over a complete secure-trie key.
fn leaf(key: H256, value: &[u8]) -> Vec<u8> {
    let mut path = vec![0x20];
    path.extend_from_slice(key.as_bytes());
    let mut stream = rlp::RlpStream::new_list(2);
    stream.append(&path).append(&value);
    stream.out().to_vec()
}

fn account(root: H256) -> TrieAccount {
    TrieAccount {
        nonce: U256::from(u64::MAX),
        balance: U256::MAX,
        storage_root: root,
        code_hash: KECCAK_EMPTY,
        code_version: U256::zero(),
    }
}

/// Builds a witness without normalizing its account or storage values.
fn database(value: &[u8], mut nodes: Vec<Vec<u8>>) -> WitnessBackend {
    let node = leaf(keccak256(addr(1).as_bytes()), value);
    let root = keccak256(&node);
    nodes.push(node);
    WitnessBackend::from_witness(
        vicinity(),
        ExecutionWitness {
            state: nodes,
            ..ExecutionWitness::default()
        },
        root,
        BTreeMap::new(),
    )
    .unwrap()
}

#[test]
fn account_leaves_require_exactly_four_canonical_fields() {
    let valid = account(EMPTY_ROOT_HASH);
    let encoded = rlp::encode(&valid).to_vec();
    let db = database(&encoded, vec![]);
    assert_eq!(db.basic(addr(1)).nonce, U256::from(u64::MAX));
    assert_eq!(db.basic(addr(1)).balance, U256::MAX);
    assert_eq!(db.missing(), None);

    let mut invalid = vec![vec![], vec![0xc0], vec![0x80]];
    for suffix in 0..=u8::MAX {
        let mut bytes = encoded.clone();
        bytes.push(suffix);
        invalid.push(bytes);
    }
    for version in [U256::zero(), U256::one()] {
        let mut stream = rlp::RlpStream::new_list(5);
        stream
            .append(&valid.nonce)
            .append(&valid.balance)
            .append(&valid.storage_root)
            .append(&valid.code_hash)
            .append(&version);
        invalid.push(stream.out().to_vec());
    }
    let mut oversized_nonce = valid;
    oversized_nonce.nonce = U256::from(u64::MAX) + U256::one();
    invalid.push(rlp::encode(&oversized_nonce).to_vec());
    // Noncanonical integer encodings in either scalar field must not bypass list checks.
    for index in [0, 1] {
        for scalar in [&[0xb8, 1, 1][..], &[0x81, 1], &[0x82, 0, 1]] {
            let mut stream = rlp::RlpStream::new_list(4);
            for field in 0..2 {
                stream.append_raw(if field == index { scalar } else { &[1] }, 1);
            }
            stream.append(&EMPTY_ROOT_HASH).append(&KECCAK_EMPTY);
            invalid.push(stream.out().to_vec());
        }
    }
    for bytes in invalid {
        let db = database(&bytes, vec![]);
        assert_eq!(db.basic(addr(1)).balance, U256::zero());
        assert_eq!(
            db.missing(),
            Some(WitnessDbError::AccountLeaf { address: addr(1) }),
            "{bytes:x?}"
        );
        assert_eq!(
            db.try_into_state().unwrap_err(),
            WitnessDbError::AccountLeaf { address: addr(1) }
        );
    }
}

#[test]
fn storage_leaves_require_exact_canonical_nonzero_integers() {
    let mut values = vec![
        vec![],
        vec![0],
        vec![0x80],
        vec![1, 2],
        vec![1, 0xff],
        vec![0xb8, 1, 1],
        vec![0x81, 1],
        vec![0x82, 0, 1],
        vec![0xc0],
    ];
    let mut oversized = vec![0xa1];
    oversized.extend_from_slice(&[1; 33]);
    values.push(oversized);
    for bytes in values {
        let node = leaf(keccak256(slot(1).as_bytes()), &bytes);
        let db = database(&rlp::encode(&account(keccak256(&node))), vec![node]);
        assert_eq!(db.storage(addr(1), slot(1)), H256::zero());
        let expected = WitnessDbError::StorageLeaf {
            address: addr(1),
            slot: slot(1),
        };
        assert_eq!(db.missing(), Some(expected), "{bytes:x?}");
        assert_eq!(db.try_into_state().unwrap_err(), expected);
    }
    for value in [U256::one(), U256::from(128), U256::MAX] {
        let node = leaf(keccak256(slot(1).as_bytes()), &rlp::encode(&value));
        let db = database(&rlp::encode(&account(keccak256(&node))), vec![node]);
        assert_eq!(db.storage(addr(1), slot(1)), H256(value.to_big_endian()));
        assert_eq!(db.storage(addr(1), slot(2)), H256::zero());
        assert_eq!(db.missing(), None);
    }
}

#[test]
fn missing_and_malformed_storage_nodes_remain_distinct() {
    let node = vec![0xc0];
    let hash = keccak256(&node);
    for (nodes, expected) in [
        (vec![], WitnessDbError::BlindedNode { hash }),
        (vec![node], WitnessDbError::MalformedNode { hash }),
    ] {
        let db = database(&rlp::encode(&account(hash)), nodes);
        assert_eq!(db.storage(addr(1), slot(1)), H256::zero());
        assert_eq!(db.missing(), Some(expected));
        assert_eq!(db.try_into_state().unwrap_err(), expected);
    }
}
