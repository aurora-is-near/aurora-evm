//! Differential tests against a reference node builder and `triehash`.

use super::super::{LookupError, NodeStore};
use super::reference::hashed_nodes;
use crate::EMPTY_ROOT_HASH;
use crate::crypto::keccak256;
use hash_db::Hasher;
use plain_hasher::PlainHasher;
use std::collections::BTreeMap;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct KeccakHasher;

impl Hasher for KeccakHasher {
    type Out = [u8; 32];
    type StdHasher = PlainHasher;
    const LENGTH: usize = 32;

    fn hash(bytes: &[u8]) -> Self::Out {
        keccak256(bytes)
    }
}

/// Deterministic pseudo-random bytes.
fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[3]
        })
        .collect()
}

fn hashed_items(count: usize, seed: u64) -> BTreeMap<Vec<u8>, Vec<u8>> {
    (0..count)
        .map(|index| {
            let index = u64::try_from(index).expect("test sizes fit u64");
            let key = keccak256(&bytes(seed + index, 20)).to_vec();
            // Mixed value sizes: short ones make leaves that embed in their parents.
            let value = bytes(
                seed * 31 + index,
                1 + usize::try_from((index * 7) % 90).expect("below 90"),
            );
            (key, value)
        })
        .collect()
}

#[test]
fn builder_agrees_with_triehash() {
    for (count, seed) in [(0, 1), (1, 2), (2, 3), (17, 4), (200, 5)] {
        let items = hashed_items(count, seed);
        let (root, _) = hashed_nodes(&items);
        let expected = triehash::trie_root::<KeccakHasher, _, _, _>(items.iter());
        assert_eq!(root, expected, "count {count}");
    }
}

#[test]
fn every_inserted_key_is_found_and_others_are_proven_absent() {
    for (count, seed) in [(1, 11), (3, 12), (64, 13), (300, 14)] {
        let items = hashed_items(count, seed);
        let (root, nodes) = hashed_nodes(&items);
        let store = NodeStore::new(nodes);
        for (key, value) in &items {
            assert_eq!(store.get(root, key), Ok(Some(value.as_slice())));
        }
        for probe in 0..50u64 {
            let absent = keccak256(&bytes(probe + 10_000, 20));
            if !items.contains_key(absent.as_slice()) {
                assert_eq!(store.get(root, &absent), Ok(None), "count {count}");
            }
        }
        // A key that shares a prefix with an existing one but diverges inside a leaf path.
        let (existing, _) = items.iter().next().unwrap();
        let mut sibling = existing.clone();
        sibling[31] ^= 0x01;
        if !items.contains_key(&sibling) {
            assert_eq!(store.get(root, &sibling), Ok(None));
        }
    }
}

#[test]
fn short_keys_exercise_branch_values_and_embedded_nodes() {
    // Keys of differing lengths put a value into a branch slot and keep every node tiny.
    let items: BTreeMap<Vec<u8>, Vec<u8>> = [
        (vec![0x12], vec![0xaa]),
        (vec![0x12, 0x34], vec![0xbb]),
        (vec![0x12, 0x35], vec![0xcc]),
        (vec![0x99, 0x99, 0x99], vec![0xdd]),
    ]
    .into_iter()
    .collect();
    let (root, nodes) = hashed_nodes(&items);
    assert_eq!(
        root,
        triehash::trie_root::<KeccakHasher, _, _, _>(items.iter())
    );
    let store = NodeStore::new(nodes);
    for (key, value) in &items {
        assert_eq!(store.get(root, key), Ok(Some(value.as_slice())));
    }
    assert_eq!(store.get(root, &[0x12, 0x36]), Ok(None));
    assert_eq!(store.get(root, &[0x12, 0x34, 0x56]), Ok(None));
    assert_eq!(store.get(root, &[]), Ok(None));
    assert_eq!(store.get(root, &[0x99]), Ok(None));
}

#[test]
fn empty_root_proves_everything_absent_without_nodes() {
    let store = NodeStore::default();
    assert!(store.is_empty());
    assert_eq!(store.get(EMPTY_ROOT_HASH, &[1, 2, 3]), Ok(None));
}

#[test]
fn a_missing_root_is_reported() {
    let items = hashed_items(5, 21);
    let (root, _) = hashed_nodes(&items);
    let store = NodeStore::default();
    let key = items.keys().next().unwrap();
    assert_eq!(store.get(root, key), Err(LookupError::BlindedNode(root)));
}

#[test]
fn withholding_an_inner_node_fails_only_the_lookups_that_need_it() {
    let items = hashed_items(120, 33);
    let (root, mut nodes) = hashed_nodes(&items);
    // Drop one hashed non-root node.
    let victim = nodes
        .iter()
        .position(|node| keccak256(node) != root)
        .unwrap();
    let removed = nodes.remove(victim);
    let removed_hash = keccak256(&removed);
    let store = NodeStore::new(nodes);
    let mut failed = 0;
    for (key, value) in &items {
        match store.get(root, key) {
            Ok(Some(found)) => assert_eq!(found, value.as_slice()),
            Err(LookupError::BlindedNode(hash)) => {
                assert_eq!(hash, removed_hash);
                failed += 1;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(failed > 0, "the withheld node must have been on some path");
    assert!(failed < items.len(), "other paths stay answerable");
}

#[test]
fn a_node_that_is_not_a_trie_node_is_malformed() {
    let junk = rlp::encode_list::<u8, _>(&[1, 2, 3]).to_vec();
    let root = keccak256(&junk);
    let store = NodeStore::new([junk]);
    assert_eq!(
        store.get(root, &[0x00]),
        Err(LookupError::MalformedNode(root))
    );

    // A two-item node whose path has invalid hex-prefix flags.
    let mut stream = rlp::RlpStream::new_list(2);
    stream.append(&vec![0x40u8]);
    stream.append(&vec![0x01u8]);
    let bad_path = stream.out().to_vec();
    let root = keccak256(&bad_path);
    let store = NodeStore::new([bad_path]);
    assert_eq!(
        store.get(root, &[0x00]),
        Err(LookupError::MalformedNode(root))
    );
}

#[test]
fn nodes_are_deduplicated_by_hash() {
    let node = rlp::encode_list::<u8, _>(&[7]).to_vec();
    let store = NodeStore::new([node.clone(), node.clone()]);
    assert_eq!(store.len(), 1);
    assert!(store.contains(&keccak256(&node)));
}
