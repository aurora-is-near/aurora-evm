//! Permutation invariants, prefix ties, duplicate ownership, and index boundaries.

use super::super::{Entry, NodeStore, decode::Decoded, sort::by_hash};
use crate::crypto::keccak256;

/// Gives synthetic hash keys distinct, valid payloads to detect detached metadata.
fn entry(hash: [u8; 32], id: usize) -> Entry {
    let mut stream = rlp::RlpStream::new_list(2);
    stream
        .append(&vec![0x20u8])
        .append(&id.to_be_bytes().as_slice());
    let bytes = stream.out().to_vec();
    Entry {
        hash,
        decoded: Decoded::decode(&bytes),
        bytes,
    }
}

/// Checks full ordering and preservation of each buffer and its decoded value.
fn check_order(hashes: &[[u8; 32]]) {
    let mut nodes: Vec<_> = hashes
        .iter()
        .enumerate()
        .map(|(id, &hash)| entry(hash, id))
        .collect();
    let mut expected: Vec<_> = nodes
        .iter()
        .map(|e| (e.hash, e.bytes.clone(), e.bytes.as_ptr()))
        .collect();
    expected.sort_by_key(|e| e.0);
    by_hash(&mut nodes);
    assert!(nodes.is_sorted_by_key(|e| e.hash));
    for node in &nodes {
        let (_, bytes, pointer) = expected
            .iter()
            .find(|(_, _, p)| *p == node.bytes.as_ptr())
            .unwrap();
        assert_eq!(&node.bytes, bytes);
        assert_eq!(*pointer, node.bytes.as_ptr());
        let Decoded::Leaf { value_start, .. } = node.decoded.unwrap() else {
            panic!("expected leaf")
        };
        let id = usize::from_be_bytes(node.bytes[value_start..].try_into().unwrap());
        assert_eq!(node.hash, hashes[id]);
    }
    assert_eq!(
        nodes.iter().map(|e| e.hash).collect::<Vec<_>>(),
        expected.iter().map(|e| e.0).collect::<Vec<_>>()
    );
}

/// Enumerates all permutations, including disjoint cycles and fixed points.
fn permutations(hashes: &mut [[u8; 32]], start: usize) {
    if start == hashes.len() {
        check_order(hashes);
        return;
    }
    for i in start..hashes.len() {
        hashes.swap(start, i);
        permutations(hashes, start + 1);
        hashes.swap(start, i);
    }
}

#[test]
fn every_small_permutation_preserves_entries() {
    for len in 0..=7u8 {
        let mut hashes: Vec<_> = (0..len).map(|i| [i; 32]).collect();
        permutations(&mut hashes, 0);
    }
}

#[test]
fn full_hash_breaks_prefix_ties_in_lexicographic_order() {
    let mut hashes = Vec::new();
    for prefix in [0u64, 1, 255, 256, u64::MAX] {
        for suffix in [0u64, 1, 255, 256, u64::MAX] {
            let mut hash = [0; 32];
            hash[..8].copy_from_slice(&prefix.to_be_bytes());
            hash[24..].copy_from_slice(&suffix.to_be_bytes());
            hashes.push(hash);
        }
    }
    hashes.reverse();
    check_order(&hashes);
    hashes.extend_from_within(..);
    hashes.rotate_left(13);
    check_order(&hashes);
}

#[test]
fn native_indices_cross_byte_and_u16_boundaries() {
    for len in [255usize, 256, 257, 65_535, 65_536, 65_537] {
        let mut nodes: Vec<_> = (0..len)
            .map(|i| {
                let mut hash = [0; 32];
                hash[32 - size_of::<usize>()..].copy_from_slice(&i.to_be_bytes());
                entry(hash, i)
            })
            .collect();
        // A single cycle crosses the boundary; reversing adds many short cycles.
        nodes.rotate_left(1);
        by_hash(&mut nodes);
        for (i, node) in nodes.iter().enumerate() {
            assert_eq!(&node.hash[32 - size_of::<usize>()..], i.to_be_bytes());
        }
        nodes.reverse();
        by_hash(&mut nodes);
        assert!(nodes.is_sorted_by_key(|e| e.hash));
    }
}

#[test]
fn constructor_deduplicates_without_copying_surviving_buffers() {
    let mut input: Vec<_> = (0..32).map(|i| entry([0; 32], i).bytes).collect();
    input.extend_from_within(..);
    input.reverse();
    let expected: std::collections::BTreeMap<_, _> =
        input.iter().map(|b| (keccak256(b), b.clone())).collect();
    let pointers: Vec<_> = input.iter().map(Vec::as_ptr).collect();
    let store = NodeStore::new(input);
    assert_eq!(store.len(), expected.len());
    for node in &store.nodes {
        assert!(pointers.contains(&node.bytes.as_ptr()));
        assert_eq!(node.bytes, expected[&node.hash]);
        assert!(store.contains(&node.hash));
        let Decoded::Leaf { value_start, .. } = node.decoded.unwrap() else {
            panic!("expected leaf")
        };
        assert_eq!(
            store.get(node.hash, &[]),
            Ok(Some(&node.bytes[value_start..]))
        );
    }
}
