//! Malformed RLP, noncanonical MPT structure, and partial-proof boundaries.

use super::super::{LookupError, NodeStore};
use crate::crypto::keccak256;

fn leaf(path: &[u8], value: &[u8]) -> Vec<u8> {
    let mut s = rlp::RlpStream::new_list(2);
    s.append(&path).append(&value);
    s.out().to_vec()
}

fn extension(path: &[u8], child: &[u8]) -> Vec<u8> {
    let mut s = rlp::RlpStream::new_list(2);
    s.append(&path).append_raw(child, 1);
    s.out().to_vec()
}

fn branch(child: &[u8]) -> Vec<u8> {
    let mut s = rlp::RlpStream::new_list(17);
    s.append_raw(child, 1);
    s.append_raw(&leaf(&[0x30], &[2]), 1);
    for _ in 2..17 {
        s.append_empty_data();
    }
    s.out().to_vec()
}

fn reject(bytes: Vec<u8>) {
    let hash = keccak256(&bytes);
    let store = NodeStore::new([bytes]);
    assert_eq!(store.get(hash, &[]), Err(LookupError::MalformedNode(hash)));
}

#[test]
fn rejects_truncated_noncanonical_and_trailing_rlp() {
    for raw in [
        vec![],
        vec![0xc0],
        vec![0xc3, 0x20, 1, 0xb8], // Truncated third item formerly hidden by item_count.
        vec![0xc3, 0x20, 0x81, 1], // Nonminimal single-byte string.
        vec![0xf8, 2, 0x20, 1],    // Long list header for a short payload.
        vec![0xc4, 0x20, 0xb8, 1, 0x80], // Long string header for a short value.
        vec![0xf9, 0, 56],         // Leading zero in the length.
        vec![0xff; 9], // Length overflows or exceeds available bytes on both native widths.
        vec![0xc2, 0x20, 1, 0x80], // Extra item beyond the declared list.
        vec![0xc3, 0x20, 1], // Truncated list.
    ] {
        reject(raw);
    }
    for count in [1, 3, 16, 18] {
        reject(rlp::encode_list::<u8, _>(&vec![0; count]).to_vec());
    }
}

#[test]
fn rejects_invalid_paths_leaf_values_and_extension_targets() {
    for path in [&[][..], &[0x40], &[0x21], &[0x01]] {
        reject(leaf(path, &[1]));
    }
    reject(vec![0xc2, 0x20, 0xc0]); // Leaf value must be a string.
    reject(extension(&[0], &leaf(&[0x20], &[1]))); // Empty extension.
    reject(extension(&[0x11], &[0x80])); // Empty child.
    reject(extension(&[0x11], &leaf(&[0x30], &[1]))); // Extensions must lead to branches.
    for size in [1, 31, 33] {
        reject(extension(&[0x11], &rlp::encode(&vec![0x80; size])));
    }
}

#[test]
fn child_threshold_is_strict_but_short_roots_are_valid() {
    for (length, encoded_length) in [(28, 31), (29, 32), (30, 33)] {
        let value = vec![0x42; length];
        let child = leaf(&[0x30], &value);
        assert_eq!(child.len(), encoded_length);
        let inline = branch(&child);
        let root = keccak256(&inline);
        let store = NodeStore::new([inline]);
        if encoded_length < 32 {
            assert_eq!(store.get(root, &[0]), Ok(Some(value.as_slice())));
        } else {
            assert_eq!(store.get(root, &[0]), Err(LookupError::MalformedNode(root)));
        }
        let child_hash = keccak256(&child);
        let hashed = branch(&rlp::encode(&child_hash.as_slice()));
        let root = keccak256(&hashed);
        let store = NodeStore::new([hashed, child.clone()]);
        if encoded_length < 32 {
            assert_eq!(
                store.get(root, &[0]),
                Err(LookupError::MalformedNode(child_hash))
            );
        } else {
            assert_eq!(store.get(root, &[0]), Ok(Some(value.as_slice())));
        }
        let store = NodeStore::new([child]);
        // A short root is valid, even though its odd path cannot match a whole byte key.
        assert_eq!(store.get(child_hash, &[]), Ok(None));
    }
    let root_node = leaf(&[0x20], &[1]);
    let root = keccak256(&root_node);
    assert_eq!(
        NodeStore::new([root_node]).get(root, &[]),
        Ok(Some(&[1][..]))
    );
}

#[test]
fn rejects_hashed_extension_chains_and_preserves_missing_proofs() {
    let child = leaf(&[0x30], &[0x42; 40]);
    let child_hash = keccak256(&child);
    let root_node = extension(&[0x11], &rlp::encode(&child_hash.as_slice()));
    let root = keccak256(&root_node);
    let incomplete = NodeStore::new([root_node.clone()]);
    assert_eq!(
        incomplete.get(root, &[0x10]),
        Err(LookupError::BlindedNode(child_hash))
    );
    // A diverging path is proven absent without revealing the child.
    assert_eq!(incomplete.get(root, &[0x20]), Ok(None));
    let store = NodeStore::new([root_node, child]);
    assert_eq!(
        store.get(root, &[0x10]),
        Err(LookupError::MalformedNode(child_hash))
    );
}

#[test]
fn validates_unselected_inline_children_and_branch_occupancy() {
    let bad = branch(&leaf(&[0x40], &[1]));
    reject(bad);
    // A unary branch must have been compressed.
    let mut s = rlp::RlpStream::new_list(17);
    s.append_raw(&leaf(&[0x30], &[1]), 1);
    for _ in 1..17 {
        s.append_empty_data();
    }
    reject(s.out().to_vec());
    // Branch terminal values cannot be lists.
    let mut raw = branch(&leaf(&[0x30], &[1]));
    *raw.last_mut().unwrap() = 0xc0;
    reject(raw);
}

#[test]
fn malformed_unused_nodes_do_not_poison_valid_lookups() {
    let valid = leaf(&[0x20], &[1]);
    let root = keccak256(&valid);
    let store = NodeStore::new([vec![0xc3, 0x20, 1, 0xb8], valid]);
    assert_eq!(store.get(root, &[]), Ok(Some(&[1][..])));
}

#[test]
fn branch_offsets_support_large_terminal_values() {
    let value = vec![0x42; 70_000];
    let mut s = rlp::RlpStream::new_list(17);
    s.append_raw(&leaf(&[0x30], &[1]), 1);
    for _ in 1..16 {
        s.append_empty_data();
    }
    s.append(&value);
    let node = s.out().to_vec();
    let root = keccak256(&node);
    let store = NodeStore::new([node]);
    assert_eq!(store.get(root, &[]), Ok(Some(value.as_slice())));
    assert_eq!(store.get(root, &[0]), Ok(Some(&[1][..])));
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut state = 1u64;
    for length in 0..128 {
        for _ in 0..32 {
            let bytes: Vec<_> = (0..length)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state.to_le_bytes()[0]
                })
                .collect();
            let root = keccak256(&bytes);
            let store = NodeStore::new([bytes]);
            let _ = store.get(root, &state.to_be_bytes());
        }
    }
}
