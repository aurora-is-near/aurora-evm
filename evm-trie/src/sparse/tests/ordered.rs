//! End-to-end roots and partial proofs across the public ordered and sparse APIs.

use super::super::{LookupError, NodeStore};
use super::reference::hashed_nodes;
use crate::{crypto::keccak256, ordered_trie_root, ordered_trie_root_with_encoder};
use std::collections::BTreeMap;

#[test]
fn ordered_roots_round_trip_through_sparse_proofs() {
    for count in [0usize, 1, 2, 127, 128, 129, 255, 256, 257, 1000] {
        let values: Vec<_> = (0..count)
            .map(|i| rlp::encode(&vec![i.to_le_bytes()[0]; i % 140]).to_vec())
            .collect();
        let items: BTreeMap<_, _> = values
            .iter()
            .enumerate()
            .map(|(i, value)| (rlp::encode(&i).to_vec(), value.clone()))
            .collect();
        let (root, mut nodes) = hashed_nodes(&items);
        assert_eq!(root, ordered_trie_root(&values));
        assert_eq!(
            root,
            ordered_trie_root_with_encoder(&values, |value, stream| {
                stream.clear();
                stream.append_raw(value, 1);
                stream.as_raw()
            })
        );
        nodes.reverse();
        nodes.extend_from_within(..);
        let store = NodeStore::new(nodes);
        for (key, value) in items {
            assert_eq!(store.get(root, &key), Ok(Some(value.as_slice())));
        }
        assert_eq!(store.get(root, &rlp::encode(&count)), Ok(None));
    }
}

#[test]
fn removing_each_hashed_node_never_turns_membership_into_absence() {
    let items: BTreeMap<_, _> = (0usize..32)
        .map(|i| {
            (
                keccak256(&i.to_be_bytes()).to_vec(),
                vec![i.to_le_bytes()[0]; 40],
            )
        })
        .collect();
    let (root, nodes) = hashed_nodes(&items);
    for removed in 0..nodes.len() {
        let hash = keccak256(&nodes[removed]);
        // Filtering deliberately removes the exact-size hint accepted by the constructor.
        let store = NodeStore::new(
            nodes
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != removed)
                .map(|(_, node)| node.clone()),
        );
        let mut rejected = 0;
        for (key, value) in &items {
            match store.get(root, key) {
                Ok(Some(found)) => assert_eq!(found, value),
                Err(LookupError::BlindedNode(missing)) => {
                    assert_eq!(missing, hash);
                    rejected += 1;
                }
                other => panic!("membership was lost: {other:?}"),
            }
        }
        assert!(rejected > 0);
    }
}
