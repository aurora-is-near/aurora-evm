//! Reproducible sparse workloads; fixture preparation is outside measurements.

pub mod baseline;

use aurora_evm_trie::sparse::reference::hashed_nodes;
use hash_db::Hasher;
use std::collections::BTreeMap;

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    crate::KeccakHasher::hash(bytes)
}

pub struct Query {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}

pub struct Dataset {
    pub name: String,
    pub root: [u8; 32],
    pub nodes: Vec<Vec<u8>>,
    pub queries: Vec<Query>,
}

impl Dataset {
    /// Builds and independently checks the root before preparing hit/miss queries.
    fn new(name: String, items: BTreeMap<Vec<u8>, Vec<u8>>) -> Self {
        let (root, nodes) = hashed_nodes(&items);
        assert_eq!(
            root,
            triehash::trie_root::<crate::KeccakHasher, _, _, _>(&items)
        );
        let mut queries: Vec<_> = items
            .iter()
            .map(|(key, value)| Query {
                key: key.clone(),
                value: Some(value.clone()),
            })
            .collect();
        for i in 0u64..128 {
            let key = keccak256(&(i + 1_000_000).to_be_bytes()).to_vec();
            queries.push(Query {
                value: items.get(&key).cloned(),
                key,
            });
        }
        Self {
            name,
            root,
            nodes,
            queries,
        }
    }
}

/// Secure trie leaves with independent hit/miss expectations.
fn hashed_dataset(count: u64) -> Dataset {
    let items = (0..count)
        .map(|i| {
            (
                keccak256(&i.to_be_bytes()).to_vec(),
                vec![i.to_le_bytes()[0]; 40],
            )
        })
        .collect();
    Dataset::new(format!("hashed-{count}"), items)
}

/// Small deterministic inputs keep the permanent RV32 check inexpensive.
pub fn guest_datasets() -> Vec<Dataset> {
    [0, 1, 128, 1024].into_iter().map(hashed_dataset).collect()
}

/// Covers an empty root, secure paths, and embedded nodes with branch values.
pub fn datasets() -> Vec<Dataset> {
    let mut cases: Vec<_> = [0u64, 1, 128, 10_000]
        .into_iter()
        .map(hashed_dataset)
        .collect();
    cases.push(Dataset::new(
        "embedded".into(),
        [
            (vec![0x12], vec![1]),
            (vec![0x12, 0x34], vec![2]),
            (vec![0x12, 0x35], vec![3]),
            (vec![0x99], vec![4]),
        ]
        .into_iter()
        .collect(),
    ));
    cases
}
