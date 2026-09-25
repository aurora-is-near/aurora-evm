//! Shared sparse guest protocol; input generation and result checks are outside timed regions.

use aurora_evm_trie::sparse::{LookupError, NodeStore};
use serde::{Deserialize, Serialize};
use std::hint::black_box;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Answer {
    Value(Vec<u8>),
    Absent,
    Blinded([u8; 32]),
    Malformed([u8; 32]),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Query {
    pub key: Vec<u8>,
    pub expected: Answer,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Input {
    pub root: [u8; 32],
    pub nodes: Vec<Vec<u8>>,
    pub queries: Vec<Query>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Output {
    pub build_cycles: u64,
    pub lookup_cycles: u64,
    pub distinct_nodes: usize,
    pub queries: usize,
}

/// Measures the production index, then verifies every value and error outside both timers.
pub fn run(input: Input, cycles: impl Fn() -> u64) -> Output {
    let start = cycles();
    let store = NodeStore::new(input.nodes);
    let build_cycles = cycles() - start;
    let start = cycles();
    for query in &input.queries {
        let _ = black_box(store.get(input.root, black_box(&query.key)));
    }
    let lookup_cycles = cycles() - start;
    for query in &input.queries {
        let expected = match &query.expected {
            Answer::Value(value) => Ok(Some(value.as_slice())),
            Answer::Absent => Ok(None),
            Answer::Blinded(hash) => Err(LookupError::BlindedNode(*hash)),
            Answer::Malformed(hash) => Err(LookupError::MalformedNode(*hash)),
        };
        assert_eq!(store.get(input.root, &query.key), expected);
    }
    Output {
        build_cycles,
        lookup_cycles,
        distinct_nodes: store.len(),
        queries: input.queries.len(),
    }
}
