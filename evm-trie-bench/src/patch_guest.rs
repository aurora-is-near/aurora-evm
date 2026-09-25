//! Isolated patch-trie benchmark; no block execution or post-state integration.

use aurora_evm_trie::sparse::{NodeStore, PatchTrie};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Update {
    pub key: [u8; 32],
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Input {
    pub root: [u8; 32],
    pub nodes: Vec<Vec<u8>>,
    pub updates: Vec<Update>,
    pub expected: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Region {
    pub cycles: u64,
    pub heap: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Round {
    pub update: Region,
    pub finalize: Region,
    pub cached: Region,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Output {
    pub build: Region,
    pub initialize: Region,
    pub rounds: Vec<Round>,
    pub root: [u8; 32],
}

/// The heap callback leaks a four-byte marker in the guest's bump allocator.
/// Deltas exclude that marker; counters and assertions are outside the timed operation.
fn measure<T>(
    cycles: &impl Fn() -> u64,
    heap: &impl Fn() -> usize,
    f: impl FnOnce() -> T,
) -> (T, Region) {
    let before = heap();
    let start = cycles();
    let value = f();
    let cycles = cycles() - start;
    let used = heap() - before - 4;
    (value, Region { cycles, heap: used })
}

/// Measures index construction, updates and finalization, then repeats using reset arenas.
pub fn run(input: Input, cycles: impl Fn() -> u64, heap: impl Fn() -> usize) -> Output {
    let (store, build) = measure(&cycles, &heap, || NodeStore::new(input.nodes));
    let (mut trie, initialize) = measure(&cycles, &heap, || PatchTrie::new(&store, input.root));
    let mut rounds = Vec::with_capacity(2);
    for _ in 0..2 {
        let (_, update) = measure(&cycles, &heap, || {
            trie.reset(input.root);
            for update in &input.updates {
                match &update.value {
                    Some(value) => trie.insert(&update.key, value),
                    None => trie.remove(&update.key),
                }
                .unwrap();
            }
        });
        let (root, finalize) = measure(&cycles, &heap, || trie.root_hash().unwrap());
        assert_eq!(root, input.expected);
        let (again, cached) = measure(&cycles, &heap, || trie.root_hash().unwrap());
        assert_eq!(again, root);
        rounds.push(Round {
            update,
            finalize,
            cached,
        });
    }
    Output {
        build,
        initialize,
        rounds,
        root: input.expected,
    }
}
