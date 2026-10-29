#![no_main]

use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);

fn main() {
    let (implementation, values, expected): (usize, Vec<Vec<u8>>, [u8; 32]) = env::read();
    let slices: Vec<_> = values.iter().map(Vec::as_slice).collect();
    let start = env::cycle_count();
    let actual = (aurora_evm_trie_bench::IMPLEMENTATIONS[implementation].1)(&slices);
    let cycles = env::cycle_count() - start;
    assert_eq!(
        actual, expected,
        "RV32 root differs from the independent oracle"
    );
    env::commit(&(actual, cycles));
}
