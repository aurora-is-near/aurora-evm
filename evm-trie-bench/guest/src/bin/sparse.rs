#![no_main]

use aurora_evm_trie_bench::sparse_guest::{Input, run};
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);

fn main() {
    let input: Input = env::read();
    let output = run(input, env::cycle_count);
    env::commit(&output);
}
