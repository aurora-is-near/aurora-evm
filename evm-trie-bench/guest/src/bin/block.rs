#![no_main]

use aurora_evm_trie_bench::block_guest::{Input, run};
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);

fn main() {
    let input: Input = env::read();
    let output = run(input, env::cycle_count, || {
        Box::into_raw(Box::new(0u32)).addr()
    });
    env::commit(&output);
}
