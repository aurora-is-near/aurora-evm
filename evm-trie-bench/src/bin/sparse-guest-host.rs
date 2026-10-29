//! Runs deterministic sparse index workloads in RISC Zero and reports separate guest regions.

use aurora_evm_trie_bench::sparse::{guest_datasets, keccak256};
use aurora_evm_trie_bench::sparse_guest::{Answer, Input, Output, Query};
use risc0_zkvm::{ExecutorEnv, default_executor};
use std::error::Error;

fn measure(name: &str, input: Input, elf: &[u8]) -> Result<(), Box<dyn Error>> {
    let nodes = input.nodes.len();
    let bytes: usize = input.nodes.iter().map(Vec::len).sum();
    let queries = input.queries.len();
    let env = ExecutorEnv::builder().write(&input)?.build()?;
    let session = default_executor().execute(env, elf)?;
    let output: Output = session.journal.decode()?;
    assert_eq!(output.queries, queries);
    let distinct = input
        .nodes
        .iter()
        .map(|node| keccak256(node))
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    assert_eq!(output.distinct_nodes, distinct);
    println!(
        "{name}: nodes={nodes} bytes={bytes} queries={queries} build={} lookup={} session={} segments={}",
        output.build_cycles,
        output.lookup_cycles,
        session.cycles(),
        session.segments.len(),
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let elf = std::fs::read(
        std::env::args()
            .nth(1)
            .ok_or("usage: sparse-guest-host ELF")?,
    )?;
    let elf = risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    for data in guest_datasets() {
        let queries: Vec<_> = data
            .queries
            .into_iter()
            .map(|query| Query {
                key: query.key,
                expected: query.value.map_or(Answer::Absent, Answer::Value),
            })
            .collect();
        measure(
            &data.name,
            Input {
                root: data.root,
                nodes: data.nodes.clone(),
                queries: queries.clone(),
            },
            &elf,
        )?;
        if data.name == "hashed-128" {
            let mut nodes = data.nodes;
            nodes.sort_unstable_by_key(|node| keccak256(node));
            measure(
                "sorted",
                Input {
                    root: data.root,
                    nodes: nodes.clone(),
                    queries: queries.clone(),
                },
                &elf,
            )?;
            nodes.reverse();
            measure(
                "reversed",
                Input {
                    root: data.root,
                    nodes: nodes.clone(),
                    queries: queries.clone(),
                },
                &elf,
            )?;
            nodes.extend_from_within(..);
            let repeated = queries
                .iter()
                .cycle()
                .take(queries.len() * 8)
                .cloned()
                .collect();
            measure(
                "duplicates-repeated",
                Input {
                    root: data.root,
                    nodes,
                    queries: repeated,
                },
                &elf,
            )?;
            measure(
                "withheld-root",
                Input {
                    root: data.root,
                    nodes: vec![],
                    queries: vec![Query {
                        key: queries[0].key.clone(),
                        expected: Answer::Blinded(data.root),
                    }],
                },
                &elf,
            )?;
        }
    }
    let malformed = vec![0xc3, 0x20, 1, 0xb8];
    let root = keccak256(&malformed);
    measure(
        "malformed",
        Input {
            root,
            nodes: vec![malformed],
            queries: vec![Query {
                key: vec![],
                expected: Answer::Malformed(root),
            }],
        },
        &elf,
    )?;
    Ok(())
}
