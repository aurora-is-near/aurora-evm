//! Fresh RV32 sessions for each full-production block workload and instrumentation mode.

use aurora_evm_trie_bench::{block_fixtures::cases, block_guest::Output};
use risc0_zkvm::{ExecutorEnv, ExternalProver, Prover, ProverOpts};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let elf = std::fs::read(
        std::env::args()
            .nth(1)
            .ok_or("usage: block-guest-host ELF [case-filter]")?,
    )?;
    let filter = std::env::args().nth(2).unwrap_or_default();
    // The dev-mode server executes the real guest and returns SessionStats without constructing
    // a cryptographic proof. Unlike execute()/SessionInfo, this IPC response includes paging.
    let server = std::env::var_os("RISC0_SERVER_PATH").unwrap_or_else(|| "r0vm".into());
    let prover = ExternalProver::new("block-benchmark", server);
    let opts = ProverOpts::default().with_dev_mode(true);
    let profile_dir = std::env::var_os("BLOCK_PROFILE_DIR").map(std::path::PathBuf::from);
    if let Some(dir) = &profile_dir {
        std::fs::create_dir_all(dir)?;
    }
    let elf = risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    let mut count = 0;
    for (name, mut input) in cases()
        .into_iter()
        .filter(|(name, _)| name.contains(&filter))
    {
        count += 1;
        for with_stage_hook in [false, true] {
            input.with_stage_hook = with_stage_hook;
            println!(
                "case={name} with_stage_hook={with_stage_hook} tx={} nodes={} node_bytes={}",
                input.keys.len(),
                input.nodes.len(),
                input.nodes.iter().map(Vec::len).sum::<usize>()
            );
            let mut builder = ExecutorEnv::builder();
            builder.write(&input)?;
            if let Some(dir) = &profile_dir {
                builder.enable_profiler(dir.join(format!("{name}-hook-{with_stage_hook}.pb")));
            }
            let env = builder.build()?;
            let session = prover.prove_with_opts(env, &elf, &opts)?;
            let output: Output = session.receipt.journal.decode()?;
            assert_eq!(output.block_hash, input.expected_hash);
            assert_eq!(output.gas_used, input.expected_gas);
            assert_eq!(output.receipts, input.keys.len());
            println!(
                "user={} paging={} reserved={} total={} segments={} validation={:?}",
                session.stats.user_cycles,
                session.stats.paging_cycles,
                session.stats.reserved_cycles,
                session.stats.total_cycles,
                session.stats.segments,
                output.total
            );
            if with_stage_hook {
                for (name, region) in [
                    "recovery",
                    "consensus",
                    "witness",
                    "execution",
                    "commitments",
                    "state_root",
                ]
                .iter()
                .zip(output.phases)
                {
                    println!("  {name}={region:?}");
                }
            }
        }
    }
    assert!(count > 0, "case filter matched no workloads");
    Ok(())
}
