//! Runs each algorithm in a fresh guest; optional proving uses the same ELF and inputs.

use aurora_evm_trie_bench::{IMPLEMENTATIONS, cases};
use risc0_zkvm::{ExecutorEnv, default_executor, default_prover};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let user_elf = std::fs::read(args.next().ok_or("usage: guest-host ELF [--prove]")?)?;
    let elf =
        risc0_binfmt::ProgramBinary::new(&user_elf, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    let options: Vec<_> = args.collect();
    let prove = options.iter().any(|arg| arg == "--prove");
    let boundary = options.iter().any(|arg| arg == "--boundary");
    let sizes: Vec<usize> = options
        .iter()
        .filter(|arg| *arg != "--prove" && *arg != "--boundary")
        .map(|arg| arg.parse())
        .collect::<Result<_, _>>()?;
    let sizes = if sizes.is_empty() {
        vec![0, 1, 16, 128, 200, 2000]
    } else {
        sizes
    };
    let cases = cases();
    let pool = cases
        .iter()
        .filter(|c| c.kind == "transactions")
        .max_by_key(|c| c.values.len())
        .unwrap();
    let pool: Vec<_> = pool
        .values
        .iter()
        .map(|v| hex::decode(v).unwrap())
        .collect();

    for count in sizes {
        let values: Vec<_> = (0..count)
            .map(|i| {
                if boundary {
                    let mut value = vec![0x81; 37];
                    value[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
                    value
                } else {
                    pool[i % pool.len()].clone()
                }
            })
            .collect();
        let slices: Vec<_> = values.iter().map(Vec::as_slice).collect();
        let expected = aurora_evm_trie_bench::alloy(&slices);
        for (index, (name, _)) in IMPLEMENTATIONS.iter().enumerate() {
            let env = ExecutorEnv::builder()
                .write(&(index, &values, expected))?
                .build()?;
            let start = std::time::Instant::now();
            if prove {
                let info = default_prover().prove(env, &elf)?;
                info.receipt.verify(risc0_zkvm::compute_image_id(&elf)?)?;
                let (root, measured): ([u8; 32], u64) = info.receipt.journal.decode()?;
                assert_eq!(root, expected);

                println!(
                    "n={count} {name}: region={measured} user={} total={} proof_ms={}",
                    info.stats.user_cycles,
                    info.stats.total_cycles,
                    start.elapsed().as_millis()
                );
            } else {
                let session = default_executor().execute(env, &elf)?;
                let (root, measured): ([u8; 32], u64) = session.journal.decode()?;
                assert_eq!(root, expected);

                let padded: u64 = session
                    .segments
                    .iter()
                    .map(|segment| 1u64 << segment.po2)
                    .sum();

                println!(
                    "n={count} {name}: region={measured} session_user={} padded={padded} segments={} execute_ms={}",
                    session.cycles(),
                    session.segments.len(),
                    start.elapsed().as_millis()
                );
            }
        }
    }
    Ok(())
}
