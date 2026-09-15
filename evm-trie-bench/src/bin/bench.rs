//! Time and allocation runs are separate builds; input preparation is outside both measurements.

use aurora_evm_trie_bench::{cases, IMPLEMENTATIONS};
use std::hint::black_box;
#[cfg(not(feature = "allocations"))]
use std::time::{Duration, Instant};

#[cfg(feature = "allocations")]
mod allocations {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    pub static CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static BYTES: AtomicUsize = AtomicUsize::new(0);
    pub struct Counter;

    // Instrumentation only: every request is forwarded unchanged to the system allocator.
    unsafe impl GlobalAlloc for Counter {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            CALLS.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size(), Relaxed);
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) };
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new: usize) -> *mut u8 {
            CALLS.fetch_add(1, Relaxed);
            BYTES.fetch_add(new, Relaxed);
            unsafe { System.realloc(pointer, layout, new) }
        }
    }
}

#[cfg(feature = "allocations")]
#[global_allocator]
static ALLOCATOR: allocations::Counter = allocations::Counter;

fn main() {
    let cases = cases();
    // Keep transaction and withdrawal workloads separate. Repeat a pinned transaction block
    // only for the explicitly synthetic large-N rows.
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

    println!(
        "backend={}, mode={}",
        if cfg!(feature = "tiny") {
            "tiny-keccak (same for all)"
        } else {
            "sha3 0.10 candidate/baseline; alloy default"
        },
        if cfg!(feature = "allocations") {
            "allocations only"
        } else {
            "timing without allocator instrumentation"
        }
    );

    for n in [0, 1, 16, 128, 200, 2000] {
        let slices: Vec<_> = (0..n).map(|i| pool[i % pool.len()].as_slice()).collect();
        let expected = (IMPLEMENTATIONS[0].1)(&slices);

        for (_, calculate) in IMPLEMENTATIONS {
            assert_eq!(calculate(&slices), expected);
        }

        #[cfg(feature = "allocations")]
        for (name, calculate) in IMPLEMENTATIONS {
            use std::sync::atomic::Ordering::Relaxed;
            let before = (
                allocations::CALLS.load(Relaxed),
                allocations::BYTES.load(Relaxed),
            );
            black_box(calculate(black_box(&slices)));
            let counts = (
                allocations::CALLS.load(Relaxed) - before.0,
                allocations::BYTES.load(Relaxed) - before.1,
            );
            if *name == "candidate" {
                // Every size in this workload fits the builder's stack scratch.
                assert_eq!(
                    counts,
                    (0, 0),
                    "pre-encoded candidate must not allocate for n={n}"
                );
            }

            println!("n={n} {name}: calls={} bytes={}", counts.0, counts.1);
        }

        #[cfg(not(feature = "allocations"))]
        {
            let mut samples = vec![Vec::new(); IMPLEMENTATIONS.len()];
            for round in 0..9 {
                for offset in 0..IMPLEMENTATIONS.len() {
                    let index = (round + offset) % IMPLEMENTATIONS.len();
                    let calculate = IMPLEMENTATIONS[index].1;
                    let start = Instant::now();
                    let mut iterations = 0u32;

                    while start.elapsed() < Duration::from_millis(50) {
                        black_box(calculate(black_box(&slices)));
                        iterations += 1;
                    }

                    samples[index].push(start.elapsed().as_nanos() / u128::from(iterations));
                }
            }

            for ((name, _), mut samples) in IMPLEMENTATIONS.iter().zip(samples) {
                samples.sort_unstable();

                println!(
                    "n={n} {name}: median={}ns min={}ns max={}ns",
                    samples[4], samples[0], samples[8]
                );
            }
        }
    }
    #[cfg(feature = "allocations")]
    check_encoder_allocations();
}

/// Pins the empty fast path and verifies that scratch reuse does not allocate per item.
#[cfg(feature = "allocations")]
fn check_encoder_allocations() {
    use std::sync::atomic::Ordering::Relaxed;

    let mut nonempty_counts = None;
    for n in [0, 1, 16, 200, 2000] {
        let items: Vec<u64> = (0..n).collect();
        let encoded: Vec<_> = items
            .iter()
            .map(|item| rlp::encode(item).to_vec())
            .collect();
        let slices: Vec<_> = encoded.iter().map(Vec::as_slice).collect();
        let expected = aurora_evm_trie_bench::baseline(&slices);
        let before = (
            allocations::CALLS.load(Relaxed),
            allocations::BYTES.load(Relaxed),
        );
        let actual = aurora_evm_trie_bench::encoded_candidate(black_box(&items), |item, stream| {
            stream.clear();
            stream.append(item);
            stream.as_raw()
        });
        let counts = (
            allocations::CALLS.load(Relaxed) - before.0,
            allocations::BYTES.load(Relaxed) - before.1,
        );
        assert_eq!(actual, expected);

        if n == 0 {
            assert_eq!(counts, (0, 0));
        } else {
            assert_eq!(counts, *nonempty_counts.get_or_insert(counts));
        }

        println!(
            "n={n} encoded scalars: calls={} bytes={}",
            counts.0, counts.1
        );
    }
}
