//! Separate timing and allocator-instrumented runs over the same sparse workloads.

use aurora_evm_trie::sparse::{LookupError, NodeStore};
use aurora_evm_trie_bench::sparse::{baseline, datasets, keccak256};
use std::hint::black_box;
#[cfg(not(feature = "allocations"))]
use std::time::{Duration, Instant};

#[cfg(feature = "allocations")]
mod allocations {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static BYTES: AtomicUsize = AtomicUsize::new(0);
    pub struct Counter;
    // Instrumentation only; requests are forwarded unchanged to the system allocator.
    unsafe impl GlobalAlloc for Counter {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            CALLS.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size(), Relaxed);
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) }
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new: usize) -> *mut u8 {
            CALLS.fetch_add(1, Relaxed);
            BYTES.fetch_add(new, Relaxed);
            unsafe { System.realloc(pointer, layout, new) }
        }
    }
    pub fn measure<T>(f: impl FnOnce() -> T) -> (T, (usize, usize)) {
        let before = (CALLS.load(Relaxed), BYTES.load(Relaxed));
        let result = f();
        (
            result,
            (
                CALLS.load(Relaxed) - before.0,
                BYTES.load(Relaxed) - before.1,
            ),
        )
    }
}

#[cfg(feature = "allocations")]
#[global_allocator]
static ALLOCATOR: allocations::Counter = allocations::Counter;

#[cfg(not(feature = "allocations"))]
fn elapsed(mut f: impl FnMut()) -> Duration {
    let start = Instant::now();
    let mut iterations = 0;
    while start.elapsed() < Duration::from_millis(40) {
        f();
        iterations += 1;
    }
    start.elapsed() / iterations
}

fn main() {
    #[cfg(feature = "allocations")]
    assert_eq!(
        allocations::measure(|| NodeStore::new(Vec::new())).1,
        (0, 0),
        "empty index allocated"
    );
    for data in datasets() {
        let candidate = NodeStore::new(data.nodes.clone());
        let baseline = baseline::NodeStore::new(data.nodes.clone());
        for query in &data.queries {
            assert_eq!(
                candidate.get(data.root, &query.key).unwrap(),
                query.value.as_deref()
            );
            assert_eq!(
                baseline.get(data.root, &query.key).unwrap(),
                query.value.as_deref()
            );
        }
        let run_candidate = || {
            for query in &data.queries {
                black_box(candidate.get(data.root, black_box(&query.key))).unwrap();
            }
        };
        let run_baseline = || {
            for query in &data.queries {
                black_box(baseline.get(data.root, black_box(&query.key))).unwrap();
            }
        };
        #[cfg(feature = "allocations")]
        {
            let (_, lookup) = allocations::measure(run_candidate);
            assert_eq!(lookup, (0, 0), "{} lookup allocated", data.name);
            let (_, old_lookup) = allocations::measure(run_baseline);
            let nodes = data.nodes.clone();
            let unsorted = !nodes.iter().map(|node| keccak256(node)).is_sorted();
            let (_, build) = allocations::measure(|| NodeStore::new(nodes));
            assert_eq!(
                build.0,
                usize::from(!data.nodes.is_empty()) + usize::from(unsorted),
                "{} index allocation count",
                data.name
            );
            let nodes = data.nodes.clone();
            let (_, old_build) = allocations::measure(|| baseline::NodeStore::new(nodes));
            println!(
                "{}: lookup={lookup:?} baseline_lookup={old_lookup:?} build={build:?} baseline_build={old_build:?}",
                data.name
            );
            // Sorting, reversal and duplicates must not change any proof result.
            let mut ordered = data.nodes.clone();
            ordered.sort_unstable_by_key(|node| keccak256(node));
            for variant in 0..3 {
                let mut nodes = ordered.clone();
                if variant == 1 {
                    nodes.reverse();
                } else if variant == 2 {
                    nodes.extend_from_within(..);
                }
                let unsorted = !nodes.iter().map(|node| keccak256(node)).is_sorted();
                let expected_calls = usize::from(!nodes.is_empty()) + usize::from(unsorted);
                let (store, allocation) = allocations::measure(|| NodeStore::new(nodes));
                assert_eq!(
                    allocation.0, expected_calls,
                    "{} variant {variant}",
                    data.name
                );
                assert_eq!(store.len(), candidate.len());
                let (_, lookup) = allocations::measure(|| {
                    for query in &data.queries {
                        assert_eq!(
                            store.get(data.root, &query.key).unwrap(),
                            query.value.as_deref()
                        );
                    }
                });
                assert_eq!(lookup, (0, 0));
            }
        }
        #[cfg(not(feature = "allocations"))]
        {
            let mut new_times = Vec::new();
            let mut old_times = Vec::new();
            let mut new_build = Vec::new();
            let mut old_build = Vec::new();
            for round in 0..9 {
                // Alternate order to reduce systematic warmup and thermal bias.
                for offset in 0..2 {
                    if (round + offset) % 2 == 0 {
                        new_times.push(elapsed(run_candidate));
                    } else {
                        old_times.push(elapsed(run_baseline));
                    }
                }
                for offset in 0..2 {
                    let nodes = data.nodes.clone(); // Input allocation is outside the timer.
                    let start = Instant::now();
                    if (round + offset) % 2 == 0 {
                        let store = NodeStore::new(nodes);
                        new_build.push(start.elapsed());
                        black_box(&store);
                    } else {
                        let store = baseline::NodeStore::new(nodes);
                        old_build.push(start.elapsed());
                        black_box(&store);
                    }
                }
            }
            new_times.sort();
            old_times.sort();
            new_build.sort();
            old_build.sort();
            println!(
                "{}: {} queries; lookup median {:?} baseline {:?}; build median {:?} baseline {:?}",
                data.name,
                data.queries.len(),
                new_times[4],
                old_times[4],
                new_build[4],
                old_build[4]
            );
        }
    }
    // Error paths must obey the same zero-allocation contract as successful lookups.
    let bytes = vec![0xc3, 0x20, 1, 0xb8];
    let hash = keccak256(&bytes);
    let malformed = NodeStore::new([bytes]);
    let missing = NodeStore::default();
    let verify_errors = || {
        assert_eq!(
            malformed.get(hash, &[]),
            Err(LookupError::MalformedNode(hash))
        );
        assert_eq!(missing.get(hash, &[]), Err(LookupError::BlindedNode(hash)));
    };
    #[cfg(feature = "allocations")]
    assert_eq!(allocations::measure(verify_errors).1, (0, 0));
    #[cfg(not(feature = "allocations"))]
    verify_errors();
}
