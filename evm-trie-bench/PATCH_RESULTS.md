# Isolated sparse patch acceptance — 2026-09-25

Stage 1 only: production `sparse::PatchTrie`, without witness-backend or
post-execution state-root integration. Guest: RISC Zero 3.0.6, RV32, release,
`tiny` feature with the pinned accelerated Keccak patch from `guest/Cargo.toml`.
These are execution measurements, not proof-generation timings or a comparison
with another mutable trie implementation.

## Reproduction

From `evm-trie-bench`, using the guest's `risc0` toolchain:

```sh
(cd guest && cargo build --locked --release --features tiny --bin patch --target-dir target/tiny)
RISC0_INFO=1 RUST_LOG=info cargo run --locked --release --no-default-features \
  --features guest-host,sparse,tiny --bin patch-guest-host -- \
  guest/target/tiny/riscv32im-risc0-zkvm-elf/release/patch
```

Each case runs in a fresh guest. Input decoding precedes all region timers.
`NodeStore` construction, overlay initialization, updates (including reset),
finalization, and a cached root read are measured separately. The second round
replays the same updates after reset against the original root and reuses arena
capacities. Upserts precede removals. Root oracles are host-side triehash and
Alloy; each guest round asserts its independently supplied expected root.

Heap figures are **bump-allocation deltas**, not peak live memory. Two leaked
four-byte markers delimit each region; their own allocation is subtracted.
Both markers lie outside the cycle timer. Allocator alignment and abandoned
growth buffers are included. Stack, input buffers, and journal machinery are
not part of these heap deltas. Tiny cached-call cycle values include timer and
call overhead and should not be interpreted as hashing cost.

The `trie-bench.yml` guest job runs this acceptance check on both software and
accelerated Keccak builds. It asserts roots and allocation invariants; cycle
counts remain diagnostic, without unstable timing thresholds. End-to-end block
workloads remain a later integration-stage benchmark.

## Results

The mixed cases replace, insert, and remove equal numbers of keys. Existing
values are 40 bytes; replacements are 80 bytes. Keys are Keccak hashes of fixed
integer inputs. The deep case starts empty and inserts 65 synthetic prehashed
keys that force branches through all 64 nibble positions.

| Initial leaves / workload | Build cycles | Cold update cycles | Finalize cycles | Cold update heap | Reset update cycles | Reset update heap |
|---|---:|---:|---:|---:|---:|---:|
| 128 / 48 mixed updates | 695,637 | 462,978 | 556,115 | 74,880 B | 434,217 | 0 B |
| 1,000 / 192 mixed updates | 5,747,604 | 2,485,507 | 3,093,762 | 455,808 B | 2,313,059 | 0 B |
| 1,000 / 64 equal-value writes | 5,747,604 | 811,750 | 647 | 0 B | 811,750 | 0 B |
| Empty / 65 deep-path inserts | 91 | 214,815 | 866,657 | 152,744 B | 156,384 | 0 B |

Finalization and cached root reads allocate **0 bytes** in every case. Cached
reads take 648–676 measured cycles. The second mixed-1,000 finalization is
3,093,360 cycles; the other reset finalizations match the first round.
Overlay initialization allocates 1,280 bytes for RLP scratch. NodeStore build
allocates 17,104 / 138,812 / 138,812 / 0 bytes respectively.

| Workload | Whole-session user cycles | Whole-session paging cycles | Segments |
|---|---:|---:|---:|
| 128 / mixed | 5,016,304 | 267,450 | 6 |
| 1,000 / mixed | 33,071,420 | 2,206,189 | 35 |
| 1,000 / no-op | 22,505,151 | 754,962 | 23 |
| Deep paths | 2,745,261 | 369,455 | 4 |

Session figures include input decoding, both rounds, checks, and journal output.
Paging is measured for the whole session, not attributed to individual regions.

## Acceptance and limits

- All roots match both independent host implementations; maximum-depth execution
  completes on RV32 without a stack failure.
- No-op writes allocate no overlay memory, retain no read-only paths, and do not
  rehash the root. Unit tests separately count hash calls.
- Reusing reset arenas eliminates subsequent allocations for these workloads;
  creating a new overlay for every storage trie would lose this advantage.
- Cold arena growth remains material, especially for branch-heavy batches.
  Reset does not reclaim previous bump allocations or shrink peak capacity.
  Arena entries superseded within a batch remain until reset.
- Capacity hints are a future measured optimization, not a guaranteed fix:
  update count alone does not determine node/branch counts or encoded value
  bytes. Oversized reservations can increase guest memory and paging costs.
- Real block post-state workloads, minimized witnesses from reth, and comparison
  with other mutable sparse tries remain integration-stage measurements. These
  numbers do not establish an end-to-end zkEVM speedup or global optimality.
