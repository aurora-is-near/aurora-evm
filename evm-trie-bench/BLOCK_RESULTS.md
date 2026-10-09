# Integrated stateless-validation RV32 results

Measured on 2026-10-09. These are fresh guest executions, not host timings or estimates.
Each of nine workloads runs once per hash configuration and instrumentation mode: 36 sessions.
Cycle counts are deterministic for the pinned ELF/input; they are not a statistical wall-clock study.

## Configuration and reproduction

- Repository base: `f3ef34e970e0fd08b7f3fdff9e17565d9892e1bd`, plus the stage-7 changes in this tree.
- Host Rust: `1.99.0 (b940084d7 2026-09-28)`; guest Rust: RISC Zero `1.91.1-dev (30e2186d0)`.
- `r0vm 3.0.4`, `risc0-zkvm 3.0.6`, C toolchain `2024.1.5`; v1-compatible kernel.
- Release: opt-level 3, fat LTO, one codegen unit, abort panics, debug symbols for profiling.
- Guest builds use plain Cargo; `guest/.cargo/config.toml` supplies the C toolchain names,
  `CFLAGS` and `RISC0_FEATURE_bigint2` that `risc0-build` would set. No build scripts.
- Guest-only portability patches: blst `7d1fc3e6d8cf0d52a291f52455233bf8d6432ed2`,
  c-kzg `fabdb9302039391d6fd3c47487d1316bdca8888c`.
- Accelerated tiny-keccak: `8fcc866dc94dcec3e79c3b2bc8fbc51b22f2d5e1`.
  The software build uses the default sha3 backend. The optional feature switches block-execution
  and trie hashing together; it does not claim to accelerate every hash in EVM dependencies.
- Reference sources inspected: zeth `3fe7de60ad08b47dde876bfc874e0f6069daff1f`,
  its stateless dependency `6e55612`, reth `a8e0ae87961f759a1a0b78c82324156e53c3f4be`.

Measured ELF SHA-256 (including debug information, so local source paths can affect this hash;
every cycle count below was re-verified bit-for-bit after the config-driven build replaced the
earlier scripted one):

```text
software     336bc4229148a05b0ecda60286b378c5aad3ff8a8cecebdfe77fc976b3ff8ead
accelerated  dcfc12d3ea7e77ca6e50e0d3eaed09e077c855d98d124cefb2eb2b62af0072ee
```

See [README](README.md#integrated-stateless-validation) for exact build/run/profile commands.
Both lockfiles are required. The host uses the external dev-mode executor to obtain
`SessionStats`: it executes the real guest but **does not construct or verify a cryptographic
proof**. Its fake receipt must never be used as a production proof.

## Workloads and independent checks

`Replace/Noop/Delete/Create-AxS` means A target accounts with S slots each. Replace writes 2
over 1; Noop writes 1 over 1; Delete zeroes slots. Create runs initialization writes on fresh
contracts (storage wipe/initialization). All include 128 untouched accounts. Storage overlays
are reset and reused across accounts within one validation, not across unrelated guest sessions.
Witness node preimages are deduplicated; these fixtures supply full witnesses, not minimal proofs.

`EmptyAccounts-16x0` removes pre-existing empty accounts via zero-value withdrawal credits.
`Recreate-4x1` uses four CREATE2 factories: each creates and destroys a child within the first
transaction, then recreates the same address in a second transaction. Host assertions check the
intermediate absence and final nonce/storage. This obeys post-Cancun EIP-6780; it is not deletion
of a pre-existing contract. It measures the combined workload, not a claim that every backend
wipe branch dominates that block.

Synthetic Osaka fixtures deliberately use STOP code at request-system addresses. They exercise
the real calls but not nonempty request queues; no precompile is replaced. Nonempty logs are
emitted by storage runtimes. Synthetic expected state roots use the independent full-map
triehash builder; receipt/transaction/withdrawal roots use its ordered builder.

The ninth case pins an unmodified EEST `tests@v20.0.2` Osaka access-list block and pre-state:
`testdata/block-osaka.json` contains its source path, test name and fixture hash.
Expected commitments come from the official header, not our executor.
File SHA-256: `ddbfc68db34f053ff7aa9908980f65fc8d72a58a97c90caca1fe66c88edcf34e`.
Expected block hash: `0cf00527aa9c3c9768adfe336483be1dd2f5370a88682bd3c20de605eb7d87c3`.

## Ordinary production validation: before / after

The measured region calls the ordinary, unchanged `stateless_validation`, without stage hooks.
Input deserialization, block RLP decoding and preparation precede the region; session statistics
below include them. Heap is bump growth including abandoned capacities, **not peak live memory**.
Four-byte measurement markers are subtracted. Returned state teardown is outside the region.

| Workload | Software cycles | Accelerated cycles | Reduction | Software heap bytes | Accelerated heap bytes |
|---|---:|---:|---:|---:|---:|
| Replace-1x16-Cancun | 10819727 | 6120860 | 43.4% | 77032 | 77032 |
| Replace-8x32-Cancun | 72081267 | 52619536 | 27.0% | 296304 | 297712 |
| Replace-16x64-Osaka | 211572650 | 148801374 | 29.7% | 953088 | 957904 |
| Noop-8x32-Osaka | 54172968 | 44788558 | 17.3% | 253536 | 253536 |
| Delete-8x32-Osaka | 63569109 | 49898808 | 21.5% | 326440 | 326712 |
| Create-8x32-Osaka | 63751227 | 46859805 | 26.5% | 320196 | 320468 |
| EmptyAccounts-16x0-Osaka | 6285838 | 1783032 | 71.6% | 89660 | 89660 |
| Recreate-4x1-Osaka | 40822693 | 35580187 | 12.8% | 176888 | 176888 |
| EEST-Osaka-access-list | 7765667 | 5118731 | 34.1% | 71588 | 71588 |

This supports retaining the optional hash backend: every measured workload improves.
The EEST case saves 34.1% of validation cycles and 28.8% of padded session cycles, with unchanged
validation heap. Some larger workloads allocate slightly more with acceleration (up to 4,816
bytes here); the table reports that cost rather than claiming universal zero-memory overhead.
These numbers are **not** an overall mainnet, proving-time or all-block zkEVM speedup.

## Whole-session accounting, without hooks

`total = user + paging + reserved`; total includes segment padding. Paging cannot be inferred
from validation heap alone, and phase counters must not be added to session totals.

### Software

| Workload | User | Paging | Reserved | Total | Segments |
|---|---:|---:|---:|---:|---:|
| Replace-1x16-Cancun | 13555868 | 614593 | 509603 | 14680064 | 14 |
| Replace-8x32-Cancun | 75354094 | 3609181 | 2301365 | 81264640 | 78 |
| Replace-16x64-Osaka | 215697402 | 11656329 | 6495101 | 233848832 | 224 |
| Noop-8x32-Osaka | 57488447 | 2756501 | 1752108 | 61997056 | 60 |
| Delete-8x32-Osaka | 66888036 | 3289812 | 2173896 | 72351744 | 69 |
| Create-8x32-Osaka | 67517649 | 2957032 | 2139207 | 72613888 | 70 |
| EmptyAccounts-16x0-Osaka | 9165354 | 407062 | 389056 | 9961472 | 10 |
| Recreate-4x1-Osaka | 43623753 | 1558420 | 1479459 | 46661632 | 45 |
| EEST-Osaka-access-list | 9407123 | 495590 | 583047 | 10485760 | 10 |

### Accelerated

| Workload | User | Paging | Reserved | Total | Segments |
|---|---:|---:|---:|---:|---:|
| Replace-1x16-Cancun | 8858881 | 542718 | 297729 | 9699328 | 10 |
| Replace-8x32-Cancun | 55897552 | 2969322 | 1950534 | 60817408 | 58 |
| Replace-16x64-Osaka | 152934581 | 9592724 | 4720567 | 167247872 | 160 |
| Noop-8x32-Osaka | 48105917 | 2437343 | 1885540 | 52428800 | 50 |
| Delete-8x32-Osaka | 53223221 | 2888695 | 1625300 | 57737216 | 56 |
| Create-8x32-Osaka | 50631715 | 2529875 | 1626506 | 54788096 | 53 |
| EmptyAccounts-16x0-Osaka | 4664428 | 313802 | 264650 | 5242880 | 5 |
| Recreate-4x1-Osaka | 38383127 | 1496995 | 1145414 | 41025536 | 40 |
| EEST-Osaka-access-list | 6762067 | 446204 | 262833 | 7471104 | 8 |

## Phase attribution

Separate sessions enable the feature-gated stage hook. Cells are `cycles / heap bytes`.
Phase boundaries omit callback bookkeeping; total validation includes it. The software hook
adds 2,165–2,166 validation cycles per case. Marker-adjusted heap matches the ordinary path.
Output construction after Finished is included only in the total, not a phase.
The profiler is for attribution; ordinary sessions above are the performance baseline.

### Software

| Workload | Recovery | Consensus | Witness indexing | Execution | Commitments | Sparse root |
|---|---:|---:|---:|---:|---:|---:|
| Replace-1x16-Cancun | 4121437 / 1360 | 234907 / 7780 | 3990980 / 17168 | 960156 / 21160 | 61799 / 1280 | 1451333 / 28284 |
| Replace-8x32-Cancun | 33243012 / 1520 | 440185 / 10020 | 4751939 / 19940 | 15844993 / 199364 | 530958 / 1280 | 17271065 / 64180 |
| Replace-16x64-Osaka | 66550183 / 1840 | 651253 / 12580 | 6111935 / 24772 | 70484726 / 782292 | 1045756 / 1280 | 66729681 / 130324 |
| Noop-8x32-Osaka | 33243012 / 1520 | 442491 / 10020 | 4840446 / 20236 | 14720682 / 213708 | 535962 / 1280 | 391259 / 6772 |
| Delete-8x32-Osaka | 33243012 / 1520 | 442491 / 10020 | 4840424 / 20236 | 15653408 / 229260 | 535962 / 1280 | 8854696 / 64124 |
| Create-8x32-Osaka | 34566042 / 3568 | 1789207 / 12068 | 3529938 / 15404 | 8381673 / 223620 | 535962 / 1280 | 14949289 / 64256 |
| EmptyAccounts-16x0-Osaka | 1500 / 1280 | 319603 / 7460 | 4025184 / 17252 | 695616 / 19428 | 7355 / 0 | 1237464 / 44240 |
| Recreate-4x1-Osaka | 33268075 / 1520 | 442515 / 10020 | 3707644 / 16120 | 1491354 / 116744 | 523122 / 1280 | 1390867 / 31204 |
| EEST-Osaka-access-list | 4131542 / 1360 | 255849 / 7780 | 2134731 / 5672 | 501595 / 43784 | 65203 / 1280 | 677631 / 11712 |

### Accelerated

| Workload | Recovery | Consensus | Witness indexing | Execution | Commitments | Sparse root |
|---|---:|---:|---:|---:|---:|---:|
| Replace-1x16-Cancun | 4076322 / 1360 | 70070 / 7780 | 745193 / 17168 | 650230 / 21160 | 16808 / 1280 | 563122 / 28284 |
| Replace-8x32-Cancun | 32882190 / 1520 | 128555 / 10020 | 871432 / 19940 | 11789345 / 199364 | 125543 / 1280 | 6823356 / 65588 |
| Replace-16x64-Osaka | 65828515 / 1840 | 193145 / 12580 | 1092593 / 24772 | 54828782 / 783700 | 249314 / 1280 | 26609909 / 133732 |
| Noop-8x32-Osaka | 32882190 / 1520 | 131290 / 10020 | 885612 / 20236 | 10620523 / 213708 | 130547 / 1280 | 139280 / 6772 |
| Delete-8x32-Osaka | 32882190 / 1520 | 131290 / 10020 | 885590 / 20236 | 11553289 / 229260 | 130547 / 1280 | 4316786 / 64396 |
| Create-8x32-Osaka | 33251204 / 3568 | 395174 / 12068 | 667661 / 15404 | 7931623 / 223620 | 130547 / 1280 | 4484480 / 64528 |
| EmptyAccounts-16x0-Osaka | 1500 / 1280 | 94687 / 7460 | 753203 / 17252 | 399231 / 19428 | 7365 / 0 | 527930 / 44240 |
| Recreate-4x1-Osaka | 32907253 / 1520 | 131314 / 10020 | 698779 / 16120 | 1222208 / 116744 | 115163 / 1280 | 506354 / 31204 |
| EEST-Osaka-access-list | 4086820 / 1360 | 75719 / 7780 | 332985 / 5672 | 383159 / 43784 | 19898 / 1280 | 221034 / 11712 |

The accelerated EEST case spends about 80% of measured validation cycles in sender recovery.
Witness indexing drops from 2,134,731 to 332,985 cycles; the sparse-root phase drops from 677,631
to 221,034. The no-op workload allocates only 6,772 bytes in reconstruction, versus 65,588 for
the comparable replacement workload: the changed-account/slot filter and resettable storage
overlay remain useful. These comparisons do not isolate the cost of either data structure.

## Decisions and limits

- Keep ordinary production names and flow. Profiling composition is wholly under `profiling`;
  success, early errors and reconstruction errors are compared against production in tests.
- Keep the measured optional Keccak backend; default hashing and consensus behavior are unchanged.
  Hash padding-boundary tests, pinned roots, full EEST and guest commitments check equivalence.
- Do not guess arena capacities or replace BTree sets/maps from these aggregate measurements.
  Such policies need isolated comparisons across minimal and redundant witnesses; bump growth
  makes over-reservation costly. No unmeasured data-structure optimization is included.
- Keep release encoder-completion assertions. No measured result justifies weakening them.
- The benchmark does not cover mainnet block distributions, heavy blob/precompile workloads,
  nonempty Prague request queues, every typed transaction, or proof generation. Host EEST covers
  substantially more consensus behavior but is not evidence of those workloads' guest performance.
- Sampling profiles were generated successfully for the pinned EEST case in both hook modes.
  Profile files and local logs are not committed; commands reproduce them.
