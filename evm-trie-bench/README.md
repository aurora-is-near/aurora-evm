# Ordered trie verification and benchmarks

An isolated, named benchmark crate depending on production `aurora-evm-trie`.
The repository workspace explicitly excludes this crate and its RISC Zero guest:
alloy and proving dependencies do not enter normal block-execution builds or gates.
There is no cross-crate source inclusion or alternate copy of the production builder.

Workspace members inherit shared dependency versions from the root manifest;
member-specific optional dependencies and features remain in their own manifests.
This harness and its guest have separate manifests and lockfiles, so they cannot
inherit dependencies from the repository workspace. Benchmark reference versions
remain explicitly pinned here; the guest also owns its toolchain and acceleration
patch. The production path dependency still inherits from its own workspace.

See the production crate's [algorithm and sources](../evm-trie/ALGORITHM.md)
for the dense-index traversal and scratch-bound derivation.

## Comparisons

- `triehash` 0.8.4: previous ordered-root implementation.
- `alloy-trie` 0.9.5: independent streaming reference with sorted RLP-index keys.
- `candidate`: the normal `aurora-evm-trie` dependency.

Default runs preserve native hash backends, which are not identical (`sha3` 0.10
versus alloy's default). `--features tiny` uses `tiny-keccak` for all three.
The benchmark's hash adapter belongs only to the independent `triehash` reference;
it does not replace the production candidate's adapter.

Timing and allocator instrumentation are separate builds. Timing rotates algorithm
order over nine samples of at least 50 ms. Inputs are prepared before either
measurement. Allocation counts include allocation/reallocation requests and the
sum of requested bytes, not peak live memory or guest pages.

```sh
# Run from evm-trie-bench, without other CPU-heavy work.
cargo fmt --all -- --check
cargo fmt --all --manifest-path guest/Cargo.toml -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --release --test pinned_corpus
cargo test --locked --release --features tiny --test pinned_corpus
cargo run --release --features tiny --bin bench
cargo run --release --features tiny,allocations --bin bench
```

The transaction workload uses the largest pinned EEST case. Rows above its 400
transactions repeat the values and are explicitly synthetic. The separate
`body_metrics_benchmark` includes length checks, encoding, withdrawals and roots,
with the old materializing flow retained only as a test baseline:

```sh
# Run from the repository root, alone.
cargo test -p aurora-evm-block-execution --release body_metrics_benchmark -- --ignored --nocapture
```

## Official corpus and length differential

The data owner is `evm-block-execution/testdata/ordered-roots.json`. Both its
trie test and this harness consume that same fixture. It contains 29
size-stratified transaction/withdrawal cases extracted from EEST stable v5.4.0;
each records the fixture path, test name, block index, encoded values and external
header commitment. Its SHA-256 is:

```text
e1c6aa1a60865ff0de23a3b679864b11bb3f7af269e0b164c25393b11e304c40
```

The exporter checks every positive block against all three builders before writing
the selected corpus. Missing files, malformed data, unsupported positive blocks or
root mismatches fail the run. Expected-negative blocks are counted separately.

```sh
# The exporter takes the unpacked fixtures_stable-v5.4.0 directory and the corpus path.
cargo run --release --bin corpus -- \
  /path/to/fixtures_stable-v5.4.0 ../evm-block-execution/testdata/ordered-roots.json

# From the repository root: also checks private length calculations and the whole body.
EEST_PATH=/path/to/fixtures_stable-v5.4.0 cargo test -p aurora-evm-block-execution --release eest_body_lengths_and_roots_match_every_positive_block -- --ignored --nocapture
```

This is a codec/commitment differential, not execution of every EEST state test.
Normal gates use the pinned corpus without an external fixture installation.
The dedicated `pinned_corpus` test compares all three builders with every one of
the 29 external roots, on both hash configurations in CI. Allocation probes remain
a separate step; CI and these instructions do not depend on local Makefiles.

## RISC Zero

Install the custom `risc0` Rust toolchain and `r0vm` first. The guest pins that
toolchain and its default target, so a plain build in `guest/` cannot silently
produce a host binary. Rebuild the matching guest immediately before each run; a stale
ELF silently measures old code.

```sh
# Software backend.
(cd guest && cargo build --release)
cargo run --release --features guest-host --bin guest-host -- \
  guest/target/riscv32im-risc0-zkvm-elf/release/aurora-evm-trie-guest 0 1 16 128 200 2000

# Accelerated backend; separate target directory.
(cd guest && cargo build --release --features tiny --target-dir target/tiny)
ELF=guest/target/tiny/riscv32im-risc0-zkvm-elf/release/aurora-evm-trie-guest
cargo run --release --features guest-host,tiny --bin guest-host -- $ELF 0 1 16 128 200 2000
cargo run --release --features guest-host,tiny --bin guest-host -- $ELF --boundary 65535 65536 65537
cargo run --release --features guest-host,tiny --bin guest-host -- $ELF --prove 16
```

The software and accelerated ELF files have separate target directories. The
accelerated build patches `tiny-keccak` to RISC Zero revision
`8fcc866dc94dcec3e79c3b2bc8fbc51b22f2d5e1`, pinned in the guest manifest/lockfile.
Host and guest lockfiles are intentionally tracked.

The host wraps the user ELF with the v1-compatible kernel before execution. Each
algorithm runs in a fresh session, checks its root against alloy, and commits both
root and timed-region cycles. `--prove` constructs and verifies a receipt; do not
set `RISC0_DEV_MODE` for a proof measurement.

Region cycles exclude input decoding. Session cycles include it; summed segment
sizes include padding but are not a wall-clock proving-time model. See
[RESULTS.md](RESULTS.md) for measured results and their limits.

## Command reference

Run these commands from `evm-trie-bench/`. Local Makefiles are untracked conveniences;
the commands below cover every target without requiring one. Guest commands require
the toolchain and runtime described above. Sizes are positional arguments and can be
replaced with `--boundary 2 127 128 129 255 256 257 4096 65535 65536 65537`.

### Checks, timing and allocations

```sh
# check
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --manifest-path guest/Cargo.toml -- --check

# bench
cargo run --release --features tiny --bin bench

# allocations
cargo run --release --features tiny,allocations --bin bench
```

### Export the official corpus

This overwrites the pinned corpus only after the differential checks succeed.
Set `EEST_PATH` to the unpacked fixture directory before running it.

```sh
# corpus
test -n "${EEST_PATH:?Set EEST_PATH to the unpacked EEST fixture directory}"
cargo run --release --bin corpus -- \
  "$EEST_PATH" ../evm-block-execution/testdata/ordered-roots.json
```

### Build and execute guests

Each execution rebuilds its matching ELF first, as the local `guest-run` and
`guest-tiny-run` targets do. The build commands alone correspond to `guest` and
`guest-tiny`.

```sh
# guest-run: software backend
(cd guest && cargo build --release)
cargo run --release --features guest-host --bin guest-host -- \
  guest/target/riscv32im-risc0-zkvm-elf/release/aurora-evm-trie-guest 0 1 16 128 200 2000

# guest-tiny-run: accelerated backend
(cd guest && cargo build --release --features tiny --target-dir target/tiny)
cargo run --release --features guest-host,tiny --bin guest-host -- \
  guest/target/tiny/riscv32im-risc0-zkvm-elf/release/aurora-evm-trie-guest 0 1 16 128 200 2000
```

### Generate and verify a proof

```sh
# prove: rebuild the accelerated guest before proving
(cd guest && cargo build --release --features tiny --target-dir target/tiny)
cargo run --release --features guest-host,tiny --bin guest-host -- \
  guest/target/tiny/riscv32im-risc0-zkvm-elf/release/aurora-evm-trie-guest --prove 16
```

## Sparse witness benchmarks

Run from `evm-trie-bench/`. Dataset preparation and input copies are outside the
measurements; construction and lookup are reported separately. The frozen
`src/sparse/baseline.rs` is the pre-refactor reader, including its permissive
parser, and is used only on valid workloads for comparison. Fixture roots are
independently checked against `triehash` before measuring.

```sh
# Timing without allocator instrumentation; repeat with sparse,tiny for tiny-keccak.
cargo run --locked --release --no-default-features --features sparse --bin sparse
# Allocation assertions, including lookup hits, misses, and malformed/missing-node errors.
cargo run --locked --release --no-default-features --features sparse,allocations --bin sparse
cargo run --locked --release --no-default-features --features sparse,tiny,allocations --bin sparse
```

Workloads cover empty tries, 1/128/10,000 secure keys, absent keys, embedded nodes,
and branch values. Nine timing rounds alternate implementation order; medians
exclude fixture generation and constructor input cloning. Constructor teardown
is excluded. Allocation runs require zero lookup allocations, one retained
index allocation for a nonempty exact-size input, and one temporary key allocation
only when hashes are unsorted. Empty input allocates nothing. Ordered, reversed,
and duplicate inputs also exercise the constructor's allocation contract.
Input RLP buffers are owned by the store and are not counted as index allocations.

The `harness-differential` CI job runs sparse checks on both hash backends under
the existing benchmark path filter. Allocation/correctness failures fail CI;
wall-clock timings are printed without a threshold.

### Sparse lookups in RISC Zero

The `guest` CI job also runs a separate `sparse` binary with software and accelerated
Keccak. It covers 0/1/128/1,024-key tries, absence proofs, sorted/reversed/duplicate
nodes, repeated queries, and missing/malformed roots. Roots and values come from
the host's independently checked fixtures; the guest checks every answer and error.

```sh
(cd guest && cargo build --release --bin sparse)
cargo run --locked --release --no-default-features --features guest-host,sparse --bin sparse-guest-host -- \
  guest/target/riscv32im-risc0-zkvm-elf/release/sparse
(cd guest && cargo build --release --bin sparse --features tiny --target-dir target/tiny)
cargo run --locked --release --no-default-features --features guest-host,sparse,tiny --bin sparse-guest-host -- \
  guest/target/tiny/riscv32im-risc0-zkvm-elf/release/sparse
```

Reported guest cycles separate construction from the lookup loop. Input decoding,
answer verification, and teardown are outside those two regions; session cycles
include them. Node bytes describe the input, not peak memory. Allocation assertions
remain in the host check above. Cycle counts are diagnostics without a regression
threshold or a claim about whole-block/proving speed.
