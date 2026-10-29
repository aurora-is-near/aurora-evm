# Ordered trie results — 2026-09-11

## Verification

- Final default workspace tests and both trie hash backends pass.
- Full EEST v5.4.0 length/body differential: **61,371 positive blocks**, **60,405
  transactions**, all five supported transaction types; **3,501 expected-negative
  blocks** skipped explicitly. Computed transaction lengths, block RLP lengths and
  transaction/withdrawal roots match. No positive block failed decoding.
- The standalone exporter verified **106,058 roots**. Its 29 selected vectors
  reproduce the pinned JSON byte-for-byte.
- Native differential tests cover every count 0..260, 511..513, 4095..4097,
  65535..65537 and 100,000; exact calculated scratch capacity is tested separately
  from the rounded stack tiers. Value tests cover empty/single-byte values, full
  node lengths 31/32/33, RLP and Keccak boundaries, and every native key width.
- The encoder test checks lexicographic visits, exactly one visit per index, and
  buffer shrink/reuse. Empty streaming input does not invoke the encoder.

These tests provide strong differential evidence, not a formal proof of every
possible input. The external review's 1,500 randomized runs and 2^24 probes were
not independently rerun here and are not included in the counts above.

## Final native measurements

Apple Silicon, macOS 15.7.8, Rust 1.97.0. Timing runs were separate from allocation
runs and from other builds/proving. Standalone release uses opt-level 3, fat LTO,
one codegen unit. Input preparation is outside the measurements.

All builders use `tiny-keccak` in this table (median, microseconds):

| Items | triehash | alloy | production candidate |
|---:|---:|---:|---:|
| 1 | 1.095 | 0.974 | 0.663 |
| 16 | 16.527 | 12.208 | 11.320 |
| 128 | 131.672 | 93.580 | 89.299 |
| 200 | 205.615 | 145.835 | 139.986 |
| 2,000 | 2,107.829 | 1,458.266 | 1,399.190 |

At 2,000 items the candidate takes 4.1% less time than alloy on the same hash
backend. Native backend comparisons must not be presented as algorithm-only
comparisons: alloy can use a different SHA3 implementation/CPU acceleration.

Allocator requests for already encoded input:

| Items | triehash calls / bytes | alloy calls / bytes | candidate calls / bytes |
|---:|---:|---:|---:|
| 0 | 3 / 1,544 | 0 / 0 | 0 / 0 |
| 1 | 9 / 3,610 | 9 / 1,347 | 0 / 0 |
| 200 | 857 / 671,336 | 13 / 5,299 | 0 / 0 |
| 2,000 | 8,463 / 6,675,208 | 17 / 7,523 | 0 / 0 |

The streaming-encoder allocation gate separately measured 0/0 for empty input and
**2 calls / 1,536 bytes** for 1, 16, 200 and 2,000 scalar items. This pins scratch
reuse, not constant allocation for arbitrarily large/nested encodings: buffer and
list-stack growth still depend on the largest item. Stack usage and paging are
not included in this host allocation counter.

Full `calculate_body_metrics`, normal production SHA3 backend, repository release
profile; every row includes **16 withdrawals** (median, microseconds):

| Transactions | previous materializing flow | streaming flow | speedup |
|---:|---:|---:|---:|
| 0 | 8.355 | 3.267 | 2.56x |
| 1 | 11.167 | 5.062 | 2.21x |
| 200 | 621.071 | 348.824 | 1.78x |
| 2,000 | 6,147.238 | 3,425.295 | 1.79x |

The baseline encoded each transaction once and then copied it into an owned leaf;
it did **not** encode each transaction twice. The new flow computes lengths without
encoding, then encodes each value once at its leaf and removes the retained leaf
collection. It still writes encoding scratch and copies small inline nodes.

## RISC Zero measurements

The tables below retain the original measurements. An independent review supplied
on 2026-09-11 reports freshly rebuilt guests after crate extraction: all three roots
matched for both backends at the standard sizes through 2,000 and at boundary sizes
2, 127..129, 255..257, 4,096 and 65,535..65,537, including the heap tier.
It reports identical accelerated root-region cycle counts and approximately
147.0 million software candidate cycles at 2,000 items (previously 146.9 million).
Thus the post-extraction runtime check is covered by that review, not by a new
author-run measurement. Exact software logs were not supplied, so no more precise
replacement number is inferred. Proof measurements remain from before extraction.

Toolchain: custom Rust 1.91.1-dev; guest SDK 3.0.6, r0vm 3.0.4, v1-compatible kernel
2.2.3. Root-only timed regions use predecoded input. Accelerated runs used the same
pinned RISC Zero `tiny-keccak` backend for every algorithm:

| Items | triehash cycles | alloy cycles | candidate cycles | arena prototype cycles |
|---:|---:|---:|---:|---:|
| 1 | 17,260 | 12,862 | 9,318 | 9,654 |
| 16 | 292,186 | 195,880 | 158,042 | 160,879 |
| 128 | 2,320,980 | 1,537,051 | 1,246,667 | 1,270,615 |
| 200 | 3,637,826 | 2,414,227 | 1,954,650 | 2,006,806 |
| 2,000 | 36,610,031 | 24,184,939 | 19,508,750 | 20,356,132 |

At 2,000 items: 46.7% fewer region cycles than triehash, 19.3% fewer than alloy and
4.2% fewer than the arena prototype. The prototype was removed from the maintained
harness after comparison; these historical columns are not a fourth current API.

For the same 2,000-item accelerated sessions:

| | triehash | alloy | candidate |
|---|---:|---:|---:|
| User cycles, including input decoding | 152,956,297 | 140,531,205 | 135,855,016 |
| Sum of padded segment sizes | 165,675,008 | 147,324,928 | 142,606,336 |
| Segments | 158 | 141 | 136 |

The smaller session-level gain illustrates why root-region savings cannot be
extrapolated directly to a whole zkEVM. No page counter or peak stack measurement
was taken; padded cycles and segment counts are reported as such.

In the original software SHA3 run, the candidate used 146,918,812 region cycles versus
triehash's 163,258,257 at 2,000 items (10.0% less). Switching the candidate's backend
reduced that region to 19,508,750 cycles, about 7.5x, but this is **not** a measured
7.5x full-guest or full-zkEVM speedup. Normal block execution still defaults to SHA3.

### Actual proofs

Before crate extraction, all three 16-item accelerated proofs were constructed without dev mode and their
receipts verified. One run per algorithm:

| | User cycles | Total cycles | Proof time, ms |
|---|---:|---:|---:|
| triehash | 1,234,936 | 1,572,864 | 96,227 |
| alloy | 1,138,632 | 1,310,720 | 82,459 |
| candidate | 1,100,792 | 1,310,720 | 90,647 |

Candidate and alloy have the same padded proof size here. Single noisy wall-clock
runs do not establish that candidate proofs are faster than alloy proofs.

## Scope and remaining limits

State/storage roots, witness execution and precompiles were not changed. No claim
is made that all EEST state-transition tests now exercise block execution. The
maintained benchmark must rebuild both the host and matching guest before any new
runtime/proof result is recorded, rather than reusing a cached ELF.
