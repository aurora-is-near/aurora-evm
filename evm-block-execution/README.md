<div align="center">
  <h1>Aurora EVM Block Execution</h1>
</div>

A self-contained **block execution** layer built on top of the high-performance
[Aurora EVM](../evm) core. The Aurora EVM core executes a *single transaction*; this crate adds
the pieces needed to execute a *whole block* and validate it against its header.

### What block execution adds on top of single-transaction execution

1. **Pre-execution system calls** — write the parent block hash and beacon root into their system
   contracts (EIP-2935, EIP-4788).
2. **Transaction loop** — run every transaction in order, accumulating `cumulative_gas_used`,
   building a typed receipt per transaction, and applying the correct gas economics (upfront
   charge, unused-gas refund, coinbase tip, base-fee/blob-fee burn).
3. **Post-execution** — credit validator withdrawals (EIP-4895) and gather protocol requests
   (EIP-6110 deposits, EIP-7002 withdrawals, EIP-7251 consolidations).
4. **Roots and checksums** — compute `state_root`, `receipts_root`, `logs_bloom`, `requests_hash`,
   `gas_used` and `blob_gas_used`.
5. **Header validation** — compare the computed values against the block header.

## Scope

### In scope

- The full block-execution pipeline (pre-execution → transaction loop → post-execution).
- Per-transaction gas economics, typed receipts and gas accounting.
- System calls (EIP-4788, EIP-2935, EIP-7002, EIP-7251), deposit parsing (EIP-6110) and
  withdrawals (EIP-4895).
- Block roots (`state_root`, `receipts_root`, `withdrawals_root`, `requests_hash`, `logs_bloom`)
  and post-execution header checks.
- Target hardforks: **post-merge** Ethereum mainline only.

### Out of scope

- A full Ethereum node, networking, the mempool, payload building or the Consensus Layer.
- Header-only / consensus checks that do not follow from execution (base-fee formula, gas-limit
  bounds, timestamp ordering, difficulty/PoS, parent-relative checks) — callers must validate
  these independently; they are not implied by a matching `state_root`.
- Block reorg machinery (`BundleState` / `TransitionState` / reverts).
- Pre-merge block/uncle rewards, ommers and the DAO fork.

## Design principles

- **Concrete types, not generics/traits.** A single Ethereum-mainline path, no executor factories
  or hooks. This is the deliberate simplification of the layered design.
- **`primitive-types` (`H160`/`H256`/`U256`) and `rlp`** for values and codecs.
- **Deterministic `BTreeMap` state** that is mutated in place and moved without cloning.
- **Integer-only, checked/saturating math** (no floating point) for fully deterministic
  execution — the invariant a zkEVM depends on.
- **No `unsafe`** (`#![forbid(unsafe_code)]`) and strict Clippy (`pedantic` + `nursery`).

## `state_root`: two paths

The trie root of the world state depends on **all** accounts, not just the ones a block touches,
so it is handled in two modes:

- **Full state.** When the entire account map is available (e.g. tests or autonomous validation),
  `state_root` is computed as a pure `sec_trie_root` over the whole map — simple and fast, with no
  persistent trie.
- **Witness / stateless.** When only a witness is available, a plain `sec_trie_root` over
  the sparse state would be wrong (missing sibling nodes). In that case this crate emits the
  post-state diff and the root is computed by an external witness-backed sparse trie.

All other roots (`receipts_root`, `withdrawals_root`, `logs_bloom`, `requests_hash`) are computed
from complete lists and are therefore always available as pure functions.

## Getting started

To get started, add the following dependency to your `Cargo.toml`:

```toml 
[dependencies]
aurora-evm-block-execution = "3.0"
```

## License: [MIT](../LICENSE)
