# aurora-evm-block-execution

A self-contained **block execution** layer built on top of the high-performance
[Aurora EVM](../evm) core. The Aurora EVM core executes a *single transaction*; this crate adds
everything needed to execute a *whole block* and validate it against its header, so the engine can
be used as a drop-in replacement for the `reth + revm + alloy-evm` execution stack inside a
stateless block validator.

## What block execution adds on top of single-transaction execution

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

**In scope**

- The full block-execution pipeline (pre-execution → transaction loop → post-execution).
- Per-transaction gas economics, typed receipts and gas accounting.
- System calls (EIP-4788, EIP-2935, EIP-7002, EIP-7251), deposit parsing (EIP-6110) and
  withdrawals (EIP-4895).
- Block roots (`state_root`, `receipts_root`, `withdrawals_root`, `requests_hash`, `logs_bloom`)
  and post-execution header checks.
- Target hardforks: **post-merge … Osaka**, Ethereum mainline only.

**Out of scope**

- A full Ethereum node, networking, the mempool, payload building or the Consensus Layer.
- Header-only / consensus checks that do not follow from execution (base-fee formula, gas-limit
  bounds, timestamp ordering, difficulty/PoS, parent-relative checks) — their effect is anyway
  pinned by the `state_root` comparison.
- Block reorg machinery (revm's `BundleState` / `TransitionState` / reverts).
- Pre-merge block/uncle rewards, ommers and the DAO fork.

## Design principles

- **Concrete types, not generics/traits.** A single Ethereum-mainline path, no executor factories
  or hooks. This is the deliberate simplification of the layered `reth + revm` design.
- **`primitive-types` (`H160`/`H256`/`U256`) and `rlp`** for values and codecs. No `alloy`/`revm`
  types in the core.
- **Deterministic `BTreeMap` state** that is mutated in place and moved without cloning.
- **Integer-only math** (no floating point), suitable for deterministic and wasm targets.
- **No `unsafe`** (`#![forbid(unsafe_code)]`) and strict Clippy (`pedantic` + `nursery`).

## `state_root`: two paths

The trie root of the world state depends on **all** accounts, not just the ones a block touches,
so it is handled in two modes:

- **Full state (`standalone` feature).** When the entire account map is available (e.g. tests or
  autonomous validation), `state_root` is computed as a pure `sec_trie_root` over the whole map —
  simple and fast, with no persistent trie.
- **Witness / stateless (default).** When only a witness is available, a plain `sec_trie_root` over
  the sparse state would be wrong (missing sibling nodes). In that case this crate emits the
  post-state diff and the root is computed by an external witness-backed sparse trie.

All other roots (`receipts_root`, `withdrawals_root`, `logs_bloom`, `requests_hash`) are computed
from complete lists and are therefore always available as pure functions.

## Cargo features

- `std` *(default)* — standard library and `std`-enabled dependencies.
- `precompiles` *(default)* — the concrete precompile set (Istanbul…Osaka) backed by
  `aurora-engine-precompiles` plus the EIP-4844 KZG point-evaluation precompile (`c-kzg`).
- `standalone` — enables the full-state `state_root` path described above.

## Status

This crate is under active development. The cryptographic and codec **foundation** is in place:
Keccak-256 / SHA-256 helpers, RLP codecs (`TrieAccount`, `Receipt`, `Withdrawal`), trie roots
(`ordered_trie_root` / `sec_trie_root` / `state_root`), the logs bloom filter, and the per-hardfork
precompile set. The block-level orchestration is being built on top of this foundation.
