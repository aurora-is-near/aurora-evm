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
- Target hardforks: **Cancun through Osaka**, including the configured BPO blob schedules.
- `stateless_validation` verifies sender signatures against the supplied public keys, validates
  the ancestor chain and pre-execution header/body rules, then checks execution commitments
  and the witness-backed post-state root.

### Out of scope

- A full Ethereum node, networking, the mempool, payload building or the Consensus Layer.
- Consensus Layer fork choice, finality and proof that the supplied parent belongs to the
  canonical chain. Callers supply trusted chain configuration and the parent trust anchor.
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
  the revealed accounts would omit untouched subtrees. `witness_state_root` instead patches
  the retained pre-state trie using recorded account and storage writes, reusing untouched
  hashes and storage-overlay buffers. Missing collapse siblings return an error, not a root.
  `stateless_validation` computes and checks this root after execution commitments pass.
  Read account results through `WitnessState::accounts()`.

All other roots (`receipts_root`, `withdrawals_root`, `logs_bloom`, `requests_hash`) are computed
from complete lists and are therefore always available as pure functions.

## Witness code availability

An account proof can contain a nonempty code hash without the corresponding bytecode.
`WitnessBackend::code_hash` and `has_code` answer from that proof. Hash-only paths such as
`EXTCODEHASH`, account emptiness and CREATE collisions do not require bytecode. Execution,
`EXTCODESIZE`, `EXTCODECOPY` and delegation resolution still reject missing required code.
Gas checks run before state accesses that an unaffordable opcode must not perform.

The targeted executor and stateless tests omit code, account proofs and storage proofs, with
negative controls at affordable accesses. The EEST witness corpus supplies all pre-state code;
it supplements these tests but does not establish compatibility with every minimal client witness.

## Post-execution validation

`block::validate_block_post_execution` compares execution gas, blob gas, receipts root, logs bloom
and Prague-or-later requests hash against the header, using the same `ActiveSpec` as execution.
`stateless_validation` calls it before reconstructing and comparing the witness-backed state root.
The commitment validator itself neither repeats header/body consensus checks nor computes the
post-state root. Missing proof nodes and malformed witness nodes remain distinct errors; internal
reconstruction failures cannot be mistaken for insufficient witness data.

## Differential validation

The opt-in EEST suite uses the CI-pinned `tests@v20.0.2` blockchain fixtures. It runs complete-state,
witness, node-withholding and header-mutation passes. Witness successes are checked against a
full-state trie oracle; withholding permits only the exact removed node to be missing. The mutation
pass changes gas used, receipts root, bloom, state root and active requests hash independently and
requires each specific post-execution error. Ordinary unit tests include minimal collapse proofs,
malformed witness rejection and storage wipe/recreation scenarios.

```sh
EEST_PATH=/path/to/fixtures cargo test --release -p aurora-evm-block-execution \
  eest_blockchain_tests -- --ignored --nocapture
```

## Getting started

This crate is not published on crates.io. Use a checkout of this repository
containing `evm-block-execution` and add a path dependency to your `Cargo.toml`:

```toml
[dependencies]
aurora-evm-block-execution = { path = "../aurora-evm/evm-block-execution" }
```

Adjust the path to your checkout. Keep the full repository: this crate inherits
workspace settings and depends on the sibling `evm` and `evm-trie` crates.

## License: [MIT](../LICENSE)
