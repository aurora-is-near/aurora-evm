//! # Aurora EVM block execution
//!
//! Self-contained block-execution layer on top of the high-performance Aurora EVM core.
//! It wraps single-transaction execution (`aurora_evm::StackExecutor`) into a full block
//! execution pipeline (pre-execution system calls, transaction loop with receipts and gas
//! accounting, post-execution withdrawals/requests, block roots and header checks).
//!
//! Design principles (see `README.md`): concrete types instead of generics/traits,
//! `primitive-types` (`H160`/`H256`/`U256`) and `rlp` for codecs, deterministic `BTreeMap`
//! state, no `alloy`/`revm` dependency in the core. Hardfork scope: Merge … Osaka, mainline.
//!
//! This module set currently implements the foundation (plan phases 0–2): hashing, RLP codecs,
//! trie roots, logs bloom, the concrete precompile set, and the block input environment
//! (`BlockEnv`) and expected-header (`ExpectedHeader`) types.

#![deny(warnings)]
#![deny(clippy::pedantic, clippy::nursery)]
#![deny(clippy::as_conversions)]
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

pub mod blob;
pub mod block;
pub mod bloom;
pub mod constants;
pub mod crypto;
pub mod errors;
pub mod evm;
pub mod evm_context;
pub mod precompiles;
pub mod receipt;
pub mod requests;
pub mod result;
pub mod spec;
pub mod transaction;
pub mod trie;
pub mod withdrawal;
