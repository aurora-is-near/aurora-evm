//! Ethereum block validation and execution on top of [`aurora_evm`].
//!
//! The crate provides consensus block and transaction types, strict RLP codecs, sender recovery,
//! consensus validation, and block execution — system calls, the transaction loop, requests and
//! withdrawals — against state proven by an execution witness.

#![forbid(unsafe_code)]

pub use stateless::{StatelessValidationError, StatelessValidationOutput, stateless_validation};

pub mod block;
pub mod bloom;
pub mod chain_spec;
pub mod constants;
pub mod crypto;
pub mod eips;
pub mod errors;
pub mod evm_context;
pub mod execution_types;
pub mod executor;
pub mod precompiles;
pub mod receipt;
pub mod requests;
mod rlp_strict;
pub mod spec;
mod stateless;
pub mod system_calls;
#[cfg(test)]
mod test_utils;
pub mod transaction;
pub mod trie;
pub mod withdrawal;
pub mod witness_backend;
