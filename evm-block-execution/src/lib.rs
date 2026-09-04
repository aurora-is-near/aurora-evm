//! Ethereum block validation and execution on top of [`aurora_evm`].
//!
//! The crate provides consensus block and transaction types, strict RLP codecs, sender recovery,
//! transaction validation and execution, receipts, and protocol helpers. Stateless witness
//! execution and the remaining pre- and post-execution stages are still being assembled.

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
pub mod transaction;
pub mod trie;
pub mod withdrawal;
