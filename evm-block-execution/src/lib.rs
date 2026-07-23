//! # Aurora EVM block execution
//!
//! Self-contained block-execution layer on top of the high-performance Aurora EVM core.
//! It wraps single-transaction execution (`aurora_evm::StackExecutor`) into a full block
//! execution pipeline (pre-execution system calls, transaction loop with receipts and gas
//! accounting, post-execution withdrawals/requests, block roots and header checks).

#![forbid(unsafe_code)]

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
