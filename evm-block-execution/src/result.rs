//! The output boundary of block execution.
//!
//! Executing a block yields two kinds of artifacts, aggregated in [`BlockExecutionResult`]:
//!
//! - **computed commitments** — the `gas_used` / `blob_gas_used` totals, the block logs bloom,
//!   `receipts_root`, `withdrawals_root` (Shanghai+) and `requests_hash` (Prague+) — each of
//!   which a valid block must reproduce in its header;
//! - **raw outputs** — per-transaction [`Receipt`]s in block order, the collected EIP-7685
//!   [`Requests`], and the final post-execution state map.
//!
//! The one root deliberately missing is `state_root`: it depends on *all* accounts, not only the
//! touched ones, so the caller either computes it over the returned full state map
//! ([`state_root`](crate::trie::state_root)) or, in the stateless/witness mode, feeds the state
//! diff to an external sparse trie.
//!
//! # Place in the execution pipeline
//!
//! Assembled last, after the transaction loop and the post-execution steps. Header validation
//! then compares these fields against [`ExpectedHeader`](crate::block::ExpectedHeader); any
//! divergence surfaces as a mismatch variant of
//! [`BlockExecutionError`](crate::errors::BlockExecutionError).

use crate::bloom::Bloom;
use crate::constants::EMPTY_ROOT_HASH;
use crate::receipt::Receipt;
use crate::requests::Requests;
use aurora_evm::backend::MemoryAccount;
use primitive_types::{H160, H256};
use std::collections::BTreeMap;

/// Neutral result of block execution.
///
/// Carries the per-transaction receipts, the collected EIP-7685 requests, gas / blob-gas totals,
/// the block logs bloom, and the roots the engine computes itself (`receipts_root`,
/// `withdrawals_root`, `requests_hash`). The final post-execution state map is returned so the
/// caller can compute `state_root` (full-state path) or feed it to an external witness trie;
/// `state_root` is therefore deliberately **not** a field here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockExecutionResult {
    /// Per-transaction receipts, in block order.
    pub receipts: Vec<Receipt>,
    /// EIP-7685 requests collected during post-execution.
    pub requests: Requests,
    /// Total gas used by the block.
    pub gas_used: u64,
    /// Total blob gas used (EIP-4844).
    pub blob_gas_used: u64,
    /// Block logs bloom (OR of all receipt blooms).
    pub logs_bloom: Bloom,
    /// Receipts trie root.
    pub receipts_root: H256,
    /// Withdrawals trie root (`Some` from Shanghai onward).
    pub withdrawals_root: Option<H256>,
    /// EIP-7685 requests hash (`Some` from Prague onward).
    pub requests_hash: Option<H256>,
    /// Final post-execution world state.
    pub state: BTreeMap<H160, MemoryAccount>,
}

impl Default for BlockExecutionResult {
    fn default() -> Self {
        Self {
            receipts: Vec::new(),
            requests: Requests::default(),
            gas_used: 0,
            blob_gas_used: 0,
            logs_bloom: Bloom::zero(),
            // An empty receipts trie hashes to the canonical empty-trie root, not zero, so an
            // empty-block result carries a valid `receiptsRoot` header commitment by default.
            receipts_root: EMPTY_ROOT_HASH,
            withdrawals_root: None,
            requests_hash: None,
            state: BTreeMap::new(),
        }
    }
}
