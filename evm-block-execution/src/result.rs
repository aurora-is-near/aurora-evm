//! Aggregated outcome of executing a block.

use crate::bloom::Bloom;
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
/// caller can compute `state_root` (full-state path) or feed it to an external witness trie (see
/// `PLAN.md`, part C). `state_root` is therefore deliberately **not** a field here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::BlockExecutionResult;
    use crate::bloom::Bloom;
    use crate::constants::EMPTY_ROOT_HASH;
    use crate::receipt::Receipt;
    use crate::transaction::TxType;

    #[test]
    fn default_is_empty() {
        let result = BlockExecutionResult::default();
        assert!(result.receipts.is_empty());
        assert!(result.requests.is_empty());
        assert_eq!(result.gas_used, 0);
        assert_eq!(result.blob_gas_used, 0);
        assert_eq!(result.logs_bloom, Bloom::zero());
        assert!(result.withdrawals_root.is_none());
        assert!(result.requests_hash.is_none());
        assert!(result.state.is_empty());
    }

    #[test]
    fn fields_are_populated_and_comparable() {
        let result = BlockExecutionResult {
            receipts: vec![Receipt::new(TxType::Legacy, true, 21_000, vec![])],
            gas_used: 21_000,
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            ..Default::default()
        };
        assert_eq!(result.receipts.len(), 1);
        assert_eq!(result.gas_used, 21_000);
        assert_eq!(result.withdrawals_root, Some(EMPTY_ROOT_HASH));

        // A differing field is detected by `Eq` (built fresh, no clone).
        let other = BlockExecutionResult {
            gas_used: 42_000,
            ..Default::default()
        };
        assert_ne!(result, other);
    }
}
