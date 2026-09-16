//! Results produced by block execution.

use crate::receipt::Receipt;
use crate::requests::Requests;
use aurora_evm::backend::MemoryAccount;
use primitive_types::H160;
use std::collections::BTreeMap;

/// Consensus outputs produced by executing a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExecutionResult {
    /// Transaction receipts in block order.
    pub receipts: Vec<Receipt>,
    /// EIP-7685 requests produced by execution.
    pub requests: Requests,
    /// Total execution gas used.
    pub gas_used: u64,
    /// Total blob gas used.
    pub blob_gas_used: u64,
}

/// Block execution result together with the resulting materialized state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExecutionOutput {
    /// Consensus execution outputs.
    pub result: BlockExecutionResult,
    /// Post-execution world state.
    pub state: BTreeMap<H160, MemoryAccount>,
}
