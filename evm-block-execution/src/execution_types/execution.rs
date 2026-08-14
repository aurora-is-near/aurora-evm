use crate::receipt::Receipt;
use crate::requests::Requests;
use aurora_evm::backend::MemoryAccount;
use primitive_types::H160;
use std::collections::BTreeMap;

/// The result of executing a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExecutionResult {
    /// All the receipts of the transactions in the block.
    pub receipts: Vec<Receipt>,
    /// All the EIP-7685 requests in the block.
    pub requests: Requests,
    /// The total gas used by the block.
    pub gas_used: u64,
    /// Blob gas used by the block.
    pub blob_gas_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExecutionOutput {
    /// All the receipts of the transactions in the block.
    pub result: BlockExecutionResult,
    /// The changed state of the block after execution.
    pub state: BTreeMap<H160, MemoryAccount>,
}
