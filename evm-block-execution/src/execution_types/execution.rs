//! Results produced by block execution.

use crate::receipt::Receipt;
use crate::requests::Requests;
use crate::witness_backend::WitnessState;

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

/// Block execution result together with the state execution left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExecutionOutput {
    /// Consensus execution outputs.
    pub result: BlockExecutionResult,
    /// Every account execution touched or revealed, with the code those accounts refer to.
    pub state: WitnessState,
}
