//! Stateless validation of a single block.
//!
//! The caller hands over three things, and nothing else:
//!
//! 1. the [`Block`] to validate, in consensus form (signed transactions, no senders);
//! 2. one public key per transaction, so each sender can be *verified* rather than recovered
//!    (see [`recover_block_with_public_keys`]);
//! 3. an [`ExecutionWitness`] holding the trie nodes, contract codes and ancestor headers the
//!    block's execution touches.

use crate::block::{
    Block, RecoveredBlock, SenderRecoveryError, UncompressedPublicKey,
    recover_block_with_public_keys,
};
use crate::errors::BlockExecutionError;
use crate::execution_types::execution::BlockExecutionOutput;
use crate::execution_types::witness::ExecutionWitness;
use core::fmt;

use primitive_types::H256;

/// Output of a successfully validated block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatelessValidationOutput {
    /// Hash of the validated block.
    pub block_hash: H256,
    /// Receipts, gas totals and post-state produced while executing the block.
    pub execution_output: BlockExecutionOutput,
}

/// Errors of the stateless validation of a block.
#[derive(Debug)]
pub enum StatelessValidationError {
    /// A transaction's sender could not be established from the supplied public key.
    SenderRecovery(SenderRecoveryError),
    /// The block is invalid, or its execution failed.
    Execution(BlockExecutionError),
}

impl From<SenderRecoveryError> for StatelessValidationError {
    fn from(error: SenderRecoveryError) -> Self {
        Self::SenderRecovery(error)
    }
}

impl From<BlockExecutionError> for StatelessValidationError {
    fn from(error: BlockExecutionError) -> Self {
        Self::Execution(error)
    }
}

impl fmt::Display for StatelessValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SenderRecovery(error) => write!(f, "sender recovery failed: {error}"),
            Self::Execution(error) => write!(f, "block execution failed: {error}"),
        }
    }
}

impl core::error::Error for StatelessValidationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::SenderRecovery(error) => Some(error),
            Self::Execution(error) => Some(error),
        }
    }
}

/// Validates `block` statelessly: verifies every sender against `public_keys`, then executes the
/// block against the state revealed by `witness`.
///
/// The public keys must be in transaction order, one per transaction.
///
/// ## Errors
/// [`StatelessValidationError::SenderRecovery`] if any transaction's signature does not verify
/// against its public key, or if the key count does not match the transaction count.
pub fn stateless_validation(
    block: Block,
    public_keys: &[UncompressedPublicKey],
    witness: ExecutionWitness,
) -> Result<StatelessValidationOutput, StatelessValidationError> {
    let recovered_block = recover_block_with_public_keys(block, public_keys)?;
    stateless_validation_recovered(recovered_block, witness)
}

/// Validates a block whose senders are already established.
fn stateless_validation_recovered(
    _block: RecoveredBlock,
    _witness: ExecutionWitness,
) -> Result<StatelessValidationOutput, StatelessValidationError> {
    todo!("execution against the witness-revealed state; see the module docs")
}
