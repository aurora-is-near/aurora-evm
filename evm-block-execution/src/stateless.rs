//! Stateless validation of a consensus block against an execution witness.
//!
//! The entry point takes a signed [`Block`], one public key per transaction and an
//! [`ExecutionWitness`]. Senders are recovered, the ancestor chain is verified, the block passes
//! pre-execution consensus checks and is then executed against the state the witness proves.

use crate::block::{
    AncestorChainError, Block, BlockEnv, BlockRecoveryError, BlockValidationError, ExecutionParts,
    RecoveredBlock, SenderRecoveryError, UncompressedPublicKey, derive_ancestors,
    recover_block_with_public_keys, validate_block_consensus,
};
use crate::chain_spec::ChainSpec;
use crate::errors::BlockExecutionError;
use crate::execution_types::execution::BlockExecutionOutput;
use crate::execution_types::witness::ExecutionWitness;
use crate::executor::BlockExecutor;
use crate::witness_backend::{WitnessBackend, WitnessStateError};
use core::fmt;
use primitive_types::H256;

#[cfg(test)]
mod tests;

/// Output of a successfully validated block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatelessValidationOutput {
    /// Hash of the validated block.
    pub block_hash: H256,
    /// Receipts, gas totals and post-state produced while executing the block.
    pub execution_output: BlockExecutionOutput,
}

/// Errors of the stateless validation of a block.
///
/// Display reports the failed stage; details are available through [`core::error::Error::source`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatelessValidationError {
    /// The ancestor headers in the witness do not form a chain ending at this block's parent.
    AncestorChain(AncestorChainError),
    /// The block fails pre-execution consensus validation.
    Consensus(BlockValidationError),
    /// A transaction's sender could not be established from the supplied public key.
    SenderRecovery(SenderRecoveryError),
    /// The recovered block pairs its transactions and senders inconsistently.
    Recovery(BlockRecoveryError),
    /// The witness cannot be bound to the parent's state root.
    Witness(WitnessStateError),
    /// The block is invalid, or its execution failed.
    Execution(BlockExecutionError),
}

impl From<AncestorChainError> for StatelessValidationError {
    fn from(error: AncestorChainError) -> Self {
        Self::AncestorChain(error)
    }
}

impl From<BlockValidationError> for StatelessValidationError {
    fn from(error: BlockValidationError) -> Self {
        Self::Consensus(error)
    }
}

impl From<SenderRecoveryError> for StatelessValidationError {
    fn from(error: SenderRecoveryError) -> Self {
        Self::SenderRecovery(error)
    }
}

impl From<BlockRecoveryError> for StatelessValidationError {
    fn from(error: BlockRecoveryError) -> Self {
        Self::Recovery(error)
    }
}

impl From<WitnessStateError> for StatelessValidationError {
    fn from(error: WitnessStateError) -> Self {
        Self::Witness(error)
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
            Self::AncestorChain(_) => f.write_str("ancestor chain is invalid"),
            Self::Consensus(_) => f.write_str("block consensus validation failed"),
            Self::SenderRecovery(_) => f.write_str("sender recovery failed"),
            Self::Recovery(_) => f.write_str("block recovery is inconsistent"),
            Self::Witness(_) => f.write_str("witness cannot be used"),
            Self::Execution(_) => f.write_str("block execution failed"),
        }
    }
}

impl core::error::Error for StatelessValidationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::AncestorChain(error) => Some(error),
            Self::Consensus(error) => Some(error),
            Self::SenderRecovery(error) => Some(error),
            Self::Recovery(error) => Some(error),
            Self::Witness(error) => Some(error),
            Self::Execution(error) => Some(error),
        }
    }
}

/// Validates `block` statelessly: verifies every sender against `public_keys`, then executes the
/// block against the state revealed by `witness`.
///
/// The public keys must be in transaction order, one per transaction.
///
/// # Errors
/// Returns [`StatelessValidationError`] for sender recovery, ancestor, pre-execution consensus,
/// witness or execution failures, including any state read the witness did not prove.
pub fn stateless_validation(
    block: Block,
    public_keys: &[UncompressedPublicKey],
    witness: ExecutionWitness,
    chain_spec: ChainSpec,
) -> Result<StatelessValidationOutput, StatelessValidationError> {
    let recovered_block = recover_block_with_public_keys(block, public_keys)?;
    stateless_validation_recovered(recovered_block, witness, chain_spec)
}

/// Validates a block whose senders are already established.
pub fn stateless_validation_recovered(
    current_block: RecoveredBlock,
    witness: ExecutionWitness,
    chain_spec: ChainSpec,
) -> Result<StatelessValidationOutput, StatelessValidationError> {
    // Bind the witness to the state root of the verified parent before state is accessed.
    let ancestors = derive_ancestors(current_block.header(), &witness.headers)?;

    let active_spec = validate_block_consensus(&chain_spec, &current_block, ancestors.parent())?;

    let pre_state_root = ancestors.pre_state_root();
    let (_parent_header, ancestor_hashes) = ancestors.split();

    let block_hash = current_block.hash();
    let ExecutionParts {
        header,
        withdrawals,
        transactions,
    } = current_block.into_execution_parts()?;

    let block_env = BlockEnv::from_block(header.header(), withdrawals, active_spec)?;
    let backend = WitnessBackend::from_witness(
        block_env.vicinity(chain_spec.chain_id),
        witness,
        pre_state_root,
        ancestor_hashes,
    )?;

    let execution_output =
        BlockExecutor::with_active_spec(chain_spec, block_env, transactions, backend, active_spec)
            .execute()?;

    Ok(StatelessValidationOutput {
        block_hash,
        execution_output,
    })
}
