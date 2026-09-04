//! Stateless validation of a consensus block against an execution witness.
//!
//! The entry point takes a signed [`Block`], one public key per transaction and an
//! [`ExecutionWitness`]. Sender recovery is implemented; witness-backed execution and the remaining
//! block checks are still marked as `TODO` in the recovered path.

use crate::block::{
    AncestorChainError, Block, RecoveredBlock, SenderRecoveryError, UncompressedPublicKey,
    derive_ancestors, recover_block_with_public_keys,
};
use crate::errors::{BlockExecutionError, InvalidHeader};
use crate::execution_types::execution::BlockExecutionOutput;
use crate::execution_types::witness::ExecutionWitness;
use core::fmt;

use crate::chain_spec::ChainSpec;
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatelessValidationError {
    /// The ancestor headers in the witness do not form a chain ending at this block's parent.
    AncestorChain(AncestorChainError),
    /// The header's fields do not match the fork it is being validated against.
    InvalidHeader(InvalidHeader),
    /// A transaction's sender could not be established from the supplied public key.
    SenderRecovery(SenderRecoveryError),
    /// The block is invalid, or its execution failed.
    Execution(BlockExecutionError),
}

impl From<AncestorChainError> for StatelessValidationError {
    fn from(error: AncestorChainError) -> Self {
        Self::AncestorChain(error)
    }
}

impl From<InvalidHeader> for StatelessValidationError {
    fn from(error: InvalidHeader) -> Self {
        Self::InvalidHeader(error)
    }
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
            Self::AncestorChain(error) => write!(f, "ancestor chain is invalid: {error}"),
            Self::InvalidHeader(error) => write!(f, "header does not match its fork: {error}"),
            Self::SenderRecovery(error) => write!(f, "sender recovery failed: {error}"),
            Self::Execution(error) => write!(f, "block execution failed: {error}"),
        }
    }
}

impl core::error::Error for StatelessValidationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::AncestorChain(error) => Some(error),
            Self::InvalidHeader(error) => Some(error),
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
/// # Errors
/// Returns [`StatelessValidationError::SenderRecovery`] if the key count is wrong or a supplied key
/// does not match its transaction. The recovered path will return the other variants once its
/// validation stages are implemented.
///
/// # Panics
/// Currently panics after successful sender recovery because witness-backed execution is not yet
/// implemented.
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
// Ownership matches the completed path, which will consume these execution inputs.
#[allow(clippy::needless_pass_by_value)]
fn stateless_validation_recovered(
    current_block: RecoveredBlock,
    witness: ExecutionWitness,
    _chain_spec: ChainSpec,
) -> Result<StatelessValidationOutput, StatelessValidationError> {
    // Bind the witness to the state root of the verified parent before state is accessed.
    let ancestors = derive_ancestors(current_block.header(), &witness.headers)?;

    // TODO: enable once parent-relative consensus validation is implemented.
    // validate_block_consensus(&chain_spec, &current_block, ancestors.parent())?;

    let pre_state_root = ancestors.pre_state_root();
    let (_parent_header, ancestor_hashes) = ancestors.split();

    todo!(
        "execution against pre-state root {pre_state_root:?} with {} verified ancestor hashes; see the module docs",
        ancestor_hashes.len()
    )
}

#[cfg(test)]
mod tests {
    use super::{StatelessValidationError, stateless_validation};
    use crate::block::{AncestorChainError, Block};
    use crate::chain_spec::ChainSpec;
    use crate::eips::eip1559::BaseFeeParams;
    use crate::eips::eip7892::BlobScheduleBlobParams;
    use crate::execution_types::witness::ExecutionWitness;
    use crate::spec::Spec;
    use std::collections::BTreeMap;

    fn chain_spec() -> ChainSpec {
        ChainSpec {
            chain_id: 1,
            spec: Spec::Cancun,
            hard_forks_timestamps: BTreeMap::new(),
            deposit_contract_address: None,
            base_fee_params: BaseFeeParams::ethereum(),
            blob_schedule: BlobScheduleBlobParams::mainnet(),
        }
    }

    #[test]
    fn missing_ancestor_is_returned_before_unimplemented_execution() {
        let error = stateless_validation(
            Block::default(),
            &[],
            ExecutionWitness::default(),
            chain_spec(),
        )
        .unwrap_err();

        assert_eq!(
            error,
            StatelessValidationError::AncestorChain(AncestorChainError::MissingParent)
        );
    }
}
