//! Stateless validation of a consensus block against an execution witness.
//!
//! The entry point takes a signed [`Block`], one public key per transaction and an
//! [`ExecutionWitness`]. Sender recovery, ancestor verification and pre-execution consensus checks
//! are implemented; witness-backed execution remains `TODO` in the recovered path.

use crate::block::{
    AncestorChainError, Block, BlockValidationError, RecoveredBlock, SenderRecoveryError,
    UncompressedPublicKey, derive_ancestors, recover_block_with_public_keys,
    validate_block_consensus,
};
use crate::errors::BlockExecutionError;
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
    /// The block fails pre-execution consensus validation.
    Consensus(BlockValidationError),
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

impl From<BlockExecutionError> for StatelessValidationError {
    fn from(error: BlockExecutionError) -> Self {
        Self::Execution(error)
    }
}

impl fmt::Display for StatelessValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AncestorChain(error) => write!(f, "ancestor chain is invalid: {error}"),
            Self::Consensus(error) => write!(f, "block consensus validation failed: {error}"),
            Self::SenderRecovery(error) => write!(f, "sender recovery failed: {error}"),
            Self::Execution(error) => write!(f, "block execution failed: {error}"),
        }
    }
}

impl core::error::Error for StatelessValidationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::AncestorChain(error) => Some(error),
            Self::Consensus(error) => Some(error),
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
/// Returns [`StatelessValidationError`] for sender recovery, ancestor or pre-execution consensus
/// failures. Witness-backed execution is not yet implemented.
///
/// # Panics
/// Currently panics after successful pre-execution validation because witness-backed execution is
/// not yet implemented.
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
    chain_spec: ChainSpec,
) -> Result<StatelessValidationOutput, StatelessValidationError> {
    // Bind the witness to the state root of the verified parent before state is accessed.
    let ancestors = derive_ancestors(current_block.header(), &witness.headers)?;

    validate_block_consensus(&chain_spec, &current_block, ancestors.parent())?;

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
    use crate::block::{AncestorChainError, Block, BlockBody, BlockValidationError, Header};
    use crate::chain_spec::ChainSpec;
    use crate::eips::eip1559::BaseFeeParams;
    use crate::eips::eip7892::BlobScheduleBlobParams;
    use crate::execution_types::witness::ExecutionWitness;
    use crate::spec::Spec;
    use primitive_types::{H256, U256};
    use std::collections::BTreeMap;

    fn chain_spec() -> ChainSpec {
        ChainSpec {
            chain_id: 1,
            spec: Spec::Cancun,
            hard_forks_timestamps: BTreeMap::from([(Spec::Cancun, 0)]),
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

    #[test]
    fn consensus_validation_runs_before_unimplemented_execution() {
        let mut parent = Header {
            number: 1,
            timestamp: 1,
            ..Header::default()
        };
        parent.base_fee_per_gas = Some(1);
        parent.withdrawals_root = Some(crate::constants::EMPTY_ROOT_HASH);
        parent.blob_gas_used = Some(0);
        parent.excess_blob_gas = Some(0);
        parent.parent_beacon_block_root = Some(H256::default());

        let block = Block::new(
            Header {
                parent_hash: parent.hash_slow(),
                number: 2,
                timestamp: 2,
                difficulty: U256::one(),
                ..Header::default()
            },
            BlockBody::default(),
        );
        let witness = ExecutionWitness {
            headers: vec![rlp::encode(&parent).to_vec()],
            ..ExecutionWitness::default()
        };

        assert!(matches!(
            stateless_validation(block, &[], witness, chain_spec()),
            Err(StatelessValidationError::Consensus(
                BlockValidationError::DifficultyNotZero { .. }
            ))
        ));
    }
}
