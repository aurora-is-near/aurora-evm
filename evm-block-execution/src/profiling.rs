//! Optional phase boundaries for guest cycle/heap attribution, separate from production validation.
//!
//! As in zeth, benchmark the ordinary entry point for totals. Use this composition only for phase
//! attribution; differential tests keep its results and errors aligned with that entry point.
//! No clock, allocator, or zkVM dependency belongs here.
//!
//! | Phase | zeth/stateless counterpart |
//! |---|---|
//! | Recovery | `recover_block_with_public_keys` |
//! | Consensus | ancestors and `validate_block_consensus` |
//! | Witness | `T::new` and `WitnessDatabase::new` |
//! | Execution | `executor.execute` |
//! | Commitments | `validate_block_post_execution` |
//! | State root | `calculate_state_root` and comparison |

use crate::block::{
    Block, BlockEnv, ExecutionParts, UncompressedPublicKey, derive_ancestors,
    recover_block_with_public_keys, validate_block_consensus, validate_block_post_execution,
};
use crate::chain_spec::ChainSpec;
use crate::errors::BlockExecutionError;
use crate::execution_types::witness::ExecutionWitness;
use crate::executor::BlockExecutor;
use crate::stateless::{StatelessValidationError, StatelessValidationOutput};
use crate::trie::witness_state_root;
use crate::witness_backend::WitnessBackend;

/// Start of a validation phase, or successful completion of the whole pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationStage {
    /// Recover senders and verify supplied keys.
    Recovery,
    /// Verify ancestors/consensus and prepare execution inputs.
    Consensus,
    /// Index the witness and bind it to the pre-state root.
    Witness,
    /// Execute system calls, transactions, requests, and withdrawals.
    Execution,
    /// Validate execution commitments other than the state root.
    Commitments,
    /// Reconstruct and verify the sparse post-state root.
    StateRoot,
    /// All checks succeeded; output construction and teardown follow.
    Finished,
}

/// Composes the production validators with a hook between phases.
///
/// Errors stop the hook sequence before `Finished`. The hook is diagnostic only; production
/// [`crate::stateless_validation`] neither calls this function nor requires this feature.
///
/// # Errors
/// Returns the same [`StatelessValidationError`] as the production entry point.
///
/// # Panics
/// Panics on internal encoder invariant failures, or if the hook panics.
pub fn stateless_validation_with_stage_hook(
    block: Block,
    public_keys: &[UncompressedPublicKey],
    witness: ExecutionWitness,
    chain_spec: ChainSpec,
    mut hook: impl FnMut(ValidationStage),
) -> Result<StatelessValidationOutput, StatelessValidationError> {
    hook(ValidationStage::Recovery);
    let current_block = recover_block_with_public_keys(block, public_keys)?;
    hook(ValidationStage::Consensus);
    let ancestors = derive_ancestors(current_block.header(), &witness.headers)?;
    let active_spec = validate_block_consensus(&chain_spec, &current_block, ancestors.parent())?;
    let pre_state_root = ancestors.pre_state_root();
    let (_, ancestor_hashes) = ancestors.split();
    let block_hash = current_block.hash();
    let ExecutionParts {
        header,
        withdrawals,
        transactions,
    } = current_block.into_execution_parts()?;
    let block_env = BlockEnv::from_block(header.header(), withdrawals, active_spec)?;

    hook(ValidationStage::Witness);
    let backend = WitnessBackend::from_witness(
        block_env.vicinity(chain_spec.chain_id),
        witness,
        pre_state_root,
        ancestor_hashes,
    )?;
    hook(ValidationStage::Execution);
    let execution_output = BlockExecutor::new_with_active_spec(
        chain_spec,
        block_env,
        transactions,
        backend,
        active_spec,
    )
    .execute()?;

    hook(ValidationStage::Commitments);
    validate_block_post_execution(header.header(), &active_spec, &execution_output.result)
        .map_err(StatelessValidationError::PostExecution)?;
    hook(ValidationStage::StateRoot);
    let state_root = witness_state_root(&execution_output.state)?;

    if state_root != header.state_root {
        return Err(StatelessValidationError::PostExecution(
            BlockExecutionError::StateRootMismatch {
                got: state_root,
                expected: header.state_root,
            },
        ));
    }
    hook(ValidationStage::Finished);

    Ok(StatelessValidationOutput {
        block_hash,
        execution_output,
    })
}
