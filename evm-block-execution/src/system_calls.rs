//! Protocol system calls: EIP-2935 and EIP-4788 before the transactions, EIP-7002 and EIP-7251
//! after them.
//!
//! A system call is a `CALL` from [`SYSTEM_ADDRESS`] with [`SYSTEM_CALL_GAS_LIMIT`] gas, no value,
//! no nonce increment and no fee: nothing is deducted from the caller and nothing is paid to the
//! coinbase, so the only state a call leaves behind is what the contract itself wrote. Its logs
//! are discarded and its gas is not part of the block's `gas_used`.
//!
//! Which calls a block makes, and how their results are judged, is decided by the block executor.

use crate::precompiles::Precompiles;
use crate::spec::Spec;
use aurora_evm::ExitReason;
use aurora_evm::backend::{ApplyBackend, Backend, Log};
use aurora_evm::executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata};
use hex_literal::hex;
use primitive_types::H160;

/// The caller of every system call.
pub const SYSTEM_ADDRESS: H160 = H160(hex!("fffffffffffffffffffffffffffffffffffffffe"));

/// EIP-4788 beacon-roots contract.
pub const BEACON_ROOTS_ADDRESS: H160 = H160(hex!("000f3df6d732807ef1319fb7b8bb8522d0beac02"));

/// EIP-2935 history-storage contract.
pub const HISTORY_STORAGE_ADDRESS: H160 = H160(hex!("0000f90827f1c53a10cb7a02335b175320002935"));

/// EIP-7002 withdrawal-requests predeploy.
pub const WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS: H160 =
    H160(hex!("00000961ef480eb55e80d19ad83579a64c007002"));

/// EIP-7251 consolidation-requests predeploy.
pub const CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS: H160 =
    H160(hex!("0000bbddc7ce488642fb579f8b00f3a590007251"));

/// Gas available to every system call.
pub const SYSTEM_CALL_GAS_LIMIT: u64 = 30_000_000;

/// What a system call returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemCallOutcome {
    /// How the call ended.
    pub reason: ExitReason,
    /// The call's return data.
    pub output: Vec<u8>,
}

/// Calls `target` as the system and applies the state it changed.
///
/// A reverted or failed call changes nothing; the caller decides whether such an outcome makes
/// the block invalid.
pub(crate) fn transact_system_call<B: Backend + ApplyBackend>(
    backend: &mut B,
    precompiles: &Precompiles,
    spec: Spec,
    target: H160,
    data: Vec<u8>,
) -> SystemCallOutcome {
    let gas_config = spec.get_gasometer_config();
    let metadata = StackSubstateMetadata::new(SYSTEM_CALL_GAS_LIMIT, &gas_config);
    let executor_state = MemoryStackState::new(metadata, backend);
    let mut executor =
        StackExecutor::new_with_precompiles(executor_state, &gas_config, precompiles);

    let (reason, output) = executor.system_call(SYSTEM_ADDRESS, target, data);

    // Only the contract's own writes reach the state: the caller is neither charged nor touched
    // and no reward is paid, matching the reference client's system-call state.
    let (values, _logs) = executor.into_state().deconstruct();
    backend.apply(values, core::iter::empty::<Log>(), true);

    SystemCallOutcome { reason, output }
}
