//! Estimate mode (`Config::estimate`) charges the caller, at every `CALL` and `CREATE` and at a
//! precompile's subcall, the sixty-fourth of the remaining gas it keeps under EIP-150, so the
//! gas used is a sufficient gas limit for execution. The callee is offered the rest, capped as
//! in execution mode.

use std::collections::BTreeMap;

use aurora_evm::backend::{MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{
    MemoryStackState, PrecompileFailure, PrecompileHandle, PrecompileOutput, PrecompileSet,
    StackExecutor, StackSubstateMetadata,
};
use aurora_evm::{Config, ExitReason, ExitSucceed, Opcode};
use primitive_types::{H160, U256};

const CALLER: H160 = H160([0xca; 20]);
/// The contract making the call or the creation.
const PROBER: H160 = H160([0xc1; 20]);
const TARGET: H160 = H160([0xc2; 20]);
/// The precompile forwarding its available gas to `TARGET`.
const FORWARDER: H160 = H160([0xf0; 20]);
const INTRINSIC_GAS: u64 = 21_000;
const PUSH_GAS: u64 = 3;
/// The seven pushes of the `CALL` operands.
const CALL_PUSH_GAS: u64 = 7 * PUSH_GAS;
/// The three pushes of the `CREATE` operands.
const CREATE_PUSH_GAS: u64 = 3 * PUSH_GAS;
const COLD_CALL_GAS: u64 = 2600;
const CREATE_GAS: u64 = 32_000;
/// The gas left to the frame once the `CALL` or `CREATE` cost is paid.
const REMAINING_GAS: u64 = 66_000;
/// The sixty-fourth of `REMAINING_GAS` the caller keeps under EIP-150, `66_000 / 64`; the
/// callee may receive the other `64_969`.
const RETAINED_GAS: u64 = 1031;

fn push2(code: &mut Vec<u8>, value: u16) {
    code.push(Opcode::PUSH2.as_u8());
    code.extend_from_slice(&value.to_be_bytes());
}

/// Pushes the `CALL` operands for `TARGET` without value, input or output, except the gas.
fn push_call_operands(code: &mut Vec<u8>) {
    for _ in 0..5 {
        push2(code, 0);
    }
    code.push(Opcode::PUSH20.as_u8());
    code.extend_from_slice(TARGET.as_bytes());
}

/// `PROBER`'s code: a `CALL` of `TARGET` offering `gas`.
fn call_code(gas: u16) -> Vec<u8> {
    let mut code = Vec::new();
    push_call_operands(&mut code);
    push2(&mut code, gas);
    code.extend_from_slice(&[Opcode::CALL.as_u8(), Opcode::STOP.as_u8()]);
    code
}

/// `PROBER`'s code: a `CALL` of `TARGET` offering all the gas, reverting if the call fails.
fn checked_call_code() -> Vec<u8> {
    let mut code = Vec::new();
    push_call_operands(&mut code);
    code.extend_from_slice(&[Opcode::GAS.as_u8(), Opcode::CALL.as_u8()]);
    // The `JUMPDEST` follows the eight bytes of the jump and the revert.
    let jump_dest = u8::try_from(code.len() + 8).expect("short code");
    code.extend_from_slice(&[
        Opcode::PUSH1.as_u8(),
        jump_dest,
        Opcode::JUMPI.as_u8(),
        Opcode::PUSH1.as_u8(),
        0,
        Opcode::PUSH1.as_u8(),
        0,
        Opcode::REVERT.as_u8(),
        Opcode::JUMPDEST.as_u8(),
        Opcode::STOP.as_u8(),
    ]);
    code
}

/// `PROBER`'s code: a `CREATE` with no value and empty init code.
fn create_code() -> Vec<u8> {
    let mut code = Vec::new();
    for _ in 0..3 {
        push2(&mut code, 0);
    }
    code.extend_from_slice(&[Opcode::CREATE.as_u8(), Opcode::STOP.as_u8()]);
    code
}

/// `TARGET`'s code: `pairs` of `PUSH1 0; POP`, five gas each.
fn busy_code(pairs: usize) -> Vec<u8> {
    let mut code = Vec::new();
    for _ in 0..pairs {
        code.extend_from_slice(&[Opcode::PUSH1.as_u8(), 0, Opcode::POP.as_u8()]);
    }
    code.push(Opcode::STOP.as_u8());
    code
}

/// A precompile calling `TARGET` with no explicit gas limit, as a host's precompile forwards
/// its available gas; it returns the outcome of the subcall.
struct Forwarder;

impl PrecompileSet for Forwarder {
    fn execute(
        &self,
        handle: &mut impl PrecompileHandle,
    ) -> Option<Result<PrecompileOutput, PrecompileFailure>> {
        if handle.code_address() != FORWARDER {
            return None;
        }
        let context = handle.context().clone();
        let (reason, output) = handle.call(TARGET, None, Vec::new(), None, false, &context);
        Some(match reason {
            ExitReason::Succeed(_) => Ok(PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output,
            }),
            ExitReason::Error(exit_status) => Err(PrecompileFailure::Error { exit_status }),
            ExitReason::Revert(exit_status) => Err(PrecompileFailure::Revert {
                exit_status,
                output,
            }),
            ExitReason::Fatal(exit_status) => Err(PrecompileFailure::Fatal { exit_status }),
        })
    }

    fn is_precompile(&self, address: H160) -> bool {
        address == FORWARDER
    }
}

/// Runs a call from `CALLER` to `to` with `gas_limit`, with `prober_code` at `PROBER`,
/// `target_code` at `TARGET` and `precompiles` serving the precompile addresses; returns the
/// exit reason and the gas used.
fn execute_with(
    estimate: bool,
    to: H160,
    prober_code: Vec<u8>,
    target_code: Vec<u8>,
    gas_limit: u64,
    precompiles: &impl PrecompileSet,
) -> (ExitReason, u64) {
    let mut config = Config::prague();
    config.estimate = estimate;
    let vicinity = MemoryVicinity {
        gas_price: U256::one(),
        effective_gas_price: U256::one(),
        origin: CALLER,
        chain_id: U256::one(),
        block_hashes: Vec::new(),
        block_number: U256::one(),
        block_coinbase: H160::zero(),
        block_timestamp: U256::one(),
        block_difficulty: U256::zero(),
        block_randomness: None,
        block_gas_limit: U256::from(30_000_000),
        block_base_fee_per_gas: U256::zero(),
        blob_gas_price: None,
        blob_hashes: Vec::new(),
    };
    let account = |code: Vec<u8>| MemoryAccount {
        nonce: U256::one(),
        balance: U256::zero(),
        storage: BTreeMap::new(),
        code,
    };
    let accounts = BTreeMap::from([
        (CALLER, account(Vec::new())),
        (PROBER, account(prober_code)),
        (TARGET, account(target_code)),
    ]);
    let backend = MemoryBackend::new(&vicinity, accounts);
    let state = MemoryStackState::new(StackSubstateMetadata::new(gas_limit, &config), &backend);
    let mut executor = StackExecutor::new_with_precompiles(state, &config, precompiles);
    let (reason, _) = executor.transact_call(
        CALLER,
        to,
        U256::zero(),
        Vec::new(),
        gas_limit,
        Vec::new(),
        Vec::new(),
    );
    (reason, executor.used_gas())
}

/// Runs `prober_code` as `PROBER`, called by `CALLER` with `gas_limit`, with `target_code` at
/// `TARGET` and no precompiles.
fn execute(
    estimate: bool,
    prober_code: Vec<u8>,
    target_code: Vec<u8>,
    gas_limit: u64,
) -> (ExitReason, u64) {
    execute_with(estimate, PROBER, prober_code, target_code, gas_limit, &())
}

#[test]
fn estimate_mode_caps_a_call_request_as_execution_mode_does() {
    let gas_limit = INTRINSIC_GAS + CALL_PUSH_GAS + COLD_CALL_GAS + REMAINING_GAS;
    let stop = vec![Opcode::STOP.as_u8()];
    // The request exceeds the 63/64 of `REMAINING_GAS` the callee may receive.
    let (reason, execution_used) = execute(false, call_code(0xFFFF), stop.clone(), gas_limit);
    assert!(reason.is_succeed(), "{reason:?}");
    assert_eq!(
        execution_used,
        INTRINSIC_GAS + CALL_PUSH_GAS + COLD_CALL_GAS
    );

    let (reason, estimate_used) = execute(true, call_code(0xFFFF), stop.clone(), gas_limit);
    assert!(reason.is_succeed(), "{reason:?}");
    assert_eq!(estimate_used, execution_used + RETAINED_GAS);

    // A request within the cap is offered as is and costs the same estimate.
    let (reason, within_cap_used) = execute(true, call_code(60_000), stop, gas_limit);
    assert!(reason.is_succeed(), "{reason:?}");
    assert_eq!(within_cap_used, estimate_used);
}

#[test]
fn estimate_mode_rounds_the_retained_gas_at_sixty_four() {
    let base_cost = INTRINSIC_GAS + CALL_PUSH_GAS + COLD_CALL_GAS;
    for (remaining, retained) in [(63, 0), (64, 1), (65, 1)] {
        for estimate in [false, true] {
            let (reason, used) = execute(
                estimate,
                call_code(0xFFFF),
                vec![Opcode::STOP.as_u8()],
                base_cost + remaining,
            );
            assert!(
                reason.is_succeed(),
                "remaining={remaining}, estimate={estimate}: {reason:?}"
            );
            let expected = base_cost + if estimate { retained } else { 0 };
            assert_eq!(used, expected, "remaining={remaining}, estimate={estimate}");
        }
    }
}

#[test]
fn estimate_mode_lets_create_forward_the_available_gas() {
    let gas_limit = INTRINSIC_GAS + CREATE_PUSH_GAS + CREATE_GAS + REMAINING_GAS;
    let (reason, execution_used) = execute(false, create_code(), Vec::new(), gas_limit);
    assert!(reason.is_succeed(), "{reason:?}");
    assert_eq!(execution_used, INTRINSIC_GAS + CREATE_PUSH_GAS + CREATE_GAS);

    let (reason, estimate_used) = execute(true, create_code(), Vec::new(), gas_limit);
    assert!(reason.is_succeed(), "{reason:?}");
    assert_eq!(estimate_used, execution_used + RETAINED_GAS);
}

#[test]
fn estimate_mode_lets_a_precompile_subcall_forward_the_available_gas() {
    let gas_limit = 100_000;
    let stop = vec![Opcode::STOP.as_u8()];
    let (reason, execution_used) = execute_with(
        false,
        FORWARDER,
        Vec::new(),
        stop.clone(),
        gas_limit,
        &Forwarder,
    );
    assert!(reason.is_succeed(), "{reason:?}");
    assert_eq!(execution_used, INTRINSIC_GAS + COLD_CALL_GAS);

    let (reason, estimate_used) =
        execute_with(true, FORWARDER, Vec::new(), stop, gas_limit, &Forwarder);
    assert!(reason.is_succeed(), "{reason:?}");
    // The precompile keeps the sixty-fourth of the gas left after the access cost.
    assert_eq!(
        estimate_used,
        execution_used + (gas_limit - execution_used) / 64
    );
}

#[test]
fn the_estimate_is_a_sufficient_gas_limit() {
    // The callee needs 5000 gas; the caller offers all of its gas and reverts if the call fails.
    let work = busy_code(1000);
    let (reason, estimate) = execute(true, checked_call_code(), work.clone(), 100_000);
    assert!(reason.is_succeed(), "{reason:?}");
    let (reason, execution_used) = execute(false, checked_call_code(), work.clone(), 100_000);
    assert!(reason.is_succeed(), "{reason:?}");
    assert!(estimate > execution_used);

    // With the estimate as the limit, the 63/64 the callee receives still cover its work.
    let (reason, _) = execute(false, checked_call_code(), work.clone(), estimate);
    assert!(reason.is_succeed(), "{reason:?}");
    // With the execution-mode usage as the limit, the callee receives 63/64 of the gas it
    // needs, runs out, and the caller reverts.
    let (reason, _) = execute(false, checked_call_code(), work, execution_used);
    assert!(matches!(reason, ExitReason::Revert(_)), "{reason:?}");
}
