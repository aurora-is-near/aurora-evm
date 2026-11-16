//! EIP-3860 failures abort the frame containing CREATE/CREATE2, including at end of code.

use std::collections::BTreeMap;

use aurora_evm::backend::{Backend, MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{
    MemoryStackState, PrecompileFailure, PrecompileHandle, PrecompileOutput, PrecompileSet,
    StackExecutor, StackSubstateMetadata,
};
use aurora_evm::{Config, ExitError, ExitReason, ExitRevert, ExitSucceed};
use primitive_types::{H160, H256, U256};

const CALLER: H160 = H160([0xca; 20]);
const CONTRACT: H160 = H160([0xc1; 20]);
const PARENT: H160 = H160([0xc2; 20]);
const INTRINSIC: u64 = 21_000;
const STORE_GAS: u64 = 22_106;
const STORE_ONE: &[u8] = &[0x60, 1, 0x60, 0, 0x55];

struct Outcome {
    reason: ExitReason,
    gas: u64,
    storage: [H256; 3],
    creator_nonce: U256,
    logs: usize,
    output: Vec<u8>,
}

fn run(
    config: &Config,
    code: Vec<u8>,
    parent: Option<Vec<u8>>,
    gas_limit: u64,
    precompiles: &impl PrecompileSet,
) -> Outcome {
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
    let account = |code| MemoryAccount {
        nonce: U256::one(),
        code,
        ..MemoryAccount::default()
    };
    let target = if parent.is_some() { PARENT } else { CONTRACT };
    let backend = MemoryBackend::new(
        &vicinity,
        BTreeMap::from([
            (CALLER, account(Vec::new())),
            (CONTRACT, account(code)),
            (PARENT, account(parent.unwrap_or_default())),
        ]),
    );
    let state = MemoryStackState::new(StackSubstateMetadata::new(gas_limit, config), &backend);
    let mut executor = StackExecutor::new_with_precompiles(state, config, precompiles);
    let (reason, output) = executor.transact_call(
        CALLER,
        target,
        U256::zero(),
        Vec::new(),
        gas_limit,
        Vec::new(),
        Vec::new(),
    );
    let gas = executor.used_gas();
    let creator_nonce = executor.state().basic(CONTRACT).nonce;
    let storage = [(CONTRACT, 0), (PARENT, 0), (PARENT, 1)].map(|(address, slot)| {
        executor
            .state()
            .storage(address, H256::from_low_u64_be(slot))
    });
    let (_, logs) = executor.into_state().deconstruct();
    Outcome {
        reason,
        gas,
        storage,
        creator_nonce,
        logs: logs.into_iter().count(),
        output,
    }
}

/// The frame writes slot 0, then creates from zero-filled memory with no following opcode.
fn creation_code(create2: bool, size: u16) -> Vec<u8> {
    let mut code = STORE_ONE.to_vec();
    if create2 {
        code.extend_from_slice(&[0x60, 0]);
    }
    code.push(0x61);
    code.extend_from_slice(&size.to_be_bytes());
    code.extend_from_slice(&[0x60, 0, 0x60, 0, if create2 { 0xf5 } else { 0xf0 }]);
    code
}

fn creation(create2: bool, oversized: bool) -> (Vec<u8>, u64) {
    // For 33 bytes: leave 3 gas after base/memory/hash costs; the EIP-3860 charge is 4.
    let gas = if oversized {
        200_000
    } else {
        STORE_GAS + 9 + 32_000 + 6 + 3 + if create2 { 3 + 12 } else { 0 }
    };
    (
        creation_code(create2, if oversized { 49_153 } else { 33 }),
        gas,
    )
}

#[test]
fn terminal_create_failure_burns_gas_and_reverts_storage() {
    for config in [
        Config::london(),
        Config::shanghai(),
        Config::cancun(),
        Config::prague(),
        Config::osaka(),
    ] {
        for create2 in [false, true] {
            for oversized in [false, true] {
                let (code, gas) = creation(create2, oversized);
                let result = run(&config, code, None, INTRINSIC + gas, &());
                if config.max_initcode_size.is_some() {
                    assert_eq!(result.reason, ExitReason::Error(ExitError::OutOfGas));
                    assert_eq!(result.storage[0], H256::zero());
                    assert_eq!(result.gas, INTRINSIC + gas);
                } else {
                    assert!(result.reason.is_succeed(), "{:?}", result.reason);
                    assert_eq!(result.storage[0], H256::from_low_u64_be(1));
                    assert!(result.gas < INTRINSIC + gas);
                }
            }
        }
    }
}

#[test]
fn a_parent_can_handle_the_failed_creation_frame() {
    for create2 in [false, true] {
        for oversized in [false, true] {
            let (code, gas) = creation(create2, oversized);
            let mut parent = STORE_ONE.to_vec();
            for _ in 0..5 {
                parent.extend_from_slice(&[0x60, 0]);
            }
            parent.push(0x73);
            parent.extend_from_slice(CONTRACT.as_bytes());
            parent.push(0x62);
            parent.extend_from_slice(&u32::try_from(gas).unwrap().to_be_bytes()[1..]);
            // Store the CALL result in slot 1; it must be zero, while the parent's slot 0 survives.
            parent.extend_from_slice(&[0xf1, 0x60, 1, 0x55]);
            let result = run(&Config::prague(), code, Some(parent), 400_000, &());
            assert!(result.reason.is_succeed(), "{:?}", result.reason);
            assert_eq!(
                result.storage,
                [H256::zero(), H256::from_low_u64_be(1), H256::zero()]
            );
            // Parent SSTORE, CALL operands/cold access, child budget, PUSH1 and cold no-op SSTORE.
            assert_eq!(
                result.gas,
                INTRINSIC + STORE_GAS + 21 + 2_600 + gas + 3 + 2_200
            );
        }
    }
}

#[test]
fn delegatecall_failure_reverts_only_the_delegated_storage_changes() {
    for create2 in [false, true] {
        for oversized in [false, true] {
            let (code, mut gas) = creation(create2, oversized);
            if !oversized {
                // DELEGATECALL writes the parent's already warm, dirty slot: 100, not 22,100.
                gas -= 22_000;
            }
            let mut parent = vec![0x60, 2, 0x60, 0, 0x55];
            for _ in 0..4 {
                parent.extend_from_slice(&[0x60, 0]);
            }
            parent.push(0x73);
            parent.extend_from_slice(CONTRACT.as_bytes());
            parent.push(0x62);
            parent.extend_from_slice(&u32::try_from(gas).unwrap().to_be_bytes()[1..]);
            parent.extend_from_slice(&[0xf4, 0x60, 1, 0x55]);
            let result = run(&Config::prague(), code, Some(parent), 400_000, &());
            assert!(result.reason.is_succeed(), "{:?}", result.reason);
            assert_eq!(
                result.storage,
                [H256::zero(), H256::from_low_u64_be(2), H256::zero()]
            );
            assert_eq!(
                result.gas,
                INTRINSIC + STORE_GAS + 18 + 2_600 + gas + 3 + 2_200
            );
        }
    }
}

#[test]
fn creation_with_exactly_enough_initcode_gas_succeeds() {
    for create2 in [false, true] {
        let (code, gas) = creation(create2, false);
        // The missing fourth gas pays the second initcode word; zero-filled initcode is STOP.
        let limit = INTRINSIC + gas + 1;
        let result = run(&Config::prague(), code, None, limit, &());
        assert!(result.reason.is_succeed(), "{:?}", result.reason);
        assert_eq!(result.gas, limit);
        assert_eq!(result.storage[0], H256::from_low_u64_be(1));
        assert_eq!(result.creator_nonce, U256::from(2));
    }
}

#[test]
fn maximum_initcode_size_is_valid_at_the_exact_gas_boundary() {
    use aurora_evm::gasometer::{GasCost, Gasometer};

    let config = Config::prague();
    for create2 in [false, true] {
        let len = U256::from(49_152);
        let cost = if create2 {
            GasCost::Create2 { len }
        } else {
            GasCost::Create { len }
        };
        // 1,536 words: 3,072 initcode gas, 9,216 memory gas and (CREATE2 only) 9,216 hash gas.
        let opcode_gas = 32_000 + 3_072 + if create2 { 9_216 } else { 0 };
        let mut meter = Gasometer::new(opcode_gas, &config);
        assert_eq!(meter.gas_cost(cost, opcode_gas), Ok(opcode_gas));
        meter.record_dynamic_cost(cost, None).unwrap();
        assert_eq!(meter.total_used_gas(), opcode_gas);
        let limit = INTRINSIC + STORE_GAS + 9 + u64::from(create2) * 3 + 9_216 + opcode_gas;
        for short in [false, true] {
            let gas = limit - u64::from(short);
            let result = run(&config, creation_code(create2, 49_152), None, gas, &());
            assert_eq!(
                result.reason,
                if short {
                    ExitReason::Error(ExitError::OutOfGas)
                } else {
                    ExitReason::Succeed(ExitSucceed::Stopped)
                }
            );
            assert_eq!(result.gas, gas);
            assert_eq!(result.storage[0], H256::from_low_u64_be(u64::from(!short)));
            assert_eq!(result.creator_nonce, U256::from(if short { 1 } else { 2 }));
        }
    }
}

#[cfg(feature = "tracing")]
#[test]
fn initcode_is_charged_in_the_creation_opcode_event() {
    use aurora_evm::gasometer::tracing::{using, Event, EventListener};

    #[derive(Default)]
    struct Costs {
        dynamic: Vec<(u64, u64)>,
        separate: Vec<u64>,
    }
    impl EventListener for Costs {
        fn event(&mut self, event: Event) {
            match event {
                Event::RecordDynamicCost {
                    gas_cost,
                    memory_gas,
                    ..
                } => {
                    self.dynamic.push((gas_cost, memory_gas));
                }
                Event::RecordCost { cost, .. } => self.separate.push(cost),
                _ => (),
            }
        }
    }
    for create2 in [false, true] {
        for oversized in [false, true] {
            let (code, gas) = creation(create2, oversized);
            let mut costs = Costs::default();
            let result = using(&mut costs, || {
                run(&Config::prague(), code, None, INTRINSIC + gas + 1, &())
            });
            let mut expected = vec![(22_100, 0)]; // The preceding SSTORE.
            if oversized {
                assert_eq!(result.reason, ExitReason::Error(ExitError::OutOfGas));
            } else {
                assert!(result.reason.is_succeed());
                expected.push((32_004 + if create2 { 12 } else { 0 }, 6));
            }
            assert_eq!(costs.dynamic, expected);
            assert!(!costs.separate.contains(&4), "no delayed initcode charge");
        }
    }
}

#[test]
fn insufficient_creation_endowment_is_an_ordinary_failure() {
    for create2 in [false, true] {
        let (mut code, gas) = creation(create2, false);
        let value = code.len() - 2;
        // PUSH1 endowment; the creator's balance is zero.
        code[value] = 1;
        // Record that CREATE returned zero, retaining the earlier storage write.
        code.extend_from_slice(&[0x15, 0x60, 0, 0x55]);
        let result = run(&Config::prague(), code, None, 100_000, &());
        assert!(result.reason.is_succeed(), "{:?}", result.reason);
        assert_eq!(result.storage[0], H256::from_low_u64_be(1));
        assert_eq!(result.creator_nonce, U256::one());
        // Full CREATE price, including initcode, then ISZERO, PUSH1 and warm no-op SSTORE.
        assert_eq!(result.gas, INTRINSIC + gas + 1 + 3 + 3 + 100);
    }
}

struct SwallowedCharge {
    fail: bool,
    revert: bool,
}

impl PrecompileSet for SwallowedCharge {
    fn execute(
        &self,
        handle: &mut impl PrecompileHandle,
    ) -> Option<Result<PrecompileOutput, PrecompileFailure>> {
        handle.log(CONTRACT, Vec::new(), vec![1]).unwrap();
        // Model a host precompile that ignores the charge error and reports success/revert.
        let _ = handle.record_cost(handle.remaining_gas() + u64::from(self.fail));
        Some(if self.revert {
            Err(PrecompileFailure::Revert {
                exit_status: ExitRevert::Reverted,
                output: vec![1],
            })
        } else {
            Ok(PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output: vec![1],
            })
        })
    }

    fn is_precompile(&self, address: H160) -> bool {
        address == CONTRACT
    }
}

#[test]
fn a_precompile_cannot_hide_a_failed_gas_charge() {
    for revert in [false, true] {
        let result = run(
            &Config::prague(),
            Vec::new(),
            None,
            INTRINSIC + 1,
            &SwallowedCharge { fail: true, revert },
        );
        assert_eq!(result.reason, ExitReason::Error(ExitError::OutOfGas));
        assert_eq!(result.gas, INTRINSIC + 1);
        assert_eq!(result.logs, 0);
        assert!(result.output.is_empty());
    }
}

#[test]
fn a_frame_can_succeed_with_exactly_zero_gas_left() {
    let result = run(
        &Config::prague(),
        STORE_ONE.to_vec(),
        None,
        INTRINSIC + STORE_GAS,
        &(),
    );
    assert!(result.reason.is_succeed());
    assert_eq!(result.gas, INTRINSIC + STORE_GAS);
    assert_eq!(result.storage[0], H256::from_low_u64_be(1));
    let result = run(
        &Config::prague(),
        Vec::new(),
        None,
        INTRINSIC + 1,
        &SwallowedCharge {
            fail: false,
            revert: false,
        },
    );
    assert!(result.reason.is_succeed());
    assert_eq!(result.gas, INTRINSIC + 1);
    assert_eq!(result.logs, 1);
    assert_eq!(result.output, [1]);
}
