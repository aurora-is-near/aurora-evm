//! Config-level EIP-214 and EIP-2 regressions, including EELS Frontier code deposit.
//!
//! Deposit boundaries were cross-checked against EELS abbe05777ab8: Frontier and
//! Homestead creation messages, plus CREATE with the unmodified Frontier rules.

use aurora_evm::backend::{ApplyBackend, Backend, MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata};
use aurora_evm::{Config, CreateScheme, ExitError, ExitReason, Opcode};
use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

#[path = "config_semantics/static_calls.rs"]
mod static_calls;

const CALLER: H160 = H160([0xca; 20]);
const CONTRACT: H160 = H160([0xcc; 20]);
// SSTORE(0, 1); LOG0(0, 0); RETURN(0, 100).
const INIT: &[u8] = &[
    0x60, 1, 0x60, 0, 0x55, 0x60, 0, 0x60, 0, 0xa0, 0x60, 100, 0x60, 0, 0xf3,
];
// EELS Frontier: SSTORE 20,000; six PUSHes 18; LOG0 375; four memory words 12.
const INIT_GAS: u64 = 20_405;
const DEPOSIT_GAS: u64 = 20_000;
const RETURN_STATUS: &[u8] = &[0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3];

fn vicinity() -> MemoryVicinity {
    MemoryVicinity {
        gas_price: U256::zero(),
        effective_gas_price: U256::zero(),
        origin: CALLER,
        chain_id: U256::one(),
        block_hashes: Vec::new(),
        block_number: U256::one(),
        block_coinbase: H160::zero(),
        block_timestamp: U256::zero(),
        block_difficulty: U256::zero(),
        block_gas_limit: U256::from(1_000_000),
        block_base_fee_per_gas: U256::zero(),
        block_randomness: None,
        blob_gas_price: None,
        blob_hashes: Vec::new(),
    }
}

#[test]
fn presets_enable_staticcall_and_eip2_after_frontier() {
    let frontier = Config::frontier();

    assert!(!frontier.has_static_call);
    assert!(!frontier.create_fails_on_code_deposit_oog);

    for config in [
        Config::istanbul(),
        Config::berlin(),
        Config::london(),
        Config::merge(),
        Config::shanghai(),
        Config::cancun(),
        Config::prague(),
        Config::osaka(),
    ] {
        assert!(config.has_static_call);
        assert!(config.create_fails_on_code_deposit_oog);
    }
}

#[test]
fn staticcall_never_charges_for_a_new_account() {
    // EIP-214: STATICCALL transfers no value and never pays NEW_ACCOUNT, even with
    // the pre-EIP-161 existence rule independently selected by a custom Config.
    for mut config in [Config::frontier(), Config::istanbul()] {
        config.has_static_call = true;
        config.empty_considered_exists = true;
        let mut code = vec![0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x73];
        code.extend_from_slice(&[0xdd; 20]);
        code.extend_from_slice(&[0x60, 0, 0xfa, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3]);
        let vicinity = vicinity();
        let backend = MemoryBackend::new(
            &vicinity,
            BTreeMap::from([
                (CALLER, MemoryAccount::default()),
                (
                    CONTRACT,
                    MemoryAccount {
                        code,
                        ..MemoryAccount::default()
                    },
                ),
            ]),
        );

        // Six operand PUSHes (18), call base, MSTORE/RETURN setup + memory (15).
        let limit = 21_000 + 18 + config.gas_call + 15;
        let state = MemoryStackState::new(StackSubstateMetadata::new(limit, &config), &backend);
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
        let (reason, output) = executor.transact_call(
            CALLER,
            CONTRACT,
            U256::zero(),
            Vec::new(),
            limit,
            Vec::new(),
            Vec::new(),
        );

        assert!(reason.is_succeed(), "{reason:?}");
        assert_eq!(U256::from_big_endian(&output), U256::one());
        assert_eq!(executor.used_gas(), limit);
    }
}

#[test]
fn code_deposit_boundary_preserves_or_reverts_all_initcode_effects() {
    for fails_on_oog in [false, true] {
        for deposit_budget in [DEPOSIT_GAS - 1, DEPOSIT_GAS, DEPOSIT_GAS + 1] {
            let mut config = Config::frontier();
            config.create_fails_on_code_deposit_oog = fails_on_oog;
            let vicinity = vicinity();
            let mut backend = MemoryBackend::new(
                &vicinity,
                BTreeMap::from([(
                    CALLER,
                    MemoryAccount {
                        balance: U256::from(1_000_000),
                        ..MemoryAccount::default()
                    },
                )]),
            );

            // EELS Frontier transaction data: eleven nonzero bytes and four zeros.
            let intrinsic = 21_000 + 11 * 68 + 4 * 4;
            let limit = intrinsic + INIT_GAS + deposit_budget;
            let state = MemoryStackState::new(StackSubstateMetadata::new(limit, &config), &backend);
            let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
            let address = executor.create_address(CreateScheme::Legacy { caller: CALLER });
            let (reason, output) =
                executor.transact_create(CALLER, U256::from(7), INIT.to_vec(), limit, Vec::new());
            let insufficient = deposit_budget < DEPOSIT_GAS;
            let failed = insufficient && fails_on_oog;

            if failed {
                assert_eq!(reason, ExitReason::Error(ExitError::OutOfGas));
            } else {
                assert!(reason.is_succeed(), "{reason:?}");
            }

            assert_eq!(output, b"");

            let expected_used = if failed {
                limit
            } else {
                intrinsic + INIT_GAS + if insufficient { 0 } else { DEPOSIT_GAS }
            };

            assert_eq!(executor.used_gas(), expected_used);

            let (values, logs) = executor.into_state().deconstruct();
            let logs: Vec<_> = logs.into_iter().collect();

            assert_eq!(logs.len(), usize::from(!failed));

            backend.apply(values, logs, false);

            assert_eq!(backend.exists(address), !failed);
            assert_eq!(
                backend.storage(address, H256::zero()),
                H256::from_low_u64_be(u64::from(!failed))
            );
            assert_eq!(
                backend.basic(address).balance,
                U256::from(if failed { 0 } else { 7 })
            );
            assert_eq!(
                backend.basic(CALLER).balance,
                U256::from(if failed { 1_000_000 } else { 999_993 })
            );
            assert_eq!(
                backend.code(address),
                if insufficient {
                    Vec::new()
                } else {
                    vec![0; 100]
                }
            );
        }
    }
}

// CALL-family operands with a one-word output area and no input or value.
fn append_test_call(code: &mut Vec<u8>, target: H160, is_static: bool, gas: u16) {
    code.extend_from_slice(&[0x60, 32, 0x60, 0, 0x60, 0, 0x60, 0]);
    if !is_static {
        code.extend_from_slice(&[0x60, 0]);
    }
    code.push(0x73);
    code.extend_from_slice(target.as_bytes());
    code.push(0x61);
    code.extend_from_slice(&gas.to_be_bytes());
    code.push(if is_static { 0xfa } else { 0xf1 });
}

fn static_call_code(target: H160, followup: Option<H160>) -> Vec<u8> {
    let mut code = Vec::new();
    append_test_call(&mut code, target, true, 60_000);

    if let Some(target) = followup {
        code.push(0x50); // Discard STATICCALL's status before the nonstatic CALL.
        append_test_call(&mut code, target, false, 0);
    }
    code.extend_from_slice(RETURN_STATUS);
    code
}

#[test]
fn static_calls_preserve_absence_without_changing_call_prices_or_existing_touches() {
    const TARGET: H160 = H160([0xdd; 20]);
    const MIDDLE: H160 = H160([0xee; 20]);

    for legacy_existence in [false, true] {
        for target_balance in [None, Some(0), Some(1)] {
            for nested in [false, true] {
                for followup_call in [false, true] {
                    let mut config = Config::istanbul();
                    config.empty_considered_exists = legacy_existence;
                    let mut middle_code = Vec::new();
                    append_test_call(&mut middle_code, TARGET, false, 0);
                    middle_code.extend_from_slice(RETURN_STATUS);
                    let code = static_call_code(
                        if nested { MIDDLE } else { TARGET },
                        followup_call.then_some(TARGET),
                    );
                    let mut accounts = BTreeMap::from([
                        (CALLER, MemoryAccount::default()),
                        (
                            CONTRACT,
                            MemoryAccount {
                                code,
                                ..MemoryAccount::default()
                            },
                        ),
                        (
                            MIDDLE,
                            MemoryAccount {
                                code: middle_code,
                                ..MemoryAccount::default()
                            },
                        ),
                    ]);

                    if let Some(balance) = target_balance {
                        accounts.insert(
                            TARGET,
                            MemoryAccount {
                                balance: U256::from(balance),
                                ..MemoryAccount::default()
                            },
                        );
                    }

                    let vicinity = vicinity();
                    let mut backend = MemoryBackend::new(&vicinity, accounts);
                    let state = MemoryStackState::new(
                        StackSubstateMetadata::new(200_000, &config),
                        &backend,
                    );
                    let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
                    let (reason, output) = executor.transact_call(
                        CALLER,
                        CONTRACT,
                        U256::zero(),
                        Vec::new(),
                        200_000,
                        Vec::new(),
                        Vec::new(),
                    );

                    assert!(reason.is_succeed(), "{reason:?}");
                    assert_eq!(U256::from_big_endian(&output), U256::one());

                    // Istanbul: 700 per call, 3 per PUSH/MSTORE/memory word, 2 per POP.
                    // A nested zero CALL and a later nonstatic CALL each pay 25,000
                    // for an absent target under the legacy existence rule.
                    let new_account_fee = if legacy_existence && target_balance.is_none() {
                        25_000
                    } else {
                        0
                    };
                    let expected = 21_000
                        + 18
                        + 700
                        + 3
                        + 12
                        + if nested {
                            21 + 700 + new_account_fee + 3 + 12
                        } else {
                            0
                        }
                        + if followup_call {
                            2 + 21 + 700 + new_account_fee
                        } else {
                            0
                        };

                    assert_eq!(executor.used_gas(), expected);

                    let materialized =
                        target_balance.is_some() || followup_call || !legacy_existence;

                    // Check the journal before applying: delayed filtering cannot protect CALL pricing.
                    assert_eq!(executor.state().exists(TARGET), materialized);

                    let (values, logs) = executor.into_state().deconstruct();
                    backend.apply(values, logs, !legacy_existence);
                    let retained = if legacy_existence {
                        target_balance.is_some() || followup_call
                    } else {
                        target_balance == Some(1)
                    };

                    assert_eq!(backend.exists(TARGET), retained);
                    assert_eq!(
                        backend.basic(TARGET).balance,
                        U256::from(target_balance.unwrap_or(0))
                    );
                }
            }
        }
    }
}

#[test]
fn create_opcode_returns_address_on_frontier_deposit_failure() {
    for fails_on_oog in [false, true] {
        let mut config = Config::frontier();
        config.create_fails_on_code_deposit_oog = fails_on_oog;
        // Retain parent gas so the EIP-2 variant can report the failed CREATE as zero.
        config.call_l64_after_gas = true;
        let mut code = vec![
            0x60, 15, 0x60, 22, 0x60, 0, 0x39, 0x60, 15, 0x60, 0, 0x60, 7, 0xf0, 0x60, 0, 0x52,
            0x60, 32, 0x60, 0, 0xf3,
        ];
        code.extend_from_slice(INIT);
        let vicinity = vicinity();
        let backend = MemoryBackend::new(
            &vicinity,
            BTreeMap::from([
                (CALLER, MemoryAccount::default()),
                (
                    CONTRACT,
                    MemoryAccount {
                        code,
                        balance: U256::from(7),
                        ..MemoryAccount::default()
                    },
                ),
            ]),
        );

        // Before CREATE: 32,027 gas. L(41,045) = 40,404: one short of deposit.
        let limit = 21_000 + 32_027 + 41_045;
        let state = MemoryStackState::new(StackSubstateMetadata::new(limit, &config), &backend);
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
        let address = executor.create_address(CreateScheme::Legacy { caller: CONTRACT });
        let (reason, output) = executor.transact_call(
            CALLER,
            CONTRACT,
            U256::zero(),
            Vec::new(),
            limit,
            Vec::new(),
            Vec::new(),
        );

        assert!(reason.is_succeed(), "{reason:?}");
        assert_eq!(
            H160::from_slice(&output[12..]),
            if fails_on_oog { H160::zero() } else { address }
        );
        assert_eq!(
            executor.state().storage(address, H256::zero()),
            H256::from_low_u64_be(u64::from(!fails_on_oog))
        );
        assert_eq!(
            executor.state().basic(address).balance,
            U256::from(if fails_on_oog { 0 } else { 7 })
        );
        assert_eq!(executor.state().code(address), b"");
        assert_eq!(
            executor.used_gas(),
            21_000 + 32_027 + if fails_on_oog { 40_404 } else { INIT_GAS } + 12
        );

        let (_, logs) = executor.into_state().deconstruct();

        assert_eq!(logs.into_iter().count(), usize::from(!fails_on_oog));
    }
}

#[test]
fn frontier_create_opcode_deposit_boundary_preserves_applied_state() {
    let config = Config::frontier();

    for deposit_budget in [DEPOSIT_GAS - 1, DEPOSIT_GAS, DEPOSIT_GAS + 1] {
        // Copy the initcode, CREATE with value 7, then STOP (no post-CREATE gas needed).
        let mut code = vec![
            0x60, 15, 0x60, 15, 0x60, 0, 0x39, 0x60, 15, 0x60, 0, 0x60, 7, 0xf0, 0x00,
        ];
        code.extend_from_slice(INIT);
        let vicinity = vicinity();
        let mut backend = MemoryBackend::new(
            &vicinity,
            BTreeMap::from([
                (CALLER, MemoryAccount::default()),
                (
                    CONTRACT,
                    MemoryAccount {
                        code,
                        balance: U256::from(7),
                        ..MemoryAccount::default()
                    },
                ),
            ]),
        );

        // Frontier forwards all remaining gas: six PUSHes, CODECOPY + one word,
        // one memory word, and CREATE cost 32,027 before the child starts.
        let limit = 21_000 + 32_027 + INIT_GAS + deposit_budget;
        let state = MemoryStackState::new(StackSubstateMetadata::new(limit, &config), &backend);
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
        let address = executor.create_address(CreateScheme::Legacy { caller: CONTRACT });
        let (reason, output) = executor.transact_call(
            CALLER,
            CONTRACT,
            U256::zero(),
            Vec::new(),
            limit,
            Vec::new(),
            Vec::new(),
        );
        let deposited = deposit_budget >= DEPOSIT_GAS;

        assert!(reason.is_succeed(), "{reason:?}");
        assert_eq!(output, b"");
        assert_eq!(
            executor.used_gas(),
            21_000 + 32_027 + INIT_GAS + if deposited { DEPOSIT_GAS } else { 0 }
        );

        let (values, logs) = executor.into_state().deconstruct();
        let logs: Vec<_> = logs.into_iter().collect();

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].address, address);

        backend.apply(values, logs, false);

        assert!(backend.exists(address));
        assert_eq!(backend.basic(address).balance, U256::from(7));
        assert_eq!(backend.basic(CONTRACT).balance, U256::zero());
        assert_eq!(backend.basic(CONTRACT).nonce, U256::one());
        assert_eq!(
            backend.storage(address, H256::zero()),
            H256::from_low_u64_be(1)
        );
        assert_eq!(
            backend.code(address),
            if deposited { vec![0; 100] } else { Vec::new() }
        );
    }
}

#[test]
fn frontier_deposit_policy_does_not_mask_other_creation_errors() {
    let cases = [
        (vec![0xfe], ExitError::InvalidCode(Opcode::INVALID)),
        (INIT.to_vec(), ExitError::CreateContractLimit),
        // Return one byte, 0xef, forbidden independently by EIP-3541.
        (
            vec![0x60, 0xef, 0x60, 0, 0x53, 0x60, 1, 0x60, 0, 0xf3],
            ExitError::CreateContractStartingWithEF,
        ),
    ];

    for (initcode, error) in cases {
        let mut config = Config::frontier();
        config.create_contract_limit = Some(99);
        config.disallow_executable_format = true;
        let vicinity = vicinity();
        let backend = MemoryBackend::new(
            &vicinity,
            BTreeMap::from([(
                CALLER,
                MemoryAccount {
                    balance: U256::from(7),
                    ..MemoryAccount::default()
                },
            )]),
        );
        let limit = 100_000;
        let state = MemoryStackState::new(StackSubstateMetadata::new(limit, &config), &backend);
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
        let address = executor.create_address(CreateScheme::Legacy { caller: CALLER });
        let (reason, _) =
            executor.transact_create(CALLER, U256::from(7), initcode, limit, Vec::new());

        assert_eq!(reason, ExitReason::Error(error));
        assert_eq!(executor.used_gas(), limit);
        assert!(!executor.state().exists(address));
        assert_eq!(executor.state().basic(CALLER).balance, U256::from(7));

        let (_, logs) = executor.into_state().deconstruct();

        assert_eq!(logs.into_iter().count(), 0);
    }
}
