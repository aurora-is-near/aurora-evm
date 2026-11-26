//! Static legacy frames reached through precompiles, CALLCODE and DELEGATECALL.

use super::*;
use aurora_evm::backend::Apply;
use aurora_evm::executor::stack::{
    PrecompileFailure, PrecompileHandle, PrecompileOutput, PrecompileSet,
};
use aurora_evm::{Context, ExitSucceed, Transfer};

const SOURCE: H160 = H160([0xee; 20]);
const TARGET: H160 = H160([0xdd; 20]);

struct ZeroTransfer;

impl PrecompileSet for ZeroTransfer {
    fn execute(
        &self,
        handle: &mut impl PrecompileHandle,
    ) -> Option<Result<PrecompileOutput, PrecompileFailure>> {
        if handle.code_address() != SOURCE {
            return None;
        }
        assert!(handle.is_static());

        let (reason, output) = handle.call(
            TARGET,
            Some(Transfer {
                source: SOURCE,
                target: TARGET,
                value: U256::zero(),
            }),
            Vec::new(),
            Some(0),
            false, // Static mode must be inherited, not supplied by the precompile.
            &Context {
                address: TARGET,
                caller: SOURCE,
                apparent_value: U256::zero(),
            },
        );

        assert!(reason.is_succeed(), "{reason:?}");
        assert_eq!(output, b"");
        Some(Ok(PrecompileOutput {
            exit_status: ExitSucceed::Stopped,
            output,
        }))
    }

    fn is_precompile(&self, address: H160) -> bool {
        address == SOURCE
    }
}

#[test]
fn static_precompile_zero_transfer_preserves_absent_endpoints_and_existing_touches() {
    for source_exists in [false, true] {
        for target_exists in [false, true] {
            let mut config = Config::istanbul();
            config.empty_considered_exists = true;
            let mut accounts = BTreeMap::from([
                (CALLER, MemoryAccount::default()),
                (
                    CONTRACT,
                    MemoryAccount {
                        code: static_call_code(SOURCE, None),
                        ..MemoryAccount::default()
                    },
                ),
            ]);

            for (address, exists) in [(SOURCE, source_exists), (TARGET, target_exists)] {
                if exists {
                    accounts.insert(address, MemoryAccount::default());
                }
            }

            let vicinity = vicinity();
            let mut backend = MemoryBackend::new(&vicinity, accounts);
            let state =
                MemoryStackState::new(StackSubstateMetadata::new(200_000, &config), &backend);
            let mut executor = StackExecutor::new_with_precompiles(state, &config, &ZeroTransfer);
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
            assert_eq!(
                executor.used_gas(),
                21_000 + 18 + 700 + 3 + 12 + 700 + if target_exists { 0 } else { 25_000 }
            );
            assert_eq!(executor.state().exists(SOURCE), source_exists);
            assert_eq!(executor.state().exists(TARGET), target_exists);

            let (values, logs) = executor.into_state().deconstruct();
            let values: Vec<_> = values.into_iter().collect();

            // Observe touches directly: legacy apply retains existing empty accounts either way.
            for (address, exists) in [(SOURCE, source_exists), (TARGET, target_exists)] {
                assert_eq!(values.iter().any(|value| matches!(value, Apply::Modify { address: touched, .. } if *touched == address)), exists);
            }

            backend.apply(values, logs, false);

            assert_eq!(backend.exists(SOURCE), source_exists);
            assert_eq!(backend.exists(TARGET), target_exists);
        }
    }
}

#[test]
fn static_callcode_and_delegatecall_keep_the_execution_account() {
    // CALLCODE's value charge includes a stipend returned by the empty callee.
    for (opcode, value, inner_cost) in [
        (Opcode::CALLCODE, 0, 21 + 700),
        (Opcode::CALLCODE, 1, 21 + 700 + 9_000 - 2_300),
        (Opcode::DELEGATECALL, 0, 18 + 700),
    ] {
        let mut config = Config::istanbul();
        config.empty_considered_exists = true;
        let mut code = vec![0x60, 32, 0x60, 0, 0x60, 0, 0x60, 0];

        // CALLCODE may carry value in a static frame: it transfers to itself.
        if opcode == Opcode::CALLCODE {
            code.extend_from_slice(&[0x60, value]);
        }

        code.push(0x73);
        code.extend_from_slice(TARGET.as_bytes());
        code.extend_from_slice(&[0x60, 0, opcode.as_u8()]);
        code.extend_from_slice(RETURN_STATUS);

        // Return the inner opcode's status, rather than merely STATICCALL's success.
        let mut outer_code = Vec::new();
        append_test_call(&mut outer_code, SOURCE, true, 60_000);
        outer_code.extend_from_slice(&[0x50, 0x60, 32, 0x60, 0, 0xf3]);
        let vicinity = vicinity();
        let mut backend = MemoryBackend::new(
            &vicinity,
            BTreeMap::from([
                (CALLER, MemoryAccount::default()),
                (
                    CONTRACT,
                    MemoryAccount {
                        code: outer_code,
                        ..MemoryAccount::default()
                    },
                ),
                (
                    SOURCE,
                    MemoryAccount {
                        balance: U256::from(7),
                        code,
                        ..MemoryAccount::default()
                    },
                ),
            ]),
        );

        let state = MemoryStackState::new(StackSubstateMetadata::new(200_000, &config), &backend);
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

        assert_eq!(
            executor.used_gas(),
            21_000 + 18 + 700 + 3 + 8 + inner_cost + 3 + 12
        );
        assert!(!executor.state().exists(TARGET));
        assert_eq!(executor.state().basic(SOURCE).balance, U256::from(7));

        let (values, logs) = executor.into_state().deconstruct();
        backend.apply(values, logs, false);

        assert!(!backend.exists(TARGET));
        assert_eq!(backend.basic(SOURCE).balance, U256::from(7));
    }
}
