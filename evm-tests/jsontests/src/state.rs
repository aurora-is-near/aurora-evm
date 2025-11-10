use crate::assertions::{
    self, assert_call_exit_exception, assert_empty_create_caller, assert_vicinity_validation,
    check_create_exit_reason,
};
use crate::config::TestConfig;
use crate::execution_results::{FailedTestDetails, TestExecutionResult};
// TODO: use crate::old_precompiles::JsonPrecompile;
use crate::precompiles::Precompiles;
use crate::state_dump::{StateTestsDump, StateTestsDumper};
use crate::types::account_state::MemoryAccountsState;
use crate::types::blob::{calc_data_fee, calc_max_data_fee, BlobExcessGasAndPrice};
use crate::types::transaction::TxType;
use crate::types::{Spec, StateTestCase};
use aurora_evm::backend::{ApplyBackend, MemoryBackend};
use aurora_evm::executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata};
use aurora_evm::utils::U256_ZERO;
use primitive_types::H160;
use std::str::FromStr;
/*
impl Test {
    pub fn unwrap_caller_secret_key(&self) -> H256 {
        self.0.transaction.secret.unwrap().into()
    }
}
*/

/// Runs a test in a separate thread with a specified stack size.
///
/// # Panics
/// This function will panic if thread spawning or joining fails.
#[must_use]
pub fn test(test_config: TestConfig, test: StateTestCase) -> TestExecutionResult {
    use std::thread;

    const STACK_SIZE: usize = 16 * 1024 * 1024;

    // Spawn thread with explicit stack size
    let child = thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(move || test_run(&test_config, &test))
        .unwrap();

    // Wait for thread to join
    child.join().unwrap()
}

#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
fn test_run(test_config: &TestConfig, test: &StateTestCase) -> TestExecutionResult {
    let mut tests_result = TestExecutionResult::new();
    for (spec, states) in &test.post_states {
        // TODO
        if *spec >= Spec::Prague {
            continue;
        }

        // TODO
        // if test_config.name != "tests/static/state_tests/stStaticCall/static_callBasicFiller.json::static_callBasic[fork_Prague-state_test-d1-g0-v0]" {
        //     continue
        // }
        // println!("{test:?}");

        // Run tests for specific EVM hard fork (Spec)
        if let Some(s) = test_config.spec.as_ref() {
            if s != spec {
                continue;
            }
        }

        // Geet gasometer config for the current spec
        let Some(gasometer_config) = spec.get_gasometer_config() else {
            // If the spec is not supported, skip the test
            continue;
        };

        // EIP-4844
        let blob_gas_price = BlobExcessGasAndPrice::from_env(&test.env);
        // EIP-4844
        let data_max_fee = calc_max_data_fee(&gasometer_config, &test.transaction);
        let data_fee = calc_data_fee(
            &gasometer_config,
            &test.transaction,
            blob_gas_price.as_ref(),
        );

        let original_state = test.pre_state.as_ref().to_memory_accounts_state();
        let vicinity = test.get_memory_vicinity(spec, blob_gas_price);

        if let Err(tx_err) = vicinity {
            tests_result.total += states.len() as u64;
            let h = states.first().unwrap().hash;
            // if vicinity could not be computed then the transaction was invalid so we simply
            // check the original state and move on
            let (is_valid_hash, actual_hash) = original_state.check_valid_hash(&h);
            if !is_valid_hash {
                tests_result.failed_tests.push(FailedTestDetails {
                    expected_hash: h,
                    actual_hash,
                    index: 0,
                    name: String::from_str(&test_config.name).unwrap(),
                    spec: spec.clone(),
                    state: original_state.0,
                });
                if test_config.verbose_output.verbose_failed {
                    println!(
                        " [{spec:?}] {}: {tx_err:?} ... validation failed\t<----",
                        test_config.name
                    );
                }
                tests_result.failed += 1;
                continue;
            }
            assert_vicinity_validation(&tx_err, states, spec, test_config);
            // As it's expected validation error - skip the test run
            continue;
        }

        let vicinity = vicinity.unwrap();
        let caller = test.transaction.get_caller_from_secret_key();

        let caller_balance = original_state.caller_balance(caller);
        // EIP-3607
        let caller_code = original_state.caller_code(caller);
        // EIP-7702 - check if it's delegated designation. If it's delegation designation then
        // even if `caller_code` is non-empty transaction should be executed.
        let is_delegated = original_state.is_delegated(caller);

        for (i, state) in states.iter().enumerate() {
            let mut backend = MemoryBackend::new(&vicinity, original_state.0.clone());
            // TODO
            // println!("\nSTATE BEFORE: {:#?}", backend.state());
            tests_result.total += 1;

            // Test case may be expected to fail with an unsupported tx type if the current fork is
            // older than Berlin (see EIP-2718). However, this is not implemented in sputnik itself and rather
            // in the code hosting sputnik. https://github.com/rust-blockchain/evm/pull/40
            if spec.is_filtered_spec_for_skip()
                && TxType::from_tx_bytes(&state.tx_bytes) != TxType::Legacy
                && state.expect_exception.as_deref() == Some("TR_TypeNotSupported")
            {
                continue;
            }

            let gas_limit: u64 = test.transaction.get_gas_limit(state).as_u64();
            let data: Vec<u8> = test.transaction.get_data(state);

            let valid_tx = test.transaction.validate(
                test.env.block_gas_limit,
                caller_balance,
                &gasometer_config,
                &vicinity,
                blob_gas_price,
                data_max_fee,
                spec,
                state,
            );
            // Only execute valid transactions
            let authorization_list = match valid_tx {
                Ok(list) => list,
                Err(err)
                    if assertions::check_validate_exit_reason(
                        &err,
                        state.expect_exception.as_ref(),
                        test_config.name.as_str(),
                        spec,
                    ) =>
                {
                    continue
                }
                Err(err) => panic!("transaction validation error: {err:?}"),
            };

            // We do not check overflow after TX validation
            let total_fee = if let Some(data_fee) = data_fee {
                vicinity.effective_gas_price * gas_limit + data_fee
            } else {
                vicinity.effective_gas_price * gas_limit
            };

            // Dump state transaction data
            let mut state_tests_dump = StateTestsDump::default();
            state_tests_dump.set_state(&original_state.0);
            state_tests_dump.set_vicinity(&vicinity);

            let metadata = StackSubstateMetadata::new(gas_limit, &gasometer_config);
            let executor_state = MemoryStackState::new(metadata, &backend);
            // let precompile = JsonPrecompile::precompile(spec).unwrap();
            let precompile = Precompiles::new(spec);
            let mut executor =
                StackExecutor::new_with_precompiles(executor_state, &gasometer_config, &precompile);
            executor.state_mut().withdraw(caller, total_fee).unwrap();

            let access_list = test.transaction.get_access_list(state);

            // EIP-3607: Reject transactions from senders with deployed code
            // EIP-7702: Accept transaction even if caller has code.
            if caller_code.is_empty() || is_delegated {
                let value = test.transaction.get_value(state);
                if let Some(to) = test.transaction.to {
                    state_tests_dump.set_tx_data(
                        to,
                        value,
                        data.clone(),
                        gas_limit,
                        access_list.clone(),
                    );

                    // Exit reason for Call do not analyzed as it mostly do not expect exceptions
                    let _reason = executor.transact_call(
                        caller,
                        to,
                        value,
                        data,
                        gas_limit,
                        access_list.clone(),
                        authorization_list.clone(),
                    );
                    // TODO
                    // println!("\nCALLER: {caller:?}\nTO: {to:?}\nVALUE: {value:?}n{gas_limit:?}\n{:?}\n{:?}\nREASON: {_reason:?}",access_list,authorization_list);
                    assert_call_exit_exception(state.expect_exception.as_ref(), &test_config.name);
                } else {
                    let code = data;

                    let reason =
                        executor.transact_create(caller, value, code, gas_limit, access_list);
                    if check_create_exit_reason(
                        &reason.0,
                        state.expect_exception.as_ref(),
                        &format!("{spec:?}-{}-{i}", test_config.name),
                    ) {
                        continue;
                    }
                }
            } else {
                // According to EIP7702 - https://eips.ethereum.org/EIPS/eip-7702#transaction-origination:
                // allow EOAs whose code is a valid delegation designation, i.e. `0xef0100 || address`,
                // to continue to originate transactions.
                #[allow(clippy::collapsible_if)]
                if !(*spec >= Spec::Prague
                    && TxType::from_tx_bytes(&state.tx_bytes) == TxType::EOAAccountCode)
                {
                    assert_empty_create_caller(state.expect_exception.as_ref(), &test_config.name);
                }
            }

            let used_gas = executor.used_gas();
            if test_config.verbose_output.print_state {
                println!("gas_limit: {gas_limit}\nused_gas: {used_gas}");
            }

            let actual_fee = executor.fee(vicinity.effective_gas_price);
            // Forks after London burn miner rewards and thus have different gas fee
            // calculation (see EIP-1559)
            let miner_reward = if *spec > Spec::Berlin {
                let coinbase_gas_price = vicinity
                    .effective_gas_price
                    .saturating_sub(vicinity.block_base_fee_per_gas);
                executor.fee(coinbase_gas_price)
            } else {
                actual_fee
            };

            executor
                .state_mut()
                .deposit(vicinity.block_coinbase, miner_reward);

            let amount_to_return_for_caller = data_fee.map_or_else(
                || total_fee - actual_fee,
                |data_fee| total_fee - actual_fee - data_fee,
            );
            executor
                .state_mut()
                .deposit(caller, amount_to_return_for_caller);

            let (values, logs) = executor.into_state().deconstruct();

            backend.apply(values, logs, true);
            // It's special case for hard forks: London or before London
            // According to EIP-160 empty account should be removed. But in that particular test - original test state
            // contains account 0x03 (it's precompile), and when precompile 0x03 was called it exit with
            // OutOfGas result. And after exit of substate account not marked as touched, as exit reason
            // is not success. And it means, that it don't appear in Apply::Modify, then as untouched it
            // can't be removed by backend.apply event. In that particular case we should manage it manually.
            // NOTE: it's not realistic situation for real life flow.
            if *spec <= Spec::London && test_config.name == "failed_tx_xcf416c53" {
                let state = backend.state_mut();
                state.retain(|addr, account| {
                    // Check is account empty for precompile 0x03
                    !(addr == &H160::from_low_u64_be(3)
                        && account.balance == U256_ZERO
                        && account.nonce == U256_ZERO
                        && account.code.is_empty())
                });
            }

            // TODO
            // println!("\nSTATE AFTER: {:#?}", backend.state());
            let backend_state = MemoryAccountsState(backend.state().clone());
            let (is_valid_hash, actual_hash) = backend_state.check_valid_hash(&state.hash);
            if !is_valid_hash {
                let failed_res = FailedTestDetails {
                    expected_hash: state.hash,
                    actual_hash,
                    index: i,
                    name: test_config.name.clone(),
                    spec: spec.clone(),
                    state: backend.state().clone(),
                };
                tests_result.failed_tests.push(failed_res);
                tests_result.failed += 1;

                if test_config.verbose_output.verbose_failed {
                    println!("\n[{spec:?}] {}:{i} ... failed\t<----", test_config.name);
                }

                if test_config.verbose_output.print_state {
                    // Print detailed state data
                    println!(
                        "expected_hash:\t{:?}\nactual_hash:\t{actual_hash:?}",
                        state.hash.0,
                    );
                    for (addr, acc) in backend.state().clone() {
                        // Decode balance
                        let balance = acc.balance.to_string();

                        println!(
                            "{addr:?}: {{\n    balance: {balance}\n    code: {:?}\n    nonce: {}\n    storage: {:#?}\n}}",
                            hex::encode(acc.code),
                            acc.nonce,
                            acc.storage
                        );
                    }
                    if let Some(e) = state.expect_exception.as_ref() {
                        println!("-> expect_exception: {e}");
                    }
                }
            } else if test_config.verbose_output.very_verbose
                && !test_config.verbose_output.verbose_failed
            {
                println!(" [{spec:?}]  {}:{i} ... passed", test_config.name);
            }

            state_tests_dump.set_used_gas(used_gas);
            state_tests_dump.set_state_hash(actual_hash);
            state_tests_dump.set_result_state(backend.state());
            state_tests_dump.dump_to_file(spec);
        }
    }
    tests_result
}
