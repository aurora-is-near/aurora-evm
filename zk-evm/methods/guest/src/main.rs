#![allow(unused_imports, dead_code)]
use aurora_evm::backend::{ApplyBackend, MemoryBackend};
use aurora_evm::executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata};
use aurora_evm::utils::U256_ZERO;
use aurora_evm_jsontests::assertions;
use aurora_evm_jsontests::assertions::{
    assert_call_exit_exception, assert_empty_create_caller, assert_vicinity_validation,
    check_create_exit_reason,
};
use aurora_evm_jsontests::config::TestConfig;
use aurora_evm_jsontests::precompiles::Precompiles;
use aurora_evm_jsontests::types::account_state::{AccountsState, MemoryAccountsState};
use aurora_evm_jsontests::types::blob::{calc_data_fee, calc_max_data_fee, BlobExcessGasAndPrice};
use aurora_evm_jsontests::types::info::Info;
use aurora_evm_jsontests::types::transaction::{Transaction, TxType};
use aurora_evm_jsontests::types::{PreState, StateEnv};
use aurora_evm_jsontests::types::{Spec, StateTestCase};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub used_gas: u64,
    pub is_valid_hash: bool,
    pub actual_hash: String,
}

pub type ExecutionResults = Vec<ExecutionResult>;

fn main() {
    // read the input
    let input: String = env::read();
    let test_suite = serde_json::from_str::<HashMap<String, StateTestCase>>(&input)
        .expect("Parse test cases failed");

    let test_config = TestConfig::default();

    let mut results: ExecutionResults = vec![];

    for (_, test) in test_suite {
        for (spec, states) in &test.post_states {
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
                let h = states.first().unwrap().hash;
                // if vicinity could not be computed, then the transaction was invalid, so we simply
                // check the original state and move on
                let (is_valid_hash, actual_hash) = original_state.check_valid_hash(&h);
                if !is_valid_hash {
                    results.push(ExecutionResult {
                        used_gas: 0,
                        is_valid_hash,
                        actual_hash: actual_hash.to_string(),
                    });

                    continue;
                }
                assert_vicinity_validation(&tx_err, states, spec, &test_config);
                // As it's an expected validation error-skip the test run
                continue;
            }

            let vicinity = vicinity.unwrap();
            let caller = test.transaction.get_caller_from_secret_key();

            let caller_balance = original_state.caller_balance(caller);
            // EIP-3607
            let caller_code = original_state.caller_code(caller);
            // EIP-7702 - check if it's delegated designation. If it's a delegation designation, then,
            // even if `caller_code` is non-empty, the transaction should be executed.
            let is_delegated = original_state.is_delegated(caller);

            for state in states.iter() {
                let mut backend = MemoryBackend::new(&vicinity, original_state.0.clone());

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

                let metadata = StackSubstateMetadata::new(gas_limit, &gasometer_config);
                let executor_state = MemoryStackState::new(metadata, &backend);
                // let precompile = JsonPrecompile::precompile(spec).unwrap();
                let precompile = Precompiles::new(spec);
                let mut executor = StackExecutor::new_with_precompiles(
                    executor_state,
                    &gasometer_config,
                    &precompile,
                );
                executor.state_mut().withdraw(caller, total_fee).unwrap();

                let access_list = test.transaction.get_access_list(state);

                // EIP-3607: Reject transactions from senders with deployed code
                // EIP-7702: Accept transaction even if the caller has code.
                if caller_code.is_empty() || is_delegated {
                    let value = test.transaction.get_value(state);
                    if let Some(to) = test.transaction.to {
                        // Exit reason for the call is not analyzed as it mostly does not expect exceptions
                        let _reason = executor.transact_call(
                            caller,
                            to,
                            value,
                            data,
                            gas_limit,
                            access_list.clone(),
                            authorization_list.clone(),
                        );
                        assert_call_exit_exception(
                            state.expect_exception.as_ref(),
                            &test_config.name,
                        );
                    } else {
                        let code = data;

                        let reason =
                            executor.transact_create(caller, value, code, gas_limit, access_list);
                        if check_create_exit_reason(&reason.0, state.expect_exception.as_ref(), "")
                        {
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
                        assert_empty_create_caller(
                            state.expect_exception.as_ref(),
                            &test_config.name,
                        );
                    }
                }

                let used_gas = executor.used_gas();
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
                // It's a special case for hard forks: London and before,
                // According to EIP-160, an empty account should be removed. But in that particular test - original test state
                // contains account 0x03 (it's a precompile), and when precompile 0x03 was called it exit with
                // OutOfGas result. And after exit of the substate, the account is not marked as touched, as exit reason
                // is not a success. And it means that it doesn't appear in Apply::Modify, then as untouched it
                // can't be removed by the backend.apply event. In that particular case we should manage it manually.
                // NOTE: it's not realistic situation for real life flow.
                if *spec <= Spec::London && test_config.name == "failed_tx_xcf416c53" {
                    let state = backend.state_mut();
                    state.retain(|addr, account| {
                        // Check if the account is empty for the precompile `0x03`
                        !(addr.to_low_u64_be() == 3
                            && account.balance == U256_ZERO
                            && account.nonce == U256_ZERO
                            && account.code.is_empty())
                    });
                }

                let backend_state = MemoryAccountsState(backend.state().clone());
                let (is_valid_hash, actual_hash) = backend_state.check_valid_hash(&state.hash);
                results.push(ExecutionResult {
                    used_gas,
                    is_valid_hash,
                    actual_hash: actual_hash.to_string(),
                });
            }
        }
    }

    let output = serde_json::to_string_pretty(&results).unwrap();

    // write public output to the journal
    env::commit(&output);
}
