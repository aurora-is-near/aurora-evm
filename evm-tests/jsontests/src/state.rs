use crate::config::TestConfig;
use crate::execution_results::TestExecutionResult;
use crate::types::{BlobExcessGasAndPrice, Spec, StateTestCase};
use aurora_evm::Config;

/*
#[derive(Deserialize, Debug)]
pub struct Test(ethjson::test_helpers::state::State);

impl Test {
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn unwrap_caller_secret_key(&self) -> H256 {
        self.0.transaction.secret.unwrap().into()
    }

    /// Unwrap caller
    ///
    /// # Panics
    ///
    /// Panics if the transaction secret is missing or if parsing the secret key fails.
    #[must_use]
    pub fn unwrap_caller(&self) -> H160 {
        let hash: H256 = self.0.transaction.secret.unwrap().into();
        let mut secret_key = [0; 32];
        secret_key.copy_from_slice(hash.as_bytes());
        let secret = SecretKey::parse(&secret_key);
        let public = libsecp256k1::PublicKey::from_secret_key(&secret.unwrap());
        let mut res = [0u8; 64];
        res.copy_from_slice(&public.serialize()[1..65]);

        H160::from(H256::from_slice(Keccak256::digest(res).as_slice()))
    }

    /// Unwraps the test to compute the memory vicinity from the transaction and environment data.
    ///
    /// This function calculates the gas price and effective gas price based on the provided fork specification
    /// and follows EIP-1559 validation rules. It also extracts additional parameters such as block randomness
    /// and blob hashes from the transaction.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidTxReason` if:
    /// - The transaction provides a max fee per gas on forks prior to London.
    /// - The maximum priority fee is greater than the gas price.
    /// - The gas price is less than the block base fee.
    ///
    /// # Panics
    ///
    /// Panics occurs for invalid transaction data.
    pub fn unwrap_to_vicinity(
        &self,
        spec: &Spec,
        blob_gas_price: Option<u128>,
    ) -> Result<MemoryVicinity, InvalidTxReason> {
        let block_base_fee_per_gas = self.0.env.block_base_fee_per_gas.0;
        let tx = &self.0.transaction;
        // Validation for EIP-1559 that was introduced in London hard fork
        let gas_price = if *spec >= Spec::London {
            tx.gas_price.or(tx.max_fee_per_gas).unwrap_or_default().0
        } else {
            if tx.max_fee_per_gas.is_some() {
                return Err(InvalidTxReason::GasPriseEip1559);
            }
            tx.gas_price.expect("expect gas price").0
        };

        // EIP-1559: priority fee must be lower than gas_price
        if let Some(max_priority_fee_per_gas) = tx.max_priority_fee_per_gas {
            if max_priority_fee_per_gas.0 > gas_price {
                return Err(InvalidTxReason::PriorityFeeTooLarge);
            }
        }

        let effective_gas_price = self.0.transaction.max_priority_fee_per_gas.map_or(
            gas_price,
            |max_priority_fee_per_gas| {
                gas_price.min(max_priority_fee_per_gas.0 + block_base_fee_per_gas)
            },
        );

        // gas price cannot be lower than base fee
        if gas_price < block_base_fee_per_gas {
            return Err(InvalidTxReason::GasPriceLessThenBlockBaseFee);
        }

        let block_randomness = if *spec > Spec::Berlin {
            self.0.env.random.map(|r| {
                // Convert between U256 and H256. U256 is in little-endian but since H256 is just
                // a string-like byte array, it's big endian (MSB is the first element of the array).
                //
                // Byte order here is important because this opcode has the same value as DIFFICULTY
                // (0x44), and so for older forks of Ethereum, the threshold value of 2^64 is used to
                // distinguish between the two: if it's below, the value corresponds to the DIFFICULTY
                // opcode, otherwise to the PREVRANDAO opcode.
                crate::utils::u256_to_h256(r.0)
            })
        } else {
            None
        };
        let blob_hashes = tx.blob_versioned_hashes.clone();

        Ok(MemoryVicinity {
            gas_price,
            effective_gas_price,
            origin: self.unwrap_caller(),
            block_hashes: Vec::new(),
            block_number: self.0.env.number.into(),
            block_coinbase: self.0.env.author.into(),
            block_timestamp: self.0.env.timestamp.into(),
            block_difficulty: self.0.env.difficulty.into(),
            block_gas_limit: self.0.env.gas_limit.into(),
            chain_id: U256::one(),
            block_base_fee_per_gas,
            block_randomness,
            blob_gas_price,
            blob_hashes,
        })
    }
}
*/

/// Runs a test in a separate thread with a specified stack size.
///
/// # Panics
///
/// This function will panic if thread spawning or joining fails.
#[must_use]
pub fn test(test_config: TestConfig, name: String, test: StateTestCase) -> TestExecutionResult {
    use std::thread;

    const STACK_SIZE: usize = 16 * 1024 * 1024;

    // Spawn thread with explicit stack size
    let child = thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(move || test_run(&test_config, &name, &test))
        .unwrap();

    // Wait for thread to join
    child.join().unwrap()
}

#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
fn test_run(test_config: &TestConfig, _name: &str, test: &StateTestCase) -> TestExecutionResult {
    let tests_result = TestExecutionResult::new();
    let test_tx = &test.transaction;
    for (spec, states) in &test.post_states {
        // Run tests for specific EVM hard fork (Spec)
        if let Some(s) = test_config.spec.as_ref() {
            if s != spec {
                continue;
            }
        }

        // Geet gasometer config for the current spec
        let Some(gasometer_config) = get_gasometer_config(spec) else {
            // If the spec is not supported, skip the test
            continue;
        };

        // EIP-4844
        let blob_gas_price = BlobExcessGasAndPrice::from_env(&test.env);
        // EIP-4844
        let data_max_fee = if gasometer_config.has_shard_blob_transactions {
            let max_fee_per_blob_gas = test_tx.max_fee_per_blob_gas.unwrap_or_default().0;
            Some(eip_4844::calc_max_data_fee(
                max_fee_per_blob_gas,
                test_tx.blob_versioned_hashes.len(),
            ))
        } else {
            None
        };
        let data_fee = if gasometer_config.has_shard_blob_transactions {
            Some(eip_4844::calc_data_fee(
                blob_gas_price.expect("expect blob_gas_price"),
                test_tx.blob_versioned_hashes.len(),
            ))
        } else {
            None
        };
        /*
        let original_state = test.unwrap_to_pre_state();
        let vicinity = test.unwrap_to_vicinity(spec, blob_gas_price);
        if let Err(tx_err) = vicinity {
            tests_result.total += states.len() as u64;
            let h = states.first().unwrap().hash.0;
            // if vicinity could not be computed then the transaction was invalid so we simply
            // check the original state and move on
            let (is_valid_hash, actual_hash) = crate::utils::check_valid_hash(&h, &original_state);
            if !is_valid_hash {
                tests_result.failed_tests.push(FailedTestDetails {
                    expected_hash: h,
                    actual_hash,
                    index: 0,
                    name: String::from_str(name).unwrap(),
                    spec: spec.clone(),
                    state: original_state,
                });
                if verbose_output.verbose_failed {
                    println!(" [{spec:?}] {name}: {tx_err:?} ... validation failed\t<----");
                }
                tests_result.failed += 1;
                continue;
            }
            assert_vicinity_validation(&tx_err, states, spec, name, &file_name.clone());
            // As it's expected validation error - skip the test run
            continue;
        }
        let vicinity = vicinity.unwrap();
        let caller = test.unwrap_caller();
        let caller_balance = original_state
            .get(&caller)
            .map_or_else(U256::zero, |acc| acc.balance);
        // EIP-3607
        let caller_code = original_state
            .get(&caller)
            .map_or_else(Vec::new, |acc| acc.code.clone());
        // EIP-7702 - check if it's delegated designation. If it's delegation designation then
        // even if `caller_code` is non-empty transaction should be executed.
        let is_delegated = original_state
            .get(&caller)
            .is_some_and(|c| Authorization::is_delegated(&c.code));

        for (i, state) in states.iter().enumerate() {
            let transaction = test_tx.select(&state.indexes);
            let mut backend = MemoryBackend::new(&vicinity, original_state.clone());
            tests_result.total += 1;
            // Test case may be expected to fail with an unsupported tx type if the current fork is
            // older than Berlin (see EIP-2718). However, this is not implemented in sputnik itself and rather
            // in the code hosting sputnik. https://github.com/rust-blockchain/evm/pull/40
            let expect_tx_type_not_supported = matches!(
                spec,
                ForkSpec::EIP150
                    | ForkSpec::EIP158
                    | ForkSpec::Frontier
                    | ForkSpec::Homestead
                    | ForkSpec::Byzantium
                    | ForkSpec::Constantinople
                    | ForkSpec::ConstantinopleFix
                    | ForkSpec::Istanbul
                    | ForkSpec::Berlin
            ) && TxType::from_txbytes(&state.txbytes)
                != TxType::Legacy
                && state.expect_exception.as_deref() == Some("TR_TypeNotSupported");
            if expect_tx_type_not_supported {
                continue;
            }

            let gas_limit: u64 = transaction.gas_limit.into();
            let data: Vec<u8> = transaction.data.clone().into();
            let valid_tx = crate::utils::transaction::validate(
                &transaction,
                test.0.env.gas_limit.0,
                caller_balance,
                &gasometer_config,
                test_tx,
                &vicinity,
                blob_gas_price,
                data_max_fee,
                spec,
                state,
            );
            // Only execute valid transactions
            if let Err(err) = &valid_tx {
                if check_validate_exit_reason(err, state.expect_exception.as_ref(), name, spec) {
                    continue;
                }
            }
            let authorization_list = valid_tx.unwrap();

            // We do not check overflow after TX validation
            let total_fee = if let Some(data_fee) = data_fee {
                vicinity.effective_gas_price * gas_limit + data_fee
            } else {
                vicinity.effective_gas_price * gas_limit
            };

            // Dump state transaction data
            let mut state_tests_dump = StateTestsDump::default();
            state_tests_dump.set_state(&original_state);
            state_tests_dump.set_caller_secret_key(test.unwrap_caller_secret_key());
            state_tests_dump.set_vicinity(&vicinity);

            let metadata =
                StackSubstateMetadata::new(transaction.gas_limit.into(), &gasometer_config);
            let executor_state = MemoryStackState::new(metadata, &backend);
            let precompile = JsonPrecompile::precompile(spec).unwrap();
            let mut executor =
                StackExecutor::new_with_precompiles(executor_state, &gasometer_config, &precompile);
            executor.state_mut().withdraw(caller, total_fee).unwrap();

            let access_list: Vec<(H160, Vec<H256>)> = transaction
                .access_list
                .into_iter()
                .map(|(address, keys)| (address.0, keys.into_iter().map(|k| k.0).collect()))
                .collect();

            // EIP-3607: Reject transactions from senders with deployed code
            // EIP-7702: Accept transaction even if caller has code.
            if caller_code.is_empty() || is_delegated {
                match transaction.to {
                    ethjson::maybe::MaybeEmpty::Some(to) => {
                        let value = transaction.value.into();

                        state_tests_dump.set_tx_data(
                            to.0,
                            value,
                            data.clone(),
                            gas_limit,
                            access_list.clone(),
                        );

                        // Exit reason for Call do not analyzed as it mostly do not expect exceptions
                        let _reason = executor.transact_call(
                            caller,
                            to.into(),
                            value,
                            data,
                            gas_limit,
                            access_list,
                            authorization_list,
                        );
                        assert_call_exit_exception(state.expect_exception.as_ref(), name);
                    }
                    ethjson::maybe::MaybeEmpty::None => {
                        let code = data;
                        let value = transaction.value.into();

                        let reason =
                            executor.transact_create(caller, value, code, gas_limit, access_list);
                        if check_create_exit_reason(
                            &reason.0,
                            state.expect_exception.as_ref(),
                            &format!("{spec:?}-{name}-{i}"),
                        ) {
                            continue;
                        }
                    }
                }
            } else {
                // According to EIP7702 - https://eips.ethereum.org/EIPS/eip-7702#transaction-origination:
                // allow EOAs whose code is a valid delegation designation, i.e. `0xef0100 || address`,
                // to continue to originate transactions.
                #[allow(clippy::collapsible_if)]
                if !(*spec >= ForkSpec::Prague
                    && TxType::from_txbytes(&state.txbytes) == TxType::EOAAccountCode)
                {
                    assert_empty_create_caller(state.expect_exception.as_ref(), name);
                }
            }

            let used_gas = executor.used_gas();
            if verbose_output.print_state {
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
            // is not success. And it mean, that it don't appeared in Apply::Modify, then as untouched it
            // can't be removed by backend.apply event. In that particular case we should manage it manually.
            // NOTE: it's not realistic situation for real life flow.
            if *spec <= ForkSpec::London && name == "failed_tx_xcf416c53" {
                let state = backend.state_mut();
                state.retain(|addr, account| {
                    // Check is account empty for precompile 0x03
                    !(addr == &H160::from_low_u64_be(3)
                        && account.balance == U256::zero()
                        && account.nonce == U256::zero()
                        && account.code.is_empty())
                });
            }

            let (is_valid_hash, actual_hash) =
                crate::utils::check_valid_hash(&state.hash.0, backend.state());

            if !is_valid_hash {
                let failed_res = FailedTestDetails {
                    expected_hash: state.hash.0,
                    actual_hash,
                    index: i,
                    name: String::from_str(name).unwrap(),
                    spec: spec.clone(),
                    state: backend.state().clone(),
                };
                tests_result.failed_tests.push(failed_res);
                tests_result.failed += 1;

                if verbose_output.verbose_failed {
                    println!("\n[{spec:?}] {name}:{i} ... failed\t<----");
                }

                if verbose_output.print_state {
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
            } else if verbose_output.very_verbose && !verbose_output.verbose_failed {
                println!(" [{spec:?}]  {name}:{i} ... passed");
            }

            state_tests_dump.set_used_gas(used_gas);
            state_tests_dump.set_state_hash(actual_hash);
            state_tests_dump.set_result_state(backend.state());
            state_tests_dump.dump_to_file(spec);
        }*/
    }
    tests_result
}

/// Denotes the type of transaction.
#[derive(Debug, PartialEq, Eq)]
pub enum TxType {
    /// All transactions before EIP-2718 are legacy.
    Legacy,
    /// <https://eips.ethereum.org/EIPS/eip-2718>
    AccessList,
    /// <https://eips.ethereum.org/EIPS/eip-1559>
    DynamicFee,
    /// <https://eips.ethereum.org/EIPS/eip-4844>
    ShardBlob,
    /// <https://eips.ethereum.org/EIPS/eip-7702>
    EOAAccountCode,
}

impl TxType {
    /// Whether this is a legacy, access list, dynamic fee, etc. transaction
    /// Taken from geth's core/types/transaction.go/UnmarshalBinary, but we only detect the transaction
    /// type rather than unmarshal the entire payload.
    #[must_use]
    pub const fn from_txbytes(txbytes: &[u8]) -> Self {
        match txbytes[0] {
            b if b > 0x7f => Self::Legacy,
            1 => Self::AccessList,
            2 => Self::DynamicFee,
            3 => Self::ShardBlob,
            4 => Self::EOAAccountCode,
            _ => panic!(
                "Unknown tx type. \
You may need to update the TxType enum if Ethereum introduced new enveloped transaction types."
            ),
        }
    }
}

#[must_use]
const fn get_gasometer_config(s: &Spec) -> Option<Config> {
    match s {
        Spec::Istanbul => Some(Config::istanbul()),
        Spec::Berlin => Some(Config::berlin()),
        Spec::London => Some(Config::london()),
        Spec::Merge => Some(Config::merge()),
        Spec::Shanghai => Some(Config::shanghai()),
        Spec::Cancun => Some(Config::cancun()),
        Spec::Prague => Some(Config::prague()),
        _ => None,
    }
}
