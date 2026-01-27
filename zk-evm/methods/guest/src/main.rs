#![allow(unused_imports)]
use aurora_evm_jsontests::types::account_state::AccountsState;
use aurora_evm_jsontests::types::info::Info;
use aurora_evm_jsontests::types::transaction::Transaction;
use aurora_evm_jsontests::types::StateTestCase;
use aurora_evm_jsontests::types::{PreState, StateEnv};
use aurora_zk_evm_core::RawTestCase;
use risc0_zkvm::guest::env;
use std::collections::BTreeMap;

fn main() {
    // read the input
    let _input: RawTestCase = env::read();
    let test_case = StateTestCase {
        env: StateEnv {
            block_difficulty: Default::default(),
            block_coinbase: Default::default(),
            block_gas_limit: Default::default(),
            block_number: Default::default(),
            block_timestamp: Default::default(),
            block_base_fee_per_gas: Default::default(),
            random: None,
            parent_blob_gas_used: None,
            parent_excess_blob_gas: None,
            current_excess_blob_gas: None,
        },
        pre_state: PreState(AccountsState(BTreeMap::default())),
        post_states: Default::default(),
        transaction: Transaction {
            tx_type: None,
            data: vec![],
            gas_limit: vec![],
            gas_price: None,
            nonce: Default::default(),
            secret_key: None,
            sender: None,
            to: None,
            value: vec![],
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            init_codes: None,
            access_lists: vec![],
            blob_versioned_hashes: vec![],
            max_fee_per_blob_gas: None,
            authorization_list: None,
        },
        out: None,
        info: Info {
            comment: "".to_string(),
            filling_rpc_server: None,
            filling_tool_version: None,
            fixture_format: None,
            generated_test_hash: None,
            lllcversion: None,
            solidity: None,
            source: None,
            source_hash: None,
            labels: None,
            filling_transition_tool: None,
            hash: None,
            description: None,
            url: None,
            reference_spec: None,
            reference_spec_version: None,
            eels_resolution: None,
        },
    };
    // let _ = serde_json::from_reader::<_, HashMap<String, StateTestCase>>(reader)
    //     .expect("Parse test cases failed");
    // TODO: Run tests suite like in: test_run with simplifications for guest env

    let output = 100;

    // write public output to the journal
    env::commit(&output);
}
