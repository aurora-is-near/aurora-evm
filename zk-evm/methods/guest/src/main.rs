#![allow(unused_imports, dead_code)]
use aurora_evm_jsontests::types::account_state::AccountsState;
use aurora_evm_jsontests::types::info::Info;
use aurora_evm_jsontests::types::transaction::Transaction;
use aurora_evm_jsontests::types::StateTestCase;
use aurora_evm_jsontests::types::{PreState, StateEnv};
use aurora_zk_evm_core::RawTestCase;
use risc0_zkvm::guest::env;
use std::collections::{BTreeMap, HashMap};

fn main() {
    // read the input
    let input: String = env::read();
    let test_case = serde_json::from_str::<HashMap<String, StateTestCase>>(&input)
        .expect("Parse test cases failed");

    let output = 100;

    // write public output to the journal
    env::commit(&output);
}
