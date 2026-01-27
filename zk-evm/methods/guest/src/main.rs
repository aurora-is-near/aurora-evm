// use aurora_evm_jsontests::types::StateTestCase;
use aurora_zk_evm_core::RawTestCase;
use risc0_zkvm::guest::env;

fn main() {
    // read the input
    let _input: RawTestCase = env::read();
    // let _ = serde_json::from_reader::<_, HashMap<String, StateTestCase>>(reader)
    //     .expect("Parse test cases failed");
    // TODO: Run tests suite like in: test_run with simplifications for guest env

    let output = 100;

    // write public output to the journal
    env::commit(&output);
}
