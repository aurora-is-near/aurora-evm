//! EIP-7702 authorization refunds must not reduce the estimate below intrinsic gas.

use std::collections::BTreeMap;

use aurora_evm::backend::{Backend, MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{
    Authorization, MemoryStackState, StackExecutor, StackSubstateMetadata,
};
use aurora_evm::{Config, ExitError, ExitReason, Opcode};
use primitive_types::{H160, U256};

const CALLER: H160 = H160([0xca; 20]);
const AUTHORITY: H160 = H160([0xaa; 20]);
const TARGET: H160 = H160([0xcc; 20]);
const INTRINSIC_GAS: u64 = 21_000 + 25_000;

fn run(estimate: bool, existing_authority: bool, gas_limit: u64) -> (ExitReason, u64) {
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

    let account = |nonce: u64, code: Vec<u8>| MemoryAccount {
        nonce: U256::from(nonce),
        balance: U256::zero(),
        storage: BTreeMap::new(),
        code,
    };
    let mut accounts = BTreeMap::from([
        (CALLER, account(1, Vec::new())),
        (TARGET, account(1, vec![Opcode::STOP.as_u8()])),
    ]);
    let nonce = u64::from(existing_authority);
    if existing_authority {
        accounts.insert(AUTHORITY, account(nonce, Vec::new()));
    }
    let backend = MemoryBackend::new(&vicinity, accounts);
    let state = MemoryStackState::new(StackSubstateMetadata::new(gas_limit, &config), &backend);
    let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
    // The executor accepts recovered, validated authorization tuples through its public API.
    let authorization = Authorization::new(AUTHORITY, TARGET, nonce, true);
    let expected_code = authorization.delegation_code();
    let (reason, _) = executor.transact_call(
        CALLER,
        AUTHORITY,
        U256::zero(),
        Vec::new(),
        gas_limit,
        Vec::new(),
        vec![authorization],
    );
    if reason.is_succeed() {
        assert_eq!(executor.state().code(AUTHORITY), expected_code);
        assert_eq!(
            executor.state().basic(AUTHORITY).nonce,
            U256::from(nonce + 1)
        );
    }
    (reason, executor.used_gas())
}

#[test]
fn authorization_refund_does_not_make_the_estimate_insufficient() {
    for existing_authority in [false, true] {
        let (reason, estimate) = run(true, existing_authority, 100_000);
        assert!(reason.is_succeed(), "{reason:?}");
        assert_eq!(estimate, INTRINSIC_GAS);

        let (reason, execution_used) = run(false, existing_authority, 100_000);
        assert!(reason.is_succeed(), "{reason:?}");
        // The 12,500 authorization refund is capped at one fifth of the 46,000 spent.
        let expected = if existing_authority {
            36_800
        } else {
            INTRINSIC_GAS
        };
        assert_eq!(execution_used, expected);

        let (reason, used) = run(false, existing_authority, estimate);
        assert!(reason.is_succeed(), "{reason:?}");
        assert_eq!(used, execution_used);

        if existing_authority {
            // Refunded usage is not an admissible limit: refunds cannot fund intrinsic gas.
            let (reason, _) = run(false, true, execution_used);
            assert_eq!(reason, ExitReason::Error(ExitError::OutOfGas));
        }
    }
}
