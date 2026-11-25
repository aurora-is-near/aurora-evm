//! Public journal code ownership and export through the backend's `Apply` API.

use aurora_evm::backend::{
    Apply, ApplyBackend, Backend, Basic, MemoryAccount, MemoryBackend, MemoryVicinity,
};
use aurora_evm::executor::stack::{
    Code, MemoryStackAccount, MemoryStackState, StackState, StackSubstateMetadata,
};
use aurora_evm::Config;
use primitive_types::{H160, U256};
use std::collections::BTreeMap;

const fn vicinity() -> MemoryVicinity {
    MemoryVicinity {
        gas_price: U256::zero(),
        effective_gas_price: U256::zero(),
        origin: H160::zero(),
        chain_id: U256::one(),
        block_hashes: Vec::new(),
        block_number: U256::zero(),
        block_coinbase: H160::zero(),
        block_timestamp: U256::zero(),
        block_difficulty: U256::zero(),
        block_gas_limit: U256::zero(),
        block_base_fee_per_gas: U256::zero(),
        block_randomness: None,
        blob_gas_price: None,
        blob_hashes: Vec::new(),
    }
}

#[test]
fn memory_stack_account_supports_public_struct_literals() {
    let account = MemoryStackAccount {
        basic: Basic::default(),
        code: Some(Code::new(vec![0x5b])),
        reset: false,
    };

    assert_eq!(account.code.unwrap().as_bytes(), &[0x5b]);
}

#[test]
fn deconstruct_moves_unique_bytecode_and_preserves_an_external_owner() {
    let unique = H160::from_low_u64_be(1);
    let shared = H160::from_low_u64_be(2);
    let vicinity = vicinity();
    let config = Config::osaka();
    let mut backend = MemoryBackend::new(&vicinity, BTreeMap::new());
    let mut state = MemoryStackState::new(StackSubstateMetadata::new(0, &config), &backend);
    let bytes = vec![0x5b, 0x00];
    let unique_ptr = bytes.as_ptr();
    let external = Code::new(vec![0x60, 0x01, 0x00]);
    let shared_ptr = external.as_bytes().as_ptr();
    state.set_code(unique, bytes);
    state.account_mut(shared).code = Some(external.clone());
    let (updates, logs) = state.deconstruct();
    backend.apply(updates, logs, false);

    assert_eq!(backend.state()[&unique].code, [0x5b, 0x00]);
    assert_eq!(backend.state()[&unique].code.as_ptr(), unique_ptr);
    assert_eq!(backend.state()[&shared].code, external.as_bytes());
    assert_ne!(backend.state()[&shared].code.as_ptr(), shared_ptr);
    assert_eq!(backend.code_hash(shared), external.hash());

    // The surviving owner can now reclaim the original bytes without copying.
    let bytes = external.into_bytes();

    assert_eq!(bytes, [0x60, 0x01, 0x00]);
    assert_eq!(bytes.as_ptr(), shared_ptr);
}

#[test]
fn deconstruct_distinguishes_a_touch_from_an_explicit_code_clear() {
    let contract = H160::from_low_u64_be(1);
    let vicinity = vicinity();
    let config = Config::osaka();

    for clear in [false, true] {
        let account = MemoryAccount {
            code: vec![0x5b],
            ..MemoryAccount::default()
        };
        let mut backend = MemoryBackend::new(&vicinity, BTreeMap::from([(contract, account)]));
        let mut state = MemoryStackState::new(StackSubstateMetadata::new(0, &config), &backend);
        state.touch(contract);

        if clear {
            state.set_code(contract, Vec::new());
        }

        let (updates, logs) = state.deconstruct();
        let updates: Vec<_> = updates.into_iter().collect();
        let [Apply::Modify { address, code, .. }] = updates.as_slice() else {
            panic!("expected one account modification");
        };

        assert_eq!(*address, contract);
        assert_eq!(code.as_deref(), clear.then_some([].as_slice()));

        backend.apply(updates, logs, false);
        let expected: &[u8] = if clear { &[] } else { &[0x5b] };

        assert_eq!(backend.state()[&contract].code, expected);
    }
}
