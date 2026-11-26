//! A custom memory cap fails the current frame before a child can change state.

use std::{cell::Cell, collections::BTreeMap};

use aurora_evm::backend::{Backend, MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{
    MemoryStackState, PrecompileFailure, PrecompileHandle, PrecompileOutput, PrecompileSet,
    StackExecutor, StackSubstateMetadata,
};
use aurora_evm::{Config, ExitError, ExitReason, Memory, Opcode};
use primitive_types::{H160, H256, U256};

const CALLER: H160 = H160([0xca; 20]);
const PARENT: H160 = H160([0xaa; 20]);
const CHILD: H160 = H160([0xbb; 20]);

#[derive(Default)]
struct EntryCounter(Cell<usize>);

impl PrecompileSet for EntryCounter {
    fn execute(
        &self,
        handle: &mut impl PrecompileHandle,
    ) -> Option<Result<PrecompileOutput, PrecompileFailure>> {
        if handle.code_address() == CHILD {
            self.0.set(self.0.get() + 1);
        }
        None
    }
    fn is_precompile(&self, _: H160) -> bool {
        false
    }
}

struct Outcome {
    reason: ExitReason,
    output: Vec<u8>,
    calls: usize,
    child_slot: H256,
    child_balance: U256,
    call_result: H256,
    logs: usize,
}

fn run(limit: usize, output_offset: u8, output_len: u8, revert: bool, opcode: Opcode) -> Outcome {
    let mut parent = vec![0x60, output_len, 0x60, output_offset, 0x60, 0, 0x60, 0];

    if matches!(opcode, Opcode::CALL | Opcode::CALLCODE) {
        parent.extend_from_slice(&[0x60, 1]);
    }

    parent.push(Opcode::PUSH20.as_u8());
    parent.extend_from_slice(CHILD.as_bytes());
    parent.extend_from_slice(&[
        0x61,
        0xc3,
        0x50,
        opcode.as_u8(),
        0x60,
        0,
        0x55,
        0x60,
        output_len,
        0x60,
        output_offset,
        Opcode::RETURN.as_u8(),
    ]);
    // Store a slot, emit a log, and return/revert with a byte from memory.
    let mut child = vec![
        0x60, 7, 0x60, 0, 0x55, 0x60, 0, 0x60, 0, 0xa0, 0x60, 0xab, 0x60, 0, 0x53, 0x60, 1, 0x60, 0,
    ];
    child.push(
        if revert {
            Opcode::REVERT
        } else {
            Opcode::RETURN
        }
        .as_u8(),
    );

    execute(limit, parent, child)
}

fn execute(limit: usize, parent: Vec<u8>, child: Vec<u8>) -> Outcome {
    let mut config = Config::prague();
    config.memory_limit = limit;
    let vicinity = MemoryVicinity {
        gas_price: U256::one(),
        effective_gas_price: U256::one(),
        origin: CALLER,
        chain_id: U256::one(),
        block_hashes: vec![],
        block_number: U256::one(),
        block_coinbase: H160::zero(),
        block_timestamp: U256::one(),
        block_difficulty: U256::zero(),
        block_randomness: None,
        block_gas_limit: U256::from(30_000_000),
        block_base_fee_per_gas: U256::zero(),
        blob_gas_price: None,
        blob_hashes: vec![],
    };
    let account = |code| MemoryAccount {
        nonce: U256::one(),
        balance: U256::from(100),
        code,
        storage: BTreeMap::new(),
    };
    let backend = MemoryBackend::new(
        &vicinity,
        BTreeMap::from([
            (CALLER, account(vec![])),
            (PARENT, account(parent)),
            (CHILD, account(child)),
        ]),
    );
    let state = MemoryStackState::new(StackSubstateMetadata::new(100_000, &config), &backend);
    let counter = EntryCounter::default();
    let mut executor = StackExecutor::new_with_precompiles(state, &config, &counter);
    let (reason, output) = executor.transact_call(
        CALLER,
        PARENT,
        U256::zero(),
        vec![],
        100_000,
        vec![],
        vec![],
    );
    let child_slot = executor.state().storage(CHILD, H256::zero());
    let child_balance = executor.state().basic(CHILD).balance;
    let call_result = executor.state().storage(PARENT, H256::zero());
    // This also proves that an OOG left no open child journal behind.
    let (_, logs) = executor.into_state().deconstruct();

    Outcome {
        reason,
        output,
        calls: counter.0.get(),
        child_slot,
        child_balance,
        call_result,
        logs: logs.into_iter().count(),
    }
}

#[test]
fn mload_fails_only_when_the_word_crosses_the_memory_limit() {
    let load = |limit, offset| {
        let code = vec![
            Opcode::PUSH1.as_u8(),
            offset,
            Opcode::MLOAD.as_u8(),
            Opcode::STOP.as_u8(),
        ];
        execute(limit, code, vec![]).reason
    };

    assert!(load(32, 0).is_succeed());
    assert_eq!(load(32, 1), ExitReason::Error(ExitError::OutOfGas));
    assert!(load(64, 1).is_succeed());
}

#[test]
fn oversized_output_fails_before_any_child_entry() {
    for opcode in [
        Opcode::CALL,
        Opcode::CALLCODE,
        Opcode::DELEGATECALL,
        Opcode::STATICCALL,
    ] {
        for revert in [false, true] {
            let out = run(32, 32, 1, revert, opcode);

            assert_eq!(out.reason, ExitReason::Error(ExitError::OutOfGas));
            assert_eq!(out.calls, 0);
            assert_eq!(out.child_slot, H256::zero());
            assert_eq!(out.child_balance, U256::from(100));
            assert_eq!(out.logs, 0);
        }
    }
}

#[test]
fn successful_and_reverted_calls_keep_their_normal_results() {
    for limit in [32, usize::MAX] {
        for revert in [false, true] {
            let out = run(limit, 31, 1, revert, Opcode::CALL);

            assert!(out.reason.is_succeed());
            assert_eq!(out.output, [0xab]);
            assert_eq!(out.calls, 1);
            assert_eq!(out.call_result, H256::from_low_u64_be(u64::from(!revert)));
            assert_eq!(
                out.child_slot,
                H256::from_low_u64_be(if revert { 0 } else { 7 })
            );
            assert_eq!(
                out.child_balance,
                U256::from(if revert { 100 } else { 101 })
            );
            assert_eq!(out.logs, usize::from(!revert));
        }
    }
}

#[test]
fn zero_output_length_ignores_an_out_of_bounds_offset() {
    for revert in [false, true] {
        let out = run(32, 255, 0, revert, Opcode::CALL);

        assert!(out.reason.is_succeed());
        assert_eq!(out.calls, 1);
        assert_eq!(out.call_result, H256::from_low_u64_be(u64::from(!revert)));
    }
}

#[test]
fn a_child_memory_failure_is_a_normal_unsuccessful_call() {
    let out = run(0, 255, 0, false, Opcode::CALL);

    assert!(out.reason.is_succeed());
    assert_eq!(out.calls, 1);
    assert_eq!(out.call_result, H256::zero());
    assert_eq!(out.child_slot, H256::zero());
    assert_eq!(out.child_balance, U256::from(100));
    assert_eq!(out.logs, 0);
}

#[test]
fn limit_applies_to_word_rounded_size_without_mutation_on_error() {
    for (limit, end, expected) in [
        (0, 1, false),
        (31, 1, false),
        (32, 1, true),
        (32, 32, true),
        (33, 33, false),
        (64, 33, true),
    ] {
        let mut memory = Memory::new(limit);
        let result = memory.resize_end(end);

        if expected {
            assert_eq!(result, Ok(()));
            assert_eq!(memory.effective_len(), end.div_ceil(32) * 32);
        } else {
            assert_eq!(result, Err(ExitError::OutOfGas));
            assert_eq!(memory.effective_len(), 0);
        }

        assert_eq!(memory.data().as_slice(), []);
    }

    let mut memory = Memory::new(32);
    memory.resize_end(32).unwrap();

    assert_eq!(memory.resize_end(33), Err(ExitError::OutOfGas));
    assert_eq!(memory.resize_end(usize::MAX), Err(ExitError::InvalidRange));
    assert_eq!(
        memory.resize_offset(usize::MAX, 1),
        Err(ExitError::InvalidRange)
    );
    assert_eq!(memory.resize_offset(usize::MAX, 0), Ok(()));
    assert_eq!(memory.effective_len(), 32);
}
