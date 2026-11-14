//! A `CREATE` or `CREATE2` that fails on an exhausted creator nonce, too little balance for the
//! endowment or the call depth limit emits its `Create` tracing event before the `Exit` event of
//! the failure. A tracer that opens a frame on `Call`/`Create` and closes one on `Exit` thus
//! keeps the calling frame open.
//!
//! EELS `generic_create` fails all three without a child frame: zero is pushed and the gas meant
//! for the child stays with the caller, so the three failures cost the same.
#![cfg(feature = "tracing")]

use std::collections::BTreeMap;

use aurora_evm::backend::{Backend, MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata};
use aurora_evm::tracing::{using, Event, EventListener};
use aurora_evm::{Config, ExitError, ExitReason, ExitSucceed, Opcode};
use primitive_types::{H160, H256, U256};

const CALLER: H160 = H160([0xca; 20]);
const CREATOR: H160 = H160([0xc1; 20]);
const GAS_LIMIT: u64 = 200_000;
/// Intrinsic gas, three `PUSH1`, `CREATE`, `ISZERO`, `PUSH1` and a cold zero-to-one `SSTORE`
/// (Yellow Paper Appendix G, EIP-2929); `CREATE2` adds a `PUSH1` for the salt and no hashing
/// for empty initcode.
const FAILED_CREATION_GAS: u64 = 21_000 + 3 * 3 + 32_000 + 3 + 3 + 22_100;

/// The frame events of a transaction, in order.
#[derive(Debug, PartialEq, Eq)]
enum Frame {
    Call,
    Create,
    Exit(ExitReason),
}

#[derive(Default)]
struct Frames(Vec<Frame>);

impl EventListener for Frames {
    fn event(&mut self, event: Event<'_>) {
        match event {
            Event::Call { .. } => self.0.push(Frame::Call),
            Event::Create { .. } => self.0.push(Frame::Create),
            Event::Exit { reason, .. } => self.0.push(Frame::Exit(reason.clone())),
            _ => (),
        }
    }
}

struct Outcome {
    frames: Vec<Frame>,
    reason: ExitReason,
    gas: u64,
    /// One when the creation pushed zero and the creator went on to store `ISZERO` of it.
    failed: H256,
    creator_nonce: U256,
}

fn vicinity() -> MemoryVicinity {
    MemoryVicinity {
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
    }
}

fn account(nonce: u64, code: Vec<u8>) -> MemoryAccount {
    MemoryAccount {
        nonce: U256::from(nonce),
        balance: U256::zero(),
        storage: BTreeMap::new(),
        code,
    }
}

/// `[PUSH1 0 (salt)]`, `PUSH1 0` (size), `PUSH1 0` (offset), `PUSH1 value`, `CREATE`/`CREATE2`,
/// then `SSTORE(0, ISZERO(result))`.
fn creation_code(create2: bool, value: u8) -> Vec<u8> {
    let push = |value: u8| [Opcode::PUSH1.as_u8(), value];
    let mut code = Vec::new();
    if create2 {
        code.extend(push(0));
    }
    for operand in [0, 0, value] {
        code.extend(push(operand));
    }
    let create = if create2 {
        Opcode::CREATE2
    } else {
        Opcode::CREATE
    };
    code.push(create.as_u8());
    code.push(Opcode::ISZERO.as_u8());
    code.extend(push(0));
    code.push(Opcode::SSTORE.as_u8());
    code
}

fn run(config: &Config, create2: bool, value: u8, creator_nonce: u64) -> Outcome {
    let vicinity = vicinity();
    let backend = MemoryBackend::new(
        &vicinity,
        BTreeMap::from([
            (CALLER, account(1, Vec::new())),
            (
                CREATOR,
                account(creator_nonce, creation_code(create2, value)),
            ),
        ]),
    );
    let mut frames = Frames::default();
    let state = MemoryStackState::new(StackSubstateMetadata::new(GAS_LIMIT, config), &backend);
    let mut executor = StackExecutor::new_with_precompiles(state, config, &());
    let (reason, _) = using(&mut frames, || {
        executor.transact_call(
            CALLER,
            CREATOR,
            U256::zero(),
            Vec::new(),
            GAS_LIMIT,
            Vec::new(),
            Vec::new(),
        )
    });
    Outcome {
        frames: frames.0,
        reason,
        gas: executor.used_gas(),
        failed: executor.state().storage(CREATOR, H256::zero()),
        creator_nonce: executor.state().basic(CREATOR).nonce,
    }
}

#[test]
fn failed_creations_pair_their_create_and_exit_events() {
    let stopped = ExitReason::Succeed(ExitSucceed::Stopped);
    let prague = Config::prague();
    let mut depth_limited = Config::prague();
    // The calling frame is the deepest allowed, so it cannot create.
    depth_limited.call_stack_limit = 0;
    for create2 in [false, true] {
        for (error, config, value, creator_nonce) in [
            (ExitError::MaxNonce, &prague, 0, u64::MAX),
            (ExitError::OutOfFund, &prague, 1, 1),
            (ExitError::CallTooDeep, &depth_limited, 0, 1),
        ] {
            let case = format!("{error:?}, CREATE2: {create2}");
            let outcome = run(config, create2, value, creator_nonce);
            assert_eq!(
                outcome.frames,
                [
                    Frame::Call,
                    Frame::Create,
                    Frame::Exit(ExitReason::Error(error)),
                    Frame::Exit(stopped.clone()),
                ],
                "{case}"
            );
            assert_eq!(outcome.reason, stopped, "{case}");
            assert_eq!(outcome.failed, H256::from_low_u64_be(1), "{case}");
            assert_eq!(outcome.creator_nonce, U256::from(creator_nonce), "{case}");
            assert_eq!(
                outcome.gas,
                FAILED_CREATION_GAS + u64::from(create2) * 3,
                "{case}"
            );
        }
    }
}

#[test]
fn a_successful_creation_pairs_its_create_and_exit_events() {
    let stopped = ExitReason::Succeed(ExitSucceed::Stopped);
    for create2 in [false, true] {
        let outcome = run(&Config::prague(), create2, 0, 1);
        assert_eq!(
            outcome.frames,
            [
                Frame::Call,
                Frame::Create,
                Frame::Exit(stopped.clone()),
                Frame::Exit(stopped.clone()),
            ],
            "CREATE2: {create2}"
        );
        assert_eq!(outcome.reason, stopped, "CREATE2: {create2}");
        assert_eq!(outcome.failed, H256::zero(), "CREATE2: {create2}");
        assert_eq!(outcome.creator_nonce, U256::from(2), "CREATE2: {create2}");
    }
}

/// A `CREATE2` transaction reaches the same nonce check, so its failure is paired as well.
#[test]
fn a_create2_transaction_with_an_exhausted_nonce_pairs_its_events() {
    let config = Config::prague();
    let vicinity = vicinity();
    let backend = MemoryBackend::new(
        &vicinity,
        BTreeMap::from([(CALLER, account(u64::MAX, Vec::new()))]),
    );
    let mut frames = Frames::default();
    let state = MemoryStackState::new(StackSubstateMetadata::new(GAS_LIMIT, &config), &backend);
    let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
    let (reason, _) = using(&mut frames, || {
        executor.transact_create2(
            CALLER,
            U256::zero(),
            Vec::new(),
            H256::zero(),
            GAS_LIMIT,
            Vec::new(),
        )
    });
    let max_nonce = ExitReason::Error(ExitError::MaxNonce);
    assert_eq!(frames.0, [Frame::Create, Frame::Exit(max_nonce.clone())]);
    assert_eq!(reason, max_nonce);
    assert_eq!(executor.state().basic(CALLER).nonce, U256::from(u64::MAX));
}
