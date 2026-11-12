//! A call reads the code of its target once, as `access_delegation` in the execution specs
//! does: pricing a CALL-family opcode or a precompile subcall resolves the EIP-7702 delegation
//! designation of the target, and the call runs the code that resolution read, or the code of
//! the delegate, read once. Gas and outcomes are those of the previous implementation, which
//! read a target without a designation four times per call.

use std::cell::RefCell;
use std::collections::BTreeMap;

use aurora_evm::backend::{Backend, Basic, MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{
    CallCode, MemoryStackState, PrecompileFailure, PrecompileHandle, PrecompileOutput,
    PrecompileSet, StackExecutor, StackState, StackSubstateMetadata,
};
use aurora_evm::{Config, Context, CreateScheme, ExitError, ExitReason, Handler, Opcode};
use primitive_types::{H160, H256, U256};

const CALLER: H160 = H160([0xca; 20]);
const PROBER: H160 = H160([0xc1; 20]);
const TARGET: H160 = H160([0xc2; 20]);
const INNER: H160 = H160([0xc3; 20]);
const DELEGATE: H160 = H160([0xd1; 20]);
/// A precompile that calls `TARGET` with the available gas. As every precompile address, it
/// is warm, so a call to it pays the warm access.
const FORWARDER: H160 = H160([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00,
]);
const GAS_LIMIT: u64 = 1_000_000;

/// A `MemoryBackend` counting the code reads of every account.
struct CountingBackend<'a> {
    inner: MemoryBackend<'a>,
    code_reads: RefCell<BTreeMap<H160, usize>>,
}

impl<'a> CountingBackend<'a> {
    fn new(inner: MemoryBackend<'a>) -> Self {
        Self {
            inner,
            code_reads: RefCell::default(),
        }
    }

    fn code_reads(&self, address: H160) -> usize {
        self.code_reads
            .borrow()
            .get(&address)
            .copied()
            .unwrap_or_default()
    }
}

impl Backend for CountingBackend<'_> {
    fn gas_price(&self) -> U256 {
        self.inner.gas_price()
    }
    fn origin(&self) -> H160 {
        self.inner.origin()
    }
    fn block_hash(&self, number: U256) -> H256 {
        self.inner.block_hash(number)
    }
    fn block_number(&self) -> U256 {
        self.inner.block_number()
    }
    fn block_coinbase(&self) -> H160 {
        self.inner.block_coinbase()
    }
    fn block_timestamp(&self) -> U256 {
        self.inner.block_timestamp()
    }
    fn block_difficulty(&self) -> U256 {
        self.inner.block_difficulty()
    }
    fn block_randomness(&self) -> Option<H256> {
        self.inner.block_randomness()
    }
    fn block_gas_limit(&self) -> U256 {
        self.inner.block_gas_limit()
    }
    fn block_base_fee_per_gas(&self) -> U256 {
        self.inner.block_base_fee_per_gas()
    }
    fn chain_id(&self) -> U256 {
        self.inner.chain_id()
    }
    fn exists(&self, address: H160) -> bool {
        self.inner.exists(address)
    }
    fn basic(&self, address: H160) -> Basic {
        self.inner.basic(address)
    }
    fn code(&self, address: H160) -> Vec<u8> {
        *self.code_reads.borrow_mut().entry(address).or_default() += 1;
        self.inner.code(address)
    }
    fn code_hash(&self, address: H160) -> H256 {
        self.inner.code_hash(address)
    }
    fn has_code(&self, address: H160) -> bool {
        self.inner.has_code(address)
    }
    fn storage(&self, address: H160, index: H256) -> H256 {
        self.inner.storage(address, index)
    }
    fn is_empty_storage(&self, address: H160) -> bool {
        self.inner.is_empty_storage(address)
    }
    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
        self.inner.original_storage(address, index)
    }
    fn blob_gas_price(&self) -> Option<u128> {
        self.inner.blob_gas_price()
    }
    fn get_blob_hash(&self, index: usize) -> Option<U256> {
        self.inner.get_blob_hash(index)
    }
}

/// The precompile set with `FORWARDER`, which calls `TARGET` with no explicit gas limit.
struct Forwarder;

impl PrecompileSet for Forwarder {
    fn execute(
        &self,
        handle: &mut impl PrecompileHandle,
    ) -> Option<Result<PrecompileOutput, PrecompileFailure>> {
        if handle.code_address() != FORWARDER {
            return None;
        }
        let context = Context {
            address: TARGET,
            caller: FORWARDER,
            apparent_value: U256::zero(),
        };
        let (reason, output) = handle.call(TARGET, None, Vec::new(), None, false, &context);
        Some(match reason {
            ExitReason::Succeed(exit_status) => Ok(PrecompileOutput {
                exit_status,
                output,
            }),
            ExitReason::Error(exit_status) => Err(PrecompileFailure::Error { exit_status }),
            ExitReason::Revert(exit_status) => Err(PrecompileFailure::Revert {
                exit_status,
                output,
            }),
            ExitReason::Fatal(exit_status) => Err(PrecompileFailure::Fatal { exit_status }),
        })
    }

    fn is_precompile(&self, address: H160) -> bool {
        address == FORWARDER
    }
}

fn push(code: &mut Vec<u8>, value: u32) {
    code.push(Opcode::PUSH4.as_u8());
    code.extend_from_slice(&value.to_be_bytes());
}

fn push_address(code: &mut Vec<u8>, address: H160) {
    code.push(Opcode::PUSH20.as_u8());
    code.extend_from_slice(address.as_bytes());
}

/// `opcode` on `to` with `gas`, no memory operands, and `value` for `CALL` and `CALLCODE`.
fn call_code(opcode: Opcode, to: H160, value: Option<u32>, gas: u32) -> Vec<u8> {
    let mut code = Vec::new();
    for _ in 0..4 {
        push(&mut code, 0);
    }
    if let Some(value) = value {
        push(&mut code, value);
    }
    push_address(&mut code, to);
    push(&mut code, gas);
    code.push(opcode.as_u8());
    code.push(Opcode::POP.as_u8());
    code
}

fn calls(first: Vec<u8>, second: Vec<u8>) -> Vec<u8> {
    [first, second].concat()
}

fn stop() -> Vec<u8> {
    vec![Opcode::STOP.as_u8()]
}

/// The EIP-7702 delegation designation to `to`.
fn designator(to: H160) -> Vec<u8> {
    let mut code = vec![0xef, 0x01, 0x00];
    code.extend_from_slice(to.as_bytes());
    code
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

fn account(balance: u64, code: Vec<u8>) -> MemoryAccount {
    MemoryAccount {
        nonce: U256::one(),
        balance: U256::from(balance),
        storage: BTreeMap::new(),
        code,
    }
}

/// `EXTCODESIZE` of `address`, whose access is priced warm or cold.
fn code_size_of(address: H160) -> Vec<u8> {
    let mut code = Vec::new();
    push_address(&mut code, address);
    code.extend_from_slice(&[
        Opcode::EXTCODESIZE.as_u8(),
        Opcode::POP.as_u8(),
        Opcode::STOP.as_u8(),
    ]);
    code
}

/// The accounts of a case: `PROBER`, `INNER`, `TARGET` and `DELEGATE` hold the given code.
fn accounts(codes: [Vec<u8>; 4]) -> BTreeMap<H160, MemoryAccount> {
    let [prober_code, inner_code, target_code, delegate_code] = codes;
    BTreeMap::from([
        (CALLER, account(1_000_000, Vec::new())),
        (PROBER, account(1000, prober_code)),
        (INNER, account(0, inner_code)),
        (TARGET, account(0, target_code)),
        (DELEGATE, account(0, delegate_code)),
    ])
}

struct Case {
    name: &'static str,
    config: Config,
    /// The account the transaction calls.
    to: H160,
    /// The code of `PROBER`, `INNER`, `TARGET` and `DELEGATE`.
    codes: [Vec<u8>; 4],
    /// Backend code reads of `TARGET` and of `DELEGATE`.
    target_reads: usize,
    delegate_reads: usize,
    /// The gas used, as by the previous implementation.
    used: u64,
}

/// A case calling `PROBER`, which runs `prober_code`, on Prague; `INNER` and `DELEGATE` stop.
fn prober_case(
    name: &'static str,
    prober_code: Vec<u8>,
    target_code: Vec<u8>,
    (target_reads, delegate_reads, used): (usize, usize, u64),
) -> Case {
    Case {
        name,
        config: Config::prague(),
        to: PROBER,
        codes: [prober_code, stop(), target_code, stop()],
        target_reads,
        delegate_reads,
        used,
    }
}

/// A transaction's top-level call of `TARGET` on Prague.
fn top_level_case(
    name: &'static str,
    target_code: Vec<u8>,
    delegate_code: Vec<u8>,
    (target_reads, delegate_reads, used): (usize, usize, u64),
) -> Case {
    Case {
        name,
        config: Config::prague(),
        to: TARGET,
        codes: [stop(), stop(), target_code, delegate_code],
        target_reads,
        delegate_reads,
        used,
    }
}

/// One CALL-family opcode from `PROBER` to `TARGET`.
fn opcode_cases(call: &[u8]) -> Vec<Case> {
    vec![
        prober_case("CALL", call.to_vec(), stop(), (1, 0, 23_623)),
        prober_case(
            "CALL with value",
            call_code(Opcode::CALL, TARGET, Some(1), 50_000),
            stop(),
            (1, 0, 30_323),
        ),
        prober_case(
            "STATICCALL",
            call_code(Opcode::STATICCALL, TARGET, None, 50_000),
            stop(),
            (1, 0, 23_620),
        ),
        prober_case(
            "DELEGATECALL",
            call_code(Opcode::DELEGATECALL, TARGET, None, 50_000),
            stop(),
            (1, 0, 23_620),
        ),
        prober_case(
            "CALLCODE",
            call_code(Opcode::CALLCODE, TARGET, Some(0), 50_000),
            stop(),
            (1, 0, 23_623),
        ),
        // The designation is read once and cached, then the code of the delegate is read.
        prober_case(
            "CALL, delegating target",
            call.to_vec(),
            designator(DELEGATE),
            (1, 1, 26_223),
        ),
    ]
}

/// Repeated calls, precompile subcalls and nested frames.
fn frame_cases(call: &[u8]) -> Vec<Case> {
    let twice = calls(call.to_vec(), call.to_vec());
    let subcall = call_code(Opcode::CALL, FORWARDER, Some(0), 100_000);
    // `PROBER` calls `TARGET`, then `INNER`, which calls `TARGET` again from the inner frame.
    let nested = calls(
        call.to_vec(),
        call_code(Opcode::CALL, INNER, Some(0), 100_000),
    );
    let nested_case =
        |name: &'static str,
         target_code: Vec<u8>,
         (target_reads, delegate_reads, used): (usize, usize, u64)| Case {
            name,
            config: Config::prague(),
            to: PROBER,
            codes: [nested.clone(), call.to_vec(), target_code, stop()],
            target_reads,
            delegate_reads,
            used,
        };
    vec![
        // Each call reads its target; the cached designation is not read again.
        prober_case("two CALLs", twice.clone(), stop(), (2, 0, 23_746)),
        prober_case(
            "two CALLs, delegating target",
            twice,
            designator(DELEGATE),
            (1, 2, 26_446),
        ),
        prober_case(
            "precompile subcall",
            subcall.clone(),
            stop(),
            (1, 0, 23_723),
        ),
        prober_case(
            "precompile subcall, delegating target",
            subcall,
            designator(DELEGATE),
            (1, 1, 26_323),
        ),
        nested_case("nested frames", stop(), (2, 0, 26_369)),
        // The designation cached by the outer frame serves the inner frame.
        nested_case(
            "nested frames, delegating target",
            designator(DELEGATE),
            (1, 2, 29_069),
        ),
    ]
}

/// A transaction's top-level call and configurations before EIP-7702.
fn transaction_cases(call: &[u8]) -> Vec<Case> {
    let cancun_case = |name: &'static str, target_code: Vec<u8>, used: u64| Case {
        name,
        config: Config::cancun(),
        to: PROBER,
        codes: [call.to_vec(), stop(), target_code, stop()],
        target_reads: 1,
        delegate_reads: 0,
        used,
    };
    vec![
        top_level_case("top-level call", stop(), stop(), (1, 0, 21_000)),
        top_level_case(
            "top-level call, delegating target",
            designator(DELEGATE),
            stop(),
            (1, 1, 21_000),
        ),
        // The top-level call warms the delegate (EIP-7702): its code, run in the context of
        // the target, sizes its own account at the warm price; sizing reads the code again.
        top_level_case(
            "top-level call, delegate warm",
            designator(DELEGATE),
            code_size_of(DELEGATE),
            (1, 2, 21_105),
        ),
        // Before EIP-7702 a designation is ordinary code: it runs, fails on its first byte
        // and consumes the forwarded gas, and the delegate is never read.
        cancun_case("Cancun, designation as code", designator(DELEGATE), 73_623),
        cancun_case("Cancun", stop(), 23_623),
    ]
}

fn run(case: Case) {
    let vicinity = vicinity();
    let backend = CountingBackend::new(MemoryBackend::new(&vicinity, accounts(case.codes)));
    let state = MemoryStackState::new(
        StackSubstateMetadata::new(GAS_LIMIT, &case.config),
        &backend,
    );
    let mut executor = StackExecutor::new_with_precompiles(state, &case.config, &Forwarder);
    let (reason, _) = executor.transact_call(
        CALLER,
        case.to,
        U256::zero(),
        Vec::new(),
        GAS_LIMIT,
        Vec::new(),
        Vec::new(),
    );
    let name = case.name;
    assert!(reason.is_succeed(), "{name}: {reason:?}");
    assert_eq!(executor.used_gas(), case.used, "{name}: gas used");
    assert_eq!(
        backend.code_reads(TARGET),
        case.target_reads,
        "{name}: code reads of the target"
    );
    assert_eq!(
        backend.code_reads(DELEGATE),
        case.delegate_reads,
        "{name}: code reads of the delegate"
    );
}

#[test]
fn a_call_reads_the_code_of_its_target_once() {
    let call = call_code(Opcode::CALL, TARGET, Some(0), 50_000);
    for case in [
        opcode_cases(&call),
        frame_cases(&call),
        transaction_cases(&call),
    ]
    .into_iter()
    .flatten()
    {
        run(case);
    }
}

#[test]
fn call_code_resolves_the_delegation_with_one_read_and_caches_it() {
    let config = Config::prague();
    let vicinity = vicinity();
    let backend = CountingBackend::new(MemoryBackend::new(
        &vicinity,
        accounts([stop(), stop(), designator(DELEGATE), stop()]),
    ));
    let mut state = MemoryStackState::new(StackSubstateMetadata::new(GAS_LIMIT, &config), &backend);

    assert_eq!(state.call_code(INNER), CallCode::Own(stop()));
    assert_eq!(state.call_code(TARGET), CallCode::Delegated(DELEGATE));
    assert_eq!(state.call_code(TARGET), CallCode::Delegated(DELEGATE));
    assert_eq!(state.get_authority_target(TARGET), Some(DELEGATE));
    assert_eq!(state.get_authority_target(INNER), None);
    assert_eq!(
        backend.code_reads(INNER),
        2,
        "an address without a designation is not cached"
    );
    assert_eq!(backend.code_reads(TARGET), 1, "a designation is read once");
    assert_eq!(
        backend.code_reads(DELEGATE),
        0,
        "the delegate is not read by the resolution"
    );

    // The code a call runs, through the `Handler`, reads the delegate once.
    let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
    assert_eq!(executor.authority_code(TARGET), stop());
    assert_eq!(executor.authority_code(INNER), stop());
    assert_eq!(backend.code_reads(DELEGATE), 1);
    assert_eq!(backend.code_reads(TARGET), 1);
    assert_eq!(backend.code_reads(INNER), 3);
}

/// An address that no account holds.
const ABSENT: H160 = H160([0xee; 20]);

/// Code that fails on its first byte, so that running it is observable in gas and outcome.
fn invalid() -> Vec<u8> {
    vec![Opcode::INVALID.as_u8()]
}

/// A `CALL` with value to `to`, absent, from a frame with 20 000 gas: the check before the
/// state access passes (11 600), the pricing reads `to` and keeps its empty code, then the
/// full cost with `C_NEW` (36 600) fails the frame, so no call consumes the kept code.
fn failing_call(to: H160) -> Vec<u8> {
    call_code(Opcode::CALL, to, Some(1), 50_000)
}

fn executor<'a>(
    config: &'a Config,
    backend: &'a CountingBackend<'a>,
) -> StackExecutor<'a, 'a, MemoryStackState<'a, 'a, CountingBackend<'a>>, ()> {
    let state = MemoryStackState::new(StackSubstateMetadata::new(GAS_LIMIT, config), backend);
    StackExecutor::new_with_precompiles(state, config, &())
}

#[test]
fn the_code_kept_by_a_failed_step_is_not_run_for_another_target() {
    // `PROBER` calls `INNER` with 20 000 gas, whose failing call keeps the empty code of
    // `ABSENT`, then calls the delegating `TARGET`, which must run the delegate's code.
    let prober = calls(
        call_code(Opcode::CALL, INNER, Some(0), 20_000),
        call_code(Opcode::CALL, TARGET, Some(0), 50_000),
    );
    run(Case {
        name: "kept code of another target",
        config: Config::prague(),
        to: PROBER,
        codes: [
            prober,
            failing_call(ABSENT),
            designator(DELEGATE),
            invalid(),
        ],
        target_reads: 1,
        delegate_reads: 1,
        used: 98_846,
    });
}

#[test]
fn a_delegation_found_while_pricing_drops_the_code_kept_for_the_target() {
    let config = Config::prague();
    let vicinity = vicinity();
    let backend = CountingBackend::new(MemoryBackend::new(
        &vicinity,
        accounts([stop(), stop(), stop(), invalid()]),
    ));
    let mut executor = executor(&config, &backend);
    // Pricing a call to `TARGET` keeps its code; `TARGET` then comes to delegate, as a state
    // change between a pricing and its call would make it, and is priced again.
    assert_eq!(executor.get_authority_target(TARGET), None);
    executor.state_mut().set_code(TARGET, designator(DELEGATE));
    assert_eq!(executor.get_authority_target(TARGET), Some(DELEGATE));
    let context = Context {
        address: TARGET,
        caller: CALLER,
        apparent_value: U256::zero(),
    };
    let _ = executor.call(TARGET, None, Vec::new(), Some(50_000), false, context);
    assert_eq!(
        backend.code_reads(DELEGATE),
        1,
        "the call runs the code of the delegate"
    );
}

#[test]
fn a_transaction_starts_without_the_code_kept_by_the_previous_one() {
    let config = Config::prague();
    let vicinity = vicinity();
    let created = {
        let backend = CountingBackend::new(MemoryBackend::new(
            &vicinity,
            accounts([stop(), stop(), stop(), stop()]),
        ));
        executor(&config, &backend).create_address(CreateScheme::Legacy { caller: PROBER })
    };
    // Returns one byte of code, `INVALID`.
    let init_code = [0x60, 0xfe, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xf3];
    // `PROBER` calls `INNER`, whose failing call keeps the empty code of the address `PROBER`
    // creates next, then creates `INVALID` there.
    let mut prober = call_code(Opcode::CALL, INNER, Some(0), 20_000);
    prober.push(Opcode::PUSH10.as_u8());
    prober.extend_from_slice(&init_code);
    prober.extend_from_slice(&[
        Opcode::PUSH1.as_u8(),
        0,
        Opcode::MSTORE.as_u8(),
        Opcode::PUSH1.as_u8(),
        10,
        Opcode::PUSH1.as_u8(),
        22,
        Opcode::PUSH1.as_u8(),
        0,
        Opcode::CREATE.as_u8(),
        Opcode::POP.as_u8(),
    ]);
    let backend = CountingBackend::new(MemoryBackend::new(
        &vicinity,
        accounts([prober, failing_call(created), stop(), stop()]),
    ));
    let mut executor = executor(&config, &backend);
    let (reason, _) = executor.transact_call(
        CALLER,
        PROBER,
        U256::zero(),
        Vec::new(),
        GAS_LIMIT,
        Vec::new(),
        Vec::new(),
    );
    assert!(reason.is_succeed(), "{reason:?}");
    assert_eq!(executor.state().code(created), invalid());

    // The next transaction calls the created account at top level: its code runs.
    let (reason, _) = executor.transact_call(
        CALLER,
        created,
        U256::zero(),
        Vec::new(),
        GAS_LIMIT,
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        reason,
        ExitReason::Error(ExitError::InvalidCode(Opcode::INVALID))
    );
}
