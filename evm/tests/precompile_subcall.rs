//! A precompile's subcall, `PrecompileHandle::call`, is priced as the `CALL` opcode it stands in
//! for (Yellow Paper Appendix H.2, EIP-2929, EIP-7702): the gas owed before the first state
//! access is checked before the target is read, the target and its delegate are warm afterwards,
//! the charge is the opcode's, and a static frame transfers no value.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use aurora_evm::backend::{Backend, Basic, MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{
    MemoryStackState, PrecompileFailure, PrecompileHandle, PrecompileOutput, PrecompileSet,
    StackExecutor, StackState, StackSubstateMetadata,
};
use aurora_evm::{Config, Context, ExitError, ExitReason, ExitSucceed, Opcode, Transfer};
use primitive_types::{H160, H256, U256};

type PrecompileResult = Result<PrecompileOutput, PrecompileFailure>;

const CALLER: H160 = H160([0xca; 20]);
/// The precompile making the subcall.
const SUBCALLER: H160 = H160([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00,
]);
/// A contract making the same call with the `CALL` opcode.
const PROBER: H160 = H160([0xc1; 20]);
const TARGET: H160 = H160([0xc2; 20]);
const DELEGATE: H160 = H160([0xd1; 20]);
const INTRINSIC_GAS: u64 = 21_000;
const ACCESS_LIST_ADDRESS_GAS: u64 = 2400;
const PUSH_GAS: u64 = 3;
/// The seven pushes of the `CALL` opcode's operands.
const CALL_PUSH_GAS: u64 = 7 * PUSH_GAS;
const CALL_STIPEND: u64 = 2300;
/// The gas the target records for its own execution when it acts as a precompile.
const TARGET_PRECOMPILE_GAS: u64 = 7;

/// A `MemoryBackend` counting the reads of every account.
struct ReadProbe<'a> {
    inner: MemoryBackend<'a>,
    reads: RefCell<BTreeMap<H160, usize>>,
}

impl ReadProbe<'_> {
    fn read(&self, address: H160) {
        *self.reads.borrow_mut().entry(address).or_default() += 1;
    }

    fn reads_of(&self, address: H160) -> usize {
        self.reads
            .borrow()
            .get(&address)
            .copied()
            .unwrap_or_default()
    }
}

impl Backend for ReadProbe<'_> {
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
        self.read(address);
        self.inner.exists(address)
    }
    fn basic(&self, address: H160) -> Basic {
        self.read(address);
        self.inner.basic(address)
    }
    fn code(&self, address: H160) -> Vec<u8> {
        self.read(address);
        self.inner.code(address)
    }
    fn code_hash(&self, address: H160) -> H256 {
        self.read(address);
        self.inner.code_hash(address)
    }
    fn has_code(&self, address: H160) -> bool {
        self.read(address);
        self.inner.has_code(address)
    }
    fn storage(&self, address: H160, index: H256) -> H256 {
        self.read(address);
        self.inner.storage(address, index)
    }
    fn is_empty_storage(&self, address: H160) -> bool {
        self.read(address);
        self.inner.is_empty_storage(address)
    }
    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
        self.read(address);
        self.inner.original_storage(address, index)
    }
    fn blob_gas_price(&self) -> Option<u128> {
        self.inner.blob_gas_price()
    }
    fn get_blob_hash(&self, index: usize) -> Option<U256> {
        self.inner.get_blob_hash(index)
    }
}

/// The call of `TARGET` the precompile makes, or `PROBER` makes with the `CALL` opcode.
#[derive(Clone, Copy)]
struct Subcall {
    value: u64,
    input_len: usize,
    /// Gas offered to the callee; `None` offers all the caller may forward.
    gas: Option<u64>,
    is_static: bool,
    /// Make the call twice in one execution of the precompile.
    twice: bool,
}

const fn subcall(value: u64, input_len: usize) -> Subcall {
    Subcall {
        value,
        input_len,
        gas: None,
        is_static: false,
        twice: false,
    }
}

/// A precompile set with one precompile, at `SUBCALLER`, making a subcall.
struct Subcaller {
    call: Subcall,
    fail_after_call: bool,
    target_is_precompile: bool,
}

impl Subcaller {
    const fn new(call: Subcall) -> Self {
        Self {
            call,
            fail_after_call: false,
            target_is_precompile: false,
        }
    }
}

impl PrecompileSet for Subcaller {
    fn execute(&self, handle: &mut impl PrecompileHandle) -> Option<PrecompileResult> {
        if self.target_is_precompile && handle.code_address() == TARGET {
            if let Err(exit_status) = handle.record_cost(TARGET_PRECOMPILE_GAS) {
                return Some(Err(PrecompileFailure::Error { exit_status }));
            }
            return Some(Ok(PrecompileOutput {
                exit_status: ExitSucceed::Stopped,
                output: Vec::new(),
            }));
        }
        if handle.code_address() != SUBCALLER {
            return None;
        }
        let Subcall {
            value,
            input_len,
            gas,
            is_static,
            twice,
        } = self.call;
        let value = U256::from(value);
        let context = Context {
            address: TARGET,
            caller: SUBCALLER,
            apparent_value: value,
        };
        for _ in 0..if twice { 2 } else { 1 } {
            let transfer = (!value.is_zero()).then_some(Transfer {
                source: SUBCALLER,
                target: TARGET,
                value,
            });
            // Like a contract ignoring the result of its `CALL`: the callee's failure leaves
            // the precompile running, the frame's own failure halts it below.
            let _ = handle.call(
                TARGET,
                transfer,
                vec![0; input_len],
                gas,
                is_static,
                &context,
            );
        }
        if self.fail_after_call {
            return Some(Err(PrecompileFailure::Error {
                exit_status: ExitError::OutOfGas,
            }));
        }
        Some(match handle.record_cost(0) {
            Ok(()) => Ok(PrecompileOutput {
                exit_status: ExitSucceed::Stopped,
                output: Vec::new(),
            }),
            Err(exit_status) => Err(PrecompileFailure::Error { exit_status }),
        })
    }

    fn is_precompile(&self, address: H160) -> bool {
        address == SUBCALLER || (self.target_is_precompile && address == TARGET)
    }
}

fn push(code: &mut Vec<u8>, value: u16) {
    code.push(Opcode::PUSH2.as_u8());
    code.extend_from_slice(&value.to_be_bytes());
}

/// `PROBER`'s code: the subcall as a `CALL` opcode reading its input from memory at offset zero.
fn call_opcode(subcall: Subcall) -> Vec<u8> {
    let mut code = Vec::new();
    push(&mut code, 0);
    push(&mut code, 0);
    push(
        &mut code,
        u16::try_from(subcall.input_len).expect("a short input"),
    );
    push(&mut code, 0);
    push(
        &mut code,
        u16::try_from(subcall.value).expect("a small value"),
    );
    code.push(Opcode::PUSH20.as_u8());
    code.extend_from_slice(TARGET.as_bytes());
    let gas = subcall
        .gas
        .map_or(u16::MAX, |gas| u16::try_from(gas).expect("little gas"));
    push(&mut code, gas);
    code.extend_from_slice(&[Opcode::CALL.as_u8(), Opcode::STOP.as_u8()]);
    code
}

/// Appends a call of `to` without value, input or output, offering 0xffff gas, to `code`.
fn push_call(code: &mut Vec<u8>, opcode: Opcode, to: H160) {
    for _ in 0..if opcode == Opcode::CALL { 5 } else { 4 } {
        push(code, 0);
    }
    code.push(Opcode::PUSH20.as_u8());
    code.extend_from_slice(to.as_bytes());
    push(code, u16::MAX);
    code.push(opcode.as_u8());
}

/// Code reverting with no output.
fn revert_code() -> Vec<u8> {
    let mut code = Vec::new();
    push(&mut code, 0);
    push(&mut code, 0);
    code.push(Opcode::REVERT.as_u8());
    code
}

/// The EIP-7702 delegation designator pointing at `to`.
fn designator(to: H160) -> Vec<u8> {
    let mut code = vec![0xef, 0x01, 0x00];
    code.extend_from_slice(to.as_bytes());
    code
}

struct Case {
    name: &'static str,
    config: Config,
    subcall: Subcall,
    /// The target's code, or `None` for an absent account.
    target_code: Option<Vec<u8>>,
    access_list: Vec<(H160, Vec<H256>)>,
    /// Gas left at the subcall its cost before the state access needs: below it, nothing is
    /// read.
    gate: u64,
    /// Gas left at the subcall from which the transaction succeeds: the full cost.
    succeeds_at: u64,
}

impl Case {
    /// A Prague case whose full cost is the gate, on a cold target with the code `STOP`.
    fn new(name: &'static str, subcall: Subcall, gate: u64) -> Self {
        Self {
            name,
            config: Config::prague(),
            subcall,
            target_code: Some(vec![Opcode::STOP.as_u8()]),
            access_list: Vec::new(),
            gate,
            succeeds_at: gate,
        }
    }

    const fn istanbul(mut self) -> Self {
        self.config = Config::istanbul();
        self
    }

    fn warm_target(mut self) -> Self {
        self.access_list = vec![(TARGET, Vec::new())];
        self
    }

    fn target_code(mut self, code: Option<Vec<u8>>) -> Self {
        self.target_code = code;
        self
    }

    const fn succeeds_at(mut self, gas: u64) -> Self {
        self.succeeds_at = gas;
        self
    }

    /// The stipend a callee receiving value hands back unused.
    const fn stipend_back(&self) -> u64 {
        if self.subcall.value == 0 {
            0
        } else {
            CALL_STIPEND
        }
    }

    fn delegates_to(&self, delegate: H160) -> bool {
        self.target_code.as_deref() == Some(designator(delegate).as_slice())
    }
}

fn cases() -> Vec<Case> {
    vec![
        // A cold target without value or input: the access cost is the whole cost.
        Case::new("cold target", subcall(0, 0), 2600),
        // A value transfer adds 9000; the callee hands its 2300 stipend back.
        Case::new("cold target with value", subcall(1, 0), 11_600),
        // Funding an absent account adds 25_000 once the target has been read.
        Case::new("absent target with value", subcall(1, 0), 11_600)
            .target_code(None)
            .succeeds_at(36_600),
        // An access-listed target is warm: 100.
        Case::new("warm target", subcall(0, 0), 100).warm_target(),
        // 100 bytes of input expand the memory the call reads them from by 4 words: 12.
        Case::new("cold target with input", subcall(0, 100), 2612),
        // Gas offered to the callee does not change the charge.
        Case::new(
            "cold target offered gas",
            Subcall {
                gas: Some(1000),
                ..subcall(0, 0)
            },
            2600,
        ),
        // A delegating target (EIP-7702) is read to find its delegate, whose cold access costs
        // another 2600, or 100 when the target delegates to itself.
        Case::new("cold delegating target", subcall(0, 0), 2600)
            .target_code(Some(designator(DELEGATE)))
            .succeeds_at(5200),
        // The self-delegate's code is the designator itself, invalid to run: the callee fails,
        // the caller goes on.
        Case::new("cold self-delegating target", subcall(0, 0), 2600)
            .target_code(Some(designator(TARGET)))
            .succeeds_at(2700),
        // Before EIP-2929 the access part is the 700 of EIP-150.
        Case::new("Istanbul target", subcall(0, 0), 700).istanbul(),
        Case::new("Istanbul target with value", subcall(1, 0), 9700).istanbul(),
    ]
}

/// What a transaction did.
#[derive(Debug)]
struct Outcome {
    reason: ExitReason,
    limit: u64,
    used: u64,
    target_reads: usize,
    delegate_reads: usize,
    /// Every account the backend was asked about.
    read_accounts: BTreeSet<H160>,
    target_is_cold: bool,
    delegate_is_cold: bool,
    target_balance: U256,
}

/// Runs `case` through the precompile with `gas_left` at the subcall.
fn run(case: &Case, gas_left: u64) -> Outcome {
    execute(case, SUBCALLER, Vec::new(), gas_left)
}

/// Runs `case` through `PROBER`, which makes the call with the `CALL` opcode, with `gas_left` at
/// the opcode.
fn run_opcode(case: &Case, gas_left: u64) -> Outcome {
    execute(
        case,
        PROBER,
        call_opcode(case.subcall),
        CALL_PUSH_GAS + gas_left,
    )
}

/// Runs `case` as a transaction to `to`, with `prober_code` deployed at `PROBER` and `frame_gas`
/// left after the intrinsic gas.
fn execute(case: &Case, to: H160, prober_code: Vec<u8>, frame_gas: u64) -> Outcome {
    execute_with_precompiles(
        case,
        to,
        prober_code,
        frame_gas,
        &Subcaller::new(case.subcall),
    )
}

fn execute_with_precompiles(
    case: &Case,
    to: H160,
    prober_code: Vec<u8>,
    frame_gas: u64,
    precompiles: &Subcaller,
) -> Outcome {
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
    let account = |balance: u64, code: Vec<u8>| MemoryAccount {
        nonce: U256::one(),
        balance: U256::from(balance),
        storage: BTreeMap::new(),
        code,
    };
    let mut accounts = BTreeMap::from([
        (CALLER, account(1_000_000, Vec::new())),
        (SUBCALLER, account(1000, Vec::new())),
        (PROBER, account(1000, prober_code)),
        (DELEGATE, account(0, vec![Opcode::STOP.as_u8()])),
    ]);
    if let Some(code) = &case.target_code {
        accounts.insert(TARGET, account(0, code.clone()));
    }
    let backend = ReadProbe {
        inner: MemoryBackend::new(&vicinity, accounts),
        reads: RefCell::default(),
    };
    let access_list_gas = ACCESS_LIST_ADDRESS_GAS
        * u64::try_from(case.access_list.len()).expect("a short access list");
    let limit = INTRINSIC_GAS + access_list_gas + frame_gas;
    let state = MemoryStackState::new(StackSubstateMetadata::new(limit, &case.config), &backend);
    let mut executor = StackExecutor::new_with_precompiles(state, &case.config, precompiles);
    let (reason, _) = executor.transact_call(
        CALLER,
        to,
        U256::zero(),
        Vec::new(),
        limit,
        case.access_list.clone(),
        Vec::new(),
    );
    let used = executor.used_gas();
    let state = executor.into_state();
    let read_accounts = backend.reads.borrow().keys().copied().collect();
    Outcome {
        reason,
        limit,
        used,
        target_reads: backend.reads_of(TARGET),
        delegate_reads: backend.reads_of(DELEGATE),
        read_accounts,
        target_is_cold: state.is_cold(TARGET),
        delegate_is_cold: state.is_cold(DELEGATE),
        target_balance: state.basic(TARGET).balance,
    }
}

#[test]
fn unaffordable_subcall_halts_before_reading_the_target() {
    let out_of_gas = ExitReason::Error(ExitError::OutOfGas);
    for case in cases() {
        let short = run(&case, case.gate - 1);
        assert_eq!(short.reason, out_of_gas, "{}", case.name);
        assert_eq!(
            short.used, short.limit,
            "{}: all gas is consumed",
            case.name
        );
        assert_eq!(
            (short.target_reads, short.delegate_reads),
            (0, 0),
            "{}: state read before the check",
            case.name
        );
        // The transaction read its sender and the precompile's account, nothing else.
        assert_eq!(
            short.read_accounts,
            BTreeSet::from([CALLER, SUBCALLER]),
            "{}",
            case.name
        );

        if case.succeeds_at > case.gate {
            // Past the check the target is read, but not the delegate it names.
            let short = run(&case, case.succeeds_at - 1);
            assert_eq!(short.reason, out_of_gas, "{}", case.name);
            assert!(
                short.target_reads > 0,
                "{}: the target was not read",
                case.name
            );
            assert_eq!(
                short.delegate_reads, 0,
                "{}: delegate read before its charge",
                case.name
            );
        }
    }
}

#[test]
fn affordable_subcall_reads_the_target_and_warms_it() {
    for case in cases() {
        let at_gate = run(&case, case.gate);
        assert!(
            at_gate.target_reads > 0,
            "{}: the check passed without a read",
            case.name
        );

        let success = run(&case, case.succeeds_at);
        assert!(
            success.reason.is_succeed(),
            "{}: {:?}",
            case.name,
            success.reason
        );
        assert_eq!(
            success.used,
            success.limit - case.stipend_back(),
            "{}",
            case.name
        );
        if case.config.increase_state_access_gas {
            assert!(
                !success.target_is_cold,
                "{}: the target stays cold",
                case.name
            );
            assert_eq!(
                success.delegate_is_cold,
                !case.delegates_to(DELEGATE),
                "{}: the delegate's warmth",
                case.name
            );
        }
    }
}

/// The precompile's subcall charges what the `CALL` opcode charges for the same call, and
/// leaves the same accounts warm.
#[test]
fn subcall_is_priced_as_the_call_opcode() {
    for case in cases() {
        let through_precompile = run(&case, 60_000);
        let through_opcode = run_opcode(&case, 60_000);
        assert!(
            through_precompile.reason.is_succeed() && through_opcode.reason.is_succeed(),
            "{}: {:?} / {:?}",
            case.name,
            through_precompile.reason,
            through_opcode.reason
        );
        assert_eq!(
            through_precompile.used,
            through_opcode.used - CALL_PUSH_GAS,
            "{}",
            case.name
        );
        assert_eq!(
            (
                through_precompile.target_is_cold,
                through_precompile.delegate_is_cold
            ),
            (
                through_opcode.target_is_cold,
                through_opcode.delegate_is_cold
            ),
            "{}",
            case.name
        );
    }
}

/// The target the precompile called is warm for the rest of the transaction: a `CALL` opcode
/// to it afterwards pays 100, where a `CALL` to an untouched account pays 2600.
#[test]
fn subcall_warms_the_target_for_the_following_opcode() {
    let case = Case::new("subcall then CALL", subcall(0, 0), 2600);
    let after_subcall = |second: H160| {
        let mut code = Vec::new();
        push_call(&mut code, Opcode::CALL, SUBCALLER);
        push_call(&mut code, Opcode::CALL, second);
        code.push(Opcode::STOP.as_u8());
        execute(&case, PROBER, code, 60_000)
    };
    let to_target = after_subcall(TARGET);
    let to_cold = after_subcall(DELEGATE);
    assert!(to_target.reason.is_succeed(), "{:?}", to_target.reason);
    assert!(to_cold.reason.is_succeed(), "{:?}", to_cold.reason);
    assert_eq!(to_cold.used - to_target.used, 2500);
}

/// A second subcall to the same target in one execution of the precompile pays the warm price,
/// and the input's memory is paid once per frame.
#[test]
fn second_subcall_in_one_execution_is_warm() {
    let case = Case::new(
        "two subcalls",
        Subcall {
            twice: true,
            ..subcall(0, 100)
        },
        2612,
    );
    let outcome = run(&case, 60_000);
    assert!(outcome.reason.is_succeed(), "{:?}", outcome.reason);
    assert_eq!(outcome.used, INTRINSIC_GAS + 2612 + 100);
}

/// A static subcall is priced as the call, and warms its target.
#[test]
fn static_subcall_is_priced_as_the_call() {
    let case = Case::new(
        "static subcall",
        Subcall {
            is_static: true,
            ..subcall(0, 0)
        },
        2600,
    );
    let outcome = run(&case, 60_000);
    assert!(outcome.reason.is_succeed(), "{:?}", outcome.reason);
    assert_eq!(outcome.used, INTRINSIC_GAS + 2600);
    assert!(!outcome.target_is_cold);
}

/// A callee's revert leaves the target warm, as after a `CALL` opcode.
#[test]
fn reverting_callee_leaves_the_target_warm() {
    let case = Case::new("reverting target", subcall(0, 0), 2600).target_code(Some(revert_code()));
    let through_precompile = run(&case, 60_000);
    let through_opcode = run_opcode(&case, 60_000);
    assert!(
        through_precompile.reason.is_succeed(),
        "{:?}",
        through_precompile.reason
    );
    assert!(!through_precompile.target_is_cold);
    assert_eq!(through_precompile.used, through_opcode.used - CALL_PUSH_GAS);
}

/// A precompile in a static frame cannot transfer value: the subcall fails before any state
/// access, the frame's gas is consumed, and the target is untouched.
#[test]
fn static_frame_transfers_no_value() {
    let case = Case::new("value from a static frame", subcall(1, 0), 11_600);
    let mut code = Vec::new();
    push_call(&mut code, Opcode::STATICCALL, SUBCALLER);
    code.push(Opcode::STOP.as_u8());
    let outcome = execute(&case, PROBER, code, 60_000);
    // The prober goes on after its failed `STATICCALL`.
    assert!(outcome.reason.is_succeed(), "{:?}", outcome.reason);
    assert_eq!(outcome.target_balance, U256::zero());
    assert_eq!(outcome.target_reads, 0, "the target was read");
    assert!(outcome.target_is_cold, "the failed frame warmed the target");
    // The precompile's frame burned the gas offered to it: all but a 64th of what was left.
    let offered = 60_000 - 6 * PUSH_GAS - 100;
    assert_eq!(
        outcome.used,
        INTRINSIC_GAS + 6 * PUSH_GAS + 100 + (offered - offered / 64)
    );
}

#[test]
fn failed_precompile_discards_subcall_transfer_and_warmth() {
    let case = Case::new("failed precompile", subcall(1, 0), 11_600);
    let outcome = execute_with_precompiles(
        &case,
        SUBCALLER,
        Vec::new(),
        60_000,
        &Subcaller {
            fail_after_call: true,
            ..Subcaller::new(case.subcall)
        },
    );
    assert_eq!(outcome.reason, ExitReason::Error(ExitError::OutOfGas));
    assert_eq!(outcome.used, outcome.limit);
    assert!(outcome.target_reads > 0);
    assert!(outcome.target_is_cold);
    assert_eq!(outcome.target_balance, U256::zero());
}

#[test]
fn subcall_to_another_precompile_pays_warm_access() {
    let case = Case::new("another precompile", subcall(0, 0), 100);
    let outcome = execute_with_precompiles(
        &case,
        SUBCALLER,
        Vec::new(),
        60_000,
        &Subcaller {
            target_is_precompile: true,
            ..Subcaller::new(case.subcall)
        },
    );
    assert!(outcome.reason.is_succeed(), "{:?}", outcome.reason);
    assert_eq!(outcome.used, INTRINSIC_GAS + 100 + TARGET_PRECOMPILE_GAS);
}

#[test]
fn frontier_subcall_forwards_available_gas_and_checks_explicit_limits() {
    let mut case = Case::new("Frontier", subcall(0, 0), 40).target_code(Some(vec![
        Opcode::PUSH1.as_u8(),
        0,
        Opcode::STOP.as_u8(),
    ]));
    case.config = Config::frontier();
    // With no explicit limit, the callee receives the three gas left after the CALL cost.
    let available = run(&case, 43);
    assert!(available.reason.is_succeed(), "{:?}", available.reason);
    assert_eq!(available.used, INTRINSIC_GAS + 43);

    case.subcall.gas = Some(100);
    let exact = run(&case, 140);
    let opcode = run_opcode(&case, 140);
    assert!(exact.reason.is_succeed());
    assert_eq!(exact.used, INTRINSIC_GAS + 43);
    assert_eq!(exact.used, opcode.used - CALL_PUSH_GAS);

    case.subcall.gas = Some(101);
    let excessive = run(&case, 140);
    let opcode = run_opcode(&case, 140);
    assert_eq!(excessive.reason, ExitReason::Error(ExitError::OutOfGas));
    assert_eq!(excessive.used, excessive.limit);
    assert_eq!(excessive.reason, opcode.reason);
    assert_eq!(excessive.used, opcode.used - CALL_PUSH_GAS);
}
