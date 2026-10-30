//! The gas an opcode owes before its first state access is checked before that access
//! (Yellow Paper Appendix H.2, EIP-2200, EIP-2929, EIP-7702).
//!
//! One gas short of it, the opcode halts with `OutOfGas` and the backend is never asked for
//! the account or the slot the opcode targets. At it, the opcode reads state, and the
//! transaction completes once the full cost is affordable. So the check is exact: the whole
//! cost known before the access, and nothing beyond it.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use aurora_evm::backend::{Backend, Basic, MemoryAccount, MemoryBackend, MemoryVicinity};
use aurora_evm::executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata};
use aurora_evm::{Config, ExitError, ExitReason, Opcode};
use primitive_types::{H160, H256, U256};

const CALLER: H160 = H160([0xca; 20]);
const PROBER: H160 = H160([0xc1; 20]);
const TARGET: H160 = H160([0xc2; 20]);
const DELEGATE: H160 = H160([0xd1; 20]);
const INTRINSIC_GAS: u64 = 21_000;
const ACCESS_LIST_ADDRESS_GAS: u64 = 2400;
const PUSH_GAS: u64 = 3;

/// A `MemoryBackend` counting the reads of every account and of storage.
struct ReadProbe<'a> {
    inner: MemoryBackend<'a>,
    account_reads: RefCell<BTreeMap<H160, usize>>,
    storage_reads: Cell<usize>,
}

impl ReadProbe<'_> {
    fn read(&self, address: H160) {
        *self.account_reads.borrow_mut().entry(address).or_default() += 1;
    }

    fn read_storage(&self, address: H160) {
        self.read(address);
        self.storage_reads.set(self.storage_reads.get() + 1);
    }

    fn reads_of(&self, address: H160) -> usize {
        self.account_reads
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
        self.read_storage(address);
        self.inner.storage(address, index)
    }
    fn is_empty_storage(&self, address: H160) -> bool {
        self.read(address);
        self.inner.is_empty_storage(address)
    }
    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
        self.read_storage(address);
        self.inner.original_storage(address, index)
    }
    fn blob_gas_price(&self) -> Option<u128> {
        self.inner.blob_gas_price()
    }
    fn get_blob_hash(&self, index: usize) -> Option<U256> {
        self.inner.get_blob_hash(index)
    }
}

/// The prober's code: pushes, the probed opcode and `STOP`, with the gas the pushes cost.
struct Probe {
    code: Vec<u8>,
    push_gas: u64,
}

impl Probe {
    const fn new() -> Self {
        Self {
            code: Vec::new(),
            push_gas: 0,
        }
    }

    fn push(mut self, value: u16) -> Self {
        self.code.push(Opcode::PUSH2.as_u8());
        self.code.extend_from_slice(&value.to_be_bytes());
        self.push_gas += PUSH_GAS;
        self
    }

    fn push_address(mut self, address: H160) -> Self {
        self.code.push(Opcode::PUSH20.as_u8());
        self.code.extend_from_slice(address.as_bytes());
        self.push_gas += PUSH_GAS;
        self
    }

    fn then(mut self, opcode: Opcode) -> Self {
        self.code
            .extend_from_slice(&[opcode.as_u8(), Opcode::STOP.as_u8()]);
        self
    }
}

/// A CALL-family opcode on `TARGET` forwarding no gas, with a `value` for `CALL` and
/// `CALLCODE`, and `ret_len` bytes of output expanding memory.
fn call_family(opcode: Opcode, value: Option<u16>, ret_len: u16) -> Probe {
    let mut probe = Probe::new().push(ret_len).push(0).push(0).push(0);
    if let Some(value) = value {
        probe = probe.push(value);
    }
    probe.push_address(TARGET).push(0).then(opcode)
}

fn call(value: u16, ret_len: u16) -> Probe {
    call_family(Opcode::CALL, Some(value), ret_len)
}

fn callcode(value: u16, ret_len: u16) -> Probe {
    call_family(Opcode::CALLCODE, Some(value), ret_len)
}

fn delegatecall(ret_len: u16) -> Probe {
    call_family(Opcode::DELEGATECALL, None, ret_len)
}

fn staticcall(ret_len: u16) -> Probe {
    call_family(Opcode::STATICCALL, None, ret_len)
}

/// `SELFDESTRUCT` with `TARGET` as the beneficiary.
fn selfdestruct() -> Probe {
    Probe::new().push_address(TARGET).then(Opcode::SELFDESTRUCT)
}

/// `SSTORE` of zero into the prober's zero slot 0: a no-op store into a cold slot.
fn sstore() -> Probe {
    Probe::new().push(0).push(0).then(Opcode::SSTORE)
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
    probe: Probe,
    target_code: Vec<u8>,
    access_list: Vec<(H160, Vec<H256>)>,
    /// Gas left at the opcode its cost before the state access needs: below it, nothing is
    /// read.
    gate: u64,
    /// Gas left at the opcode from which the transaction succeeds: the full cost.
    succeeds_at: u64,
    /// Gas not used when the transaction runs with exactly `succeeds_at` at the opcode: handed
    /// back by the callee, demanded by the check beyond the cost, or refunded.
    left: u64,
}

impl Case {
    /// A Prague case whose full cost is the gate, on a cold target with the code `STOP`.
    fn new(name: &'static str, probe: Probe, gate: u64) -> Self {
        Self {
            name,
            config: Config::prague(),
            probe,
            target_code: vec![Opcode::STOP.as_u8()],
            access_list: Vec::new(),
            gate,
            succeeds_at: gate,
            left: 0,
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

    fn target_code(mut self, code: Vec<u8>) -> Self {
        self.target_code = code;
        self
    }

    const fn succeeds_at(mut self, gas: u64) -> Self {
        self.succeeds_at = gas;
        self
    }

    const fn left(mut self, gas: u64) -> Self {
        self.left = gas;
        self
    }
}

fn cases() -> Vec<Case> {
    vec![
        // A cold target without value or memory: the access cost is the whole cost.
        Case::new("cold STATICCALL", staticcall(0), 2600),
        Case::new("cold DELEGATECALL", delegatecall(0), 2600),
        Case::new("cold CALLCODE without value", callcode(0, 0), 2600),
        Case::new("cold CALL without value", call(0, 0), 2600),
        // A value transfer adds 9000; the callee hands its 2300 stipend back.
        Case::new("cold CALL with value", call(1, 0), 11_600).left(2300),
        Case::new("cold CALLCODE with value", callcode(1, 0), 11_600).left(2300),
        // An access-listed target is warm: 100.
        Case::new("warm STATICCALL", staticcall(0), 100).warm_target(),
        Case::new("warm CALL with value", call(1, 0), 9100)
            .left(2300)
            .warm_target(),
        // Returning 1024 bytes expands memory by 32 words: 98.
        Case::new("cold STATICCALL with memory", staticcall(1024), 2698),
        Case::new("cold DELEGATECALL with memory", delegatecall(1024), 2698),
        Case::new("cold CALL with value and memory", call(1, 1024), 11_698).left(2300),
        Case::new(
            "cold CALLCODE with value and memory",
            callcode(1, 1024),
            11_698,
        )
        .left(2300),
        // A delegating target (EIP-7702) is read to find its delegate, whose cold access costs
        // another 2600, or 100 when the target delegates to itself.
        Case::new("cold STATICCALL to a cold delegate", staticcall(0), 2600)
            .target_code(designator(DELEGATE))
            .succeeds_at(5200),
        Case::new("cold STATICCALL to a self-delegate", staticcall(0), 2600)
            .target_code(designator(TARGET))
            .succeeds_at(2700),
        // SELFDESTRUCT costs 5000, plus 2600 for a cold beneficiary.
        Case::new("SELFDESTRUCT to a cold beneficiary", selfdestruct(), 7600),
        Case::new("SELFDESTRUCT to a warm beneficiary", selfdestruct(), 5000).warm_target(),
        // SSTORE needs more than the 2300 stipend (EIP-2200); the no-op store then costs 2100
        // for the cold slot and 100.
        Case::new("SSTORE into a cold slot", sstore(), 2301).left(101),
        // Before EIP-2929 the access part is the 700 of EIP-150, and the no-op store 800.
        Case::new("Istanbul STATICCALL", staticcall(0), 700).istanbul(),
        Case::new("Istanbul CALL with value", call(1, 0), 9700)
            .left(2300)
            .istanbul(),
        // Before EIP-3529, SELFDESTRUCT refunds 24_000, capped at half of the gas used.
        Case::new("Istanbul SELFDESTRUCT", selfdestruct(), 5000)
            .left(13_001)
            .istanbul(),
        Case::new("Istanbul SSTORE", sstore(), 2301)
            .left(1501)
            .istanbul(),
    ]
}

/// What a transaction did, run with `gas_left` at its probed opcode.
#[derive(Debug)]
struct Outcome {
    reason: ExitReason,
    limit: u64,
    used: u64,
    /// Backend reads of the target account and of storage.
    reads: usize,
    delegate_reads: usize,
}

fn run(case: &Case, gas_left: u64) -> Outcome {
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
    let backend = ReadProbe {
        inner: MemoryBackend::new(
            &vicinity,
            BTreeMap::from([
                (CALLER, account(1_000_000, Vec::new())),
                (PROBER, account(1, case.probe.code.clone())),
                (TARGET, account(0, case.target_code.clone())),
                (DELEGATE, account(0, vec![Opcode::STOP.as_u8()])),
            ]),
        ),
        account_reads: RefCell::default(),
        storage_reads: Cell::new(0),
    };
    let access_list_gas = ACCESS_LIST_ADDRESS_GAS
        * u64::try_from(case.access_list.len()).expect("a short access list");
    let limit = INTRINSIC_GAS + access_list_gas + case.probe.push_gas + gas_left;
    let state = MemoryStackState::new(StackSubstateMetadata::new(limit, &case.config), &backend);
    let mut executor = StackExecutor::new_with_precompiles(state, &case.config, &());
    let (reason, _) = executor.transact_call(
        CALLER,
        PROBER,
        U256::zero(),
        Vec::new(),
        limit,
        case.access_list.clone(),
        Vec::new(),
    );
    Outcome {
        reason,
        limit,
        used: executor.used_gas(),
        reads: backend.reads_of(TARGET) + backend.storage_reads.get(),
        delegate_reads: backend.reads_of(DELEGATE),
    }
}

#[test]
fn unaffordable_state_access_halts_before_any_backend_read() {
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
            (short.reads, short.delegate_reads),
            (0, 0),
            "{}: state read before the check",
            case.name
        );

        if case.succeeds_at > case.gate {
            // Past the check the target is read, but not the delegate it names.
            let short = run(&case, case.succeeds_at - 1);
            assert_eq!(short.reason, out_of_gas, "{}", case.name);
            assert!(short.reads > 0, "{}: the target was not read", case.name);
            assert_eq!(
                short.delegate_reads, 0,
                "{}: delegate read before its charge",
                case.name
            );
        }
    }
}

#[test]
fn affordable_state_access_reads_state_and_charges_the_full_cost() {
    for case in cases() {
        let at_gate = run(&case, case.gate);
        assert!(
            at_gate.reads > 0,
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
        assert_eq!(success.used, success.limit - case.left, "{}", case.name);
    }
}

/// With the `tracing` feature, the step rejected by the check still reports its gas.
#[cfg(feature = "tracing")]
mod traced {
    use super::*;
    use aurora_evm::gasometer::tracing::{using, Event, EventListener};

    /// The `RecordDynamicCost` events of a transaction: the gas cost with the memory expansion
    /// of each dynamic step, and the gas the step had.
    #[derive(Default)]
    struct DynamicCosts(Vec<(u64, u64)>);

    impl EventListener for DynamicCosts {
        fn event(&mut self, event: Event) {
            if let Event::RecordDynamicCost {
                gas_cost,
                memory_gas,
                snapshot,
                ..
            } = event
            {
                let snapshot = snapshot.expect("the gasometer of a running step is live");
                self.0.push((gas_cost + memory_gas, snapshot.gas()));
            }
        }
    }

    /// The probed opcode is the only dynamic step. One gas short of its check, its event
    /// carries the checked gas and the gas it had, so a trace shows the rejected step with
    /// its own numbers rather than those of the step before.
    #[test]
    fn rejected_state_access_reports_the_checked_gas() {
        let out_of_gas = ExitReason::Error(ExitError::OutOfGas);
        for case in cases() {
            let mut costs = DynamicCosts::default();
            let short = using(&mut costs, || run(&case, case.gate - 1));
            assert_eq!(short.reason, out_of_gas, "{}", case.name);
            assert_eq!(costs.0, [(case.gate, case.gate - 1)], "{}", case.name);

            if case.succeeds_at > case.gate {
                // Rejected at the full cost instead, the step reports that cost.
                let mut costs = DynamicCosts::default();
                let short = using(&mut costs, || run(&case, case.succeeds_at - 1));
                assert_eq!(short.reason, out_of_gas, "{}", case.name);
                assert_eq!(
                    costs.0,
                    [(case.succeeds_at, case.succeeds_at - 1)],
                    "{}",
                    case.name
                );
            }
        }
    }
}
