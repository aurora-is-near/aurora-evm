//! Runtime layer for EVM.

#[cfg(not(feature = "std"))]
pub mod prelude {
    pub use alloc::{rc::Rc, vec::Vec};
}
#[cfg(feature = "std")]
pub mod prelude {
    pub use std::{rc::Rc, vec::Vec};
}

#[cfg(feature = "tracing")]
pub mod tracing;

#[cfg(feature = "tracing")]
macro_rules! event {
    ($x:expr) => {
        use crate::runtime::tracing::Event::*;
        crate::runtime::tracing::with(|listener| listener.event($x));
    };
}

#[cfg(not(feature = "tracing"))]
macro_rules! event {
    ($x:expr) => {};
}

mod context;
mod eval;
mod handler;
mod interrupt;

pub use crate::core::*;

pub use self::context::{CallScheme, Context, CreateScheme};
pub use self::handler::{Handler, Transfer};
pub use self::interrupt::{Resolve, ResolveCall, ResolveCreate};

use prelude::*;
use primitive_types::H160;

/// EVM runtime.
///
/// The runtime wraps an EVM `Machine` with support of return data and context.
pub struct Runtime {
    machine: Machine,
    return_data_buffer: Vec<u8>,
    return_data_len: usize,
    return_data_offset: usize,
    context: Context,
}

impl Runtime {
    /// Create a new runtime with given code and data.
    #[must_use]
    pub fn new(
        code: Rc<Vec<u8>>,
        data: Rc<Vec<u8>>,
        context: Context,
        stack_limit: usize,
        memory_limit: usize,
    ) -> Self {
        Self {
            machine: Machine::new(code, data, stack_limit, memory_limit),
            return_data_buffer: Vec::new(),
            return_data_len: 0,
            return_data_offset: 0,
            context,
        }
    }

    /// Get a reference to the machine.
    #[must_use]
    pub const fn machine(&self) -> &Machine {
        &self.machine
    }

    /// Get a reference to the execution context.
    #[must_use]
    pub const fn context(&self) -> &Context {
        &self.context
    }

    /// Loop stepping the runtime until it stops.
    pub fn run<H: Handler + InterpreterHandler>(
        &mut self,
        handler: &mut H,
    ) -> Capture<ExitReason, Resolve<H>> {
        loop {
            let result = self.machine.step(handler, &self.context.address);
            match result {
                Ok(()) => (),
                Err(Capture::Exit(e)) => {
                    return Capture::Exit(e);
                }
                Err(Capture::Trap(opcode)) => match eval::eval(self, opcode, handler) {
                    eval::Control::Continue => (),
                    eval::Control::CallInterrupt(interrupt) => {
                        let resolve = ResolveCall::new(self);
                        return Capture::Trap(Resolve::Call(interrupt, resolve));
                    }
                    eval::Control::CreateInterrupt(interrupt) => {
                        let resolve = ResolveCreate::new(self);
                        return Capture::Trap(Resolve::Create(interrupt, resolve));
                    }
                    eval::Control::Exit(exit) => {
                        self.machine.exit(exit.clone());
                        return Capture::Exit(exit);
                    }
                },
            }
        }
    }

    /// # Errors
    /// Return `ExitReason`
    pub fn finish_create(
        &mut self,
        reason: ExitReason,
        address: Option<H160>,
        return_data: Vec<u8>,
    ) -> Result<(), ExitReason> {
        eval::finish_create(self, reason, address, return_data)
    }

    /// # Errors
    /// Return `ExitReason`
    pub fn finish_call(
        &mut self,
        reason: ExitReason,
        return_data: Vec<u8>,
    ) -> Result<(), ExitReason> {
        eval::finish_call(
            self,
            self.return_data_len,
            self.return_data_offset,
            reason,
            return_data,
        )
    }
}

/// Runtime configuration.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug)]
pub struct Config {
    /// Gas paid for extcode.
    pub gas_ext_code: u64,
    /// Gas paid for extcodehash.
    pub gas_ext_code_hash: u64,
    /// Gas paid for sstore set.
    pub gas_sstore_set: u64,
    /// Gas paid for sstore reset.
    pub gas_sstore_reset: u64,
    /// Gas paid for sstore refund.
    pub refund_sstore_clears: i64,
    /// EIP-3529
    pub max_refund_quotient: u64,
    /// Gas paid for BALANCE opcode.
    pub gas_balance: u64,
    /// Gas paid for SLOAD opcode.
    pub gas_sload: u64,
    /// Gas paid for cold SLOAD opcode.
    pub gas_sload_cold: u64,
    /// Gas paid for SUICIDE opcode.
    pub gas_suicide: u64,
    /// Gas paid for SUICIDE opcode when it hits a new account.
    pub gas_suicide_new_account: u64,
    /// Gas paid for CALL opcode.
    pub gas_call: u64,
    /// Gas paid for EXP opcode for every byte.
    pub gas_expbyte: u64,
    /// Gas paid for a contract creation transaction.
    pub gas_transaction_create: u64,
    /// Gas paid for a message call transaction.
    pub gas_transaction_call: u64,
    /// Gas paid for zero data in a transaction.
    pub gas_transaction_zero_data: u64,
    /// Gas paid for non-zero data in a transaction.
    pub gas_transaction_non_zero_data: u64,
    /// Gas paid per address in transaction access list (see EIP-2930).
    pub gas_access_list_address: u64,
    /// Gas paid per storage key in transaction access list (see EIP-2930).
    pub gas_access_list_storage_key: u64,
    /// Gas paid for accessing cold account.
    pub gas_account_access_cold: u64,
    /// Gas paid for accessing ready storage.
    pub gas_storage_read_warm: u64,
    /// EIP-1283.
    pub sstore_gas_metering: bool,
    /// EIP-1706.
    pub sstore_revert_under_stipend: bool,
    /// EIP-2929
    pub increase_state_access_gas: bool,
    /// EIP-3529
    pub decrease_clears_refund: bool,
    /// EIP-3541
    pub disallow_executable_format: bool,
    /// EIP-3651
    pub warm_coinbase_address: bool,
    /// Whether to throw out of gas error when
    /// CALL/CALLCODE/DELEGATECALL requires more than maximum amount
    /// of gas.
    pub err_on_call_with_more_gas: bool,
    /// Take l64 for callcreate after gas.
    pub call_l64_after_gas: bool,
    /// Whether empty account is considered exists.
    pub empty_considered_exists: bool,
    /// Whether create transactions and create opcode increases nonce by one.
    pub create_increase_nonce: bool,
    /// Stack limit.
    pub stack_limit: usize,
    /// Memory limit.
    pub memory_limit: usize,
    /// Call limit.
    pub call_stack_limit: usize,
    /// Create contract limit.
    pub create_contract_limit: Option<usize>,
    /// EIP-3860, maximum size limit of `init_code`.
    pub max_initcode_size: Option<usize>,
    /// Call stipend.
    pub call_stipend: u64,
    /// Has delegate call.
    pub has_delegate_call: bool,
    /// Has create2.
    pub has_create2: bool,
    /// Has revert.
    pub has_revert: bool,
    /// Has return data.
    pub has_return_data: bool,
    /// Has bitwise shifting.
    pub has_bitwise_shifting: bool,
    /// Has chain ID.
    pub has_chain_id: bool,
    /// Has self balance.
    pub has_self_balance: bool,
    /// Has ext code hash.
    pub has_ext_code_hash: bool,
    /// Has ext block fee. See [EIP-3198](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3198.md)
    pub has_base_fee: bool,
    /// Has PUSH0 opcode. See [EIP-3855](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3855.md)
    pub has_push0: bool,
    /// Whether the gasometer is running in estimate mode.
    pub estimate: bool,
    /// Has BLOBBASEFEE. See [EIP-7516](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7516.md)
    pub has_blob_base_fee: bool,
    /// Has Shard Blob Transactions. See [EIP-4844](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md)
    pub has_shard_blob_transactions: bool,
    /// Has Transient storage. See [EIP-1153](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1153.md)
    pub has_transient_storage: bool,
    /// Has MCOPY - Memory copying instruction. See [EIP-5656](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-5656.md)
    pub has_mcopy: bool,
    /// SELFDESTRUCT restriction: EIP-6780
    pub has_restricted_selfdestruct: bool,
    /// EIP-7702
    pub has_authorization_list: bool,
    /// EIP-7702
    pub gas_per_empty_account_cost: u64,
    /// EIP-7702
    pub gas_per_auth_base_cost: u64,
    /// EIP-7623
    pub has_floor_gas: bool,
    /// EIP-7623
    pub total_cost_floor_per_token: u64,
}

impl Config {
    /// Frontier hard fork configuration.
    #[must_use]
    pub const fn frontier() -> Self {
        Self {
            gas_ext_code: 20,
            gas_ext_code_hash: 20,
            gas_balance: 20,
            gas_sload: 50,
            gas_sload_cold: 0,
            gas_sstore_set: 20000,
            gas_sstore_reset: 5000,
            refund_sstore_clears: 15000,
            max_refund_quotient: 2,
            gas_suicide: 0,
            gas_suicide_new_account: 0,
            gas_call: 40,
            gas_expbyte: 10,
            gas_transaction_create: 21000,
            gas_transaction_call: 21000,
            gas_transaction_zero_data: 4,
            gas_transaction_non_zero_data: 68,
            gas_access_list_address: 0,
            gas_access_list_storage_key: 0,
            gas_account_access_cold: 0,
            gas_storage_read_warm: 0,
            sstore_gas_metering: false,
            sstore_revert_under_stipend: false,
            increase_state_access_gas: false,
            decrease_clears_refund: false,
            disallow_executable_format: false,
            warm_coinbase_address: false,
            err_on_call_with_more_gas: true,
            empty_considered_exists: true,
            create_increase_nonce: false,
            call_l64_after_gas: false,
            stack_limit: 1024,
            memory_limit: usize::MAX,
            call_stack_limit: 1024,
            create_contract_limit: None,
            max_initcode_size: None,
            call_stipend: 2300,
            has_delegate_call: false,
            has_create2: false,
            has_revert: false,
            has_return_data: false,
            has_bitwise_shifting: false,
            has_chain_id: false,
            has_self_balance: false,
            has_ext_code_hash: false,
            has_base_fee: false,
            has_push0: false,
            estimate: false,
            has_blob_base_fee: false,
            has_shard_blob_transactions: false,
            has_transient_storage: false,
            has_mcopy: false,
            has_restricted_selfdestruct: false,
            has_authorization_list: false,
            gas_per_empty_account_cost: 0,
            gas_per_auth_base_cost: 0,
            has_floor_gas: false,
            total_cost_floor_per_token: 0,
        }
    }

    /// Istanbul hard fork configuration.
    #[must_use]
    pub const fn istanbul() -> Self {
        Self {
            gas_ext_code: 700,
            gas_ext_code_hash: 700,
            gas_balance: 700,
            gas_sload: 800,
            gas_sload_cold: 0,
            gas_sstore_set: 20000,
            gas_sstore_reset: 5000,
            refund_sstore_clears: 15000,
            max_refund_quotient: 2,
            gas_suicide: 5000,
            gas_suicide_new_account: 25000,
            gas_call: 700,
            gas_expbyte: 50,
            gas_transaction_create: 53000,
            gas_transaction_call: 21000,
            gas_transaction_zero_data: 4,
            gas_transaction_non_zero_data: 16,
            gas_access_list_address: 0,
            gas_access_list_storage_key: 0,
            gas_account_access_cold: 0,
            gas_storage_read_warm: 0,
            sstore_gas_metering: true,
            sstore_revert_under_stipend: true,
            increase_state_access_gas: false,
            decrease_clears_refund: false,
            disallow_executable_format: false,
            warm_coinbase_address: false,
            err_on_call_with_more_gas: false,
            empty_considered_exists: false,
            create_increase_nonce: true,
            call_l64_after_gas: true,
            stack_limit: 1024,
            memory_limit: usize::MAX,
            call_stack_limit: 1024,
            create_contract_limit: Some(0x6000),
            max_initcode_size: None,
            call_stipend: 2300,
            has_delegate_call: true,
            has_create2: true,
            has_revert: true,
            has_return_data: true,
            has_bitwise_shifting: true,
            has_chain_id: true,
            has_self_balance: true,
            has_ext_code_hash: true,
            has_base_fee: false,
            has_push0: false,
            estimate: false,
            has_blob_base_fee: false,
            has_shard_blob_transactions: false,
            has_transient_storage: false,
            has_mcopy: false,
            has_restricted_selfdestruct: false,
            has_authorization_list: false,
            gas_per_auth_base_cost: 0,
            gas_per_empty_account_cost: 0,
            has_floor_gas: false,
            total_cost_floor_per_token: 0,
        }
    }

    /// Berlin hard fork configuration.
    #[must_use]
    pub const fn berlin() -> Self {
        Self::config_with_derived_values(DerivedConfigInputs::berlin())
    }

    /// london hard fork configuration.
    #[must_use]
    pub const fn london() -> Self {
        Self::config_with_derived_values(DerivedConfigInputs::london())
    }

    /// The Merge (Paris) hard fork configuration.
    #[must_use]
    pub const fn merge() -> Self {
        Self::config_with_derived_values(DerivedConfigInputs::merge())
    }

    /// Shanghai hard fork configuration.
    #[must_use]
    pub const fn shanghai() -> Self {
        Self::config_with_derived_values(DerivedConfigInputs::shanghai())
    }

    /// Cancun hard fork configuration.
    #[must_use]
    pub const fn cancun() -> Self {
        Self::config_with_derived_values(DerivedConfigInputs::cancun())
    }

    /// Prague hard fork configuration.
    #[must_use]
    pub const fn prague() -> Self {
        Self::config_with_derived_values(DerivedConfigInputs::prague())
    }

    const fn config_with_derived_values(inputs: DerivedConfigInputs) -> Self {
        let DerivedConfigInputs {
            gas_storage_read_warm,
            gas_sload_cold,
            gas_access_list_storage_key,
            decrease_clears_refund,
            has_base_fee,
            has_push0,
            disallow_executable_format,
            warm_coinbase_address,
            max_initcode_size,
            has_blob_base_fee,
            has_shard_blob_transactions,
            has_transient_storage,
            has_mcopy,
            has_restricted_selfdestruct,
            has_authorization_list,
            gas_per_empty_account_cost,
            gas_per_auth_base_cost,
            has_floor_gas,
            total_cost_floor_per_token,
        } = inputs;

        // See https://eips.ethereum.org/EIPS/eip-2929
        let gas_sload = gas_storage_read_warm;
        let gas_sstore_reset = 5000 - gas_sload_cold;

        // In that particular case allow unsigned casting to signed as it can't be more than `i64::MAX`.
        #[allow(clippy::as_conversions, clippy::cast_possible_wrap)]
        // See https://eips.ethereum.org/EIPS/eip-3529
        let refund_sstore_clears = if decrease_clears_refund {
            (gas_sstore_reset + gas_access_list_storage_key) as i64
        } else {
            15000
        };
        let max_refund_quotient = if decrease_clears_refund { 5 } else { 2 };

        Self {
            gas_ext_code: 0,
            gas_ext_code_hash: 0,
            gas_balance: 0,
            gas_sload,
            gas_sload_cold,
            gas_sstore_set: 20000,
            gas_sstore_reset,
            refund_sstore_clears,
            max_refund_quotient,
            gas_suicide: 5000,
            gas_suicide_new_account: 25000,
            gas_call: 0,
            gas_expbyte: 50,
            gas_transaction_create: 53000,
            gas_transaction_call: 21000,
            gas_transaction_zero_data: 4,
            gas_transaction_non_zero_data: 16,
            gas_access_list_address: 2400,
            gas_access_list_storage_key,
            gas_account_access_cold: 2600,
            gas_storage_read_warm,
            sstore_gas_metering: true,
            sstore_revert_under_stipend: true,
            increase_state_access_gas: true,
            decrease_clears_refund,
            disallow_executable_format,
            warm_coinbase_address,
            err_on_call_with_more_gas: false,
            empty_considered_exists: false,
            create_increase_nonce: true,
            call_l64_after_gas: true,
            stack_limit: 1024,
            memory_limit: usize::MAX,
            call_stack_limit: 1024,
            create_contract_limit: Some(0x6000),
            max_initcode_size,
            call_stipend: 2300,
            has_delegate_call: true,
            has_create2: true,
            has_revert: true,
            has_return_data: true,
            has_bitwise_shifting: true,
            has_chain_id: true,
            has_self_balance: true,
            has_ext_code_hash: true,
            has_base_fee,
            has_push0,
            estimate: false,
            has_blob_base_fee,
            has_shard_blob_transactions,
            has_transient_storage,
            has_mcopy,
            has_restricted_selfdestruct,
            has_authorization_list,
            gas_per_empty_account_cost,
            gas_per_auth_base_cost,
            has_floor_gas,
            total_cost_floor_per_token,
        }
    }
}

/// Independent inputs that are used to derive other config values.
/// See `Config::config_with_derived_values` implementation for details.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct DerivedConfigInputs {
    gas_storage_read_warm: u64,
    gas_sload_cold: u64,
    gas_access_list_storage_key: u64,
    decrease_clears_refund: bool,
    has_base_fee: bool,
    has_push0: bool,
    disallow_executable_format: bool,
    warm_coinbase_address: bool,
    max_initcode_size: Option<usize>,
    has_blob_base_fee: bool,
    has_shard_blob_transactions: bool,
    has_transient_storage: bool,
    has_mcopy: bool,
    has_restricted_selfdestruct: bool,
    has_authorization_list: bool,
    gas_per_empty_account_cost: u64,
    gas_per_auth_base_cost: u64,
    has_floor_gas: bool,
    total_cost_floor_per_token: u64,
}

impl DerivedConfigInputs {
    const fn berlin() -> Self {
        Self {
            gas_storage_read_warm: 100,
            gas_sload_cold: 2100,
            gas_access_list_storage_key: 1900,
            decrease_clears_refund: false,
            has_base_fee: false,
            has_push0: false,
            disallow_executable_format: false,
            warm_coinbase_address: false,
            max_initcode_size: None,
            has_blob_base_fee: false,
            has_shard_blob_transactions: false,
            has_transient_storage: false,
            has_mcopy: false,
            has_restricted_selfdestruct: false,
            has_authorization_list: false,
            gas_per_auth_base_cost: 0,
            gas_per_empty_account_cost: 0,
            has_floor_gas: false,
            total_cost_floor_per_token: 0,
        }
    }

    const fn london() -> Self {
        Self {
            gas_storage_read_warm: 100,
            gas_sload_cold: 2100,
            gas_access_list_storage_key: 1900,
            decrease_clears_refund: true,
            has_base_fee: true,
            has_push0: false,
            disallow_executable_format: true,
            warm_coinbase_address: false,
            max_initcode_size: None,
            has_blob_base_fee: false,
            has_shard_blob_transactions: false,
            has_transient_storage: false,
            has_mcopy: false,
            has_restricted_selfdestruct: false,
            has_authorization_list: false,
            gas_per_auth_base_cost: 0,
            gas_per_empty_account_cost: 0,
            has_floor_gas: false,
            total_cost_floor_per_token: 0,
        }
    }

    const fn merge() -> Self {
        Self {
            gas_storage_read_warm: 100,
            gas_sload_cold: 2100,
            gas_access_list_storage_key: 1900,
            decrease_clears_refund: true,
            has_base_fee: true,
            has_push0: false,
            disallow_executable_format: true,
            warm_coinbase_address: false,
            max_initcode_size: None,
            has_blob_base_fee: false,
            has_shard_blob_transactions: false,
            has_transient_storage: false,
            has_mcopy: false,
            has_restricted_selfdestruct: false,
            has_authorization_list: false,
            gas_per_auth_base_cost: 0,
            gas_per_empty_account_cost: 0,
            has_floor_gas: false,
            total_cost_floor_per_token: 0,
        }
    }

    const fn shanghai() -> Self {
        Self {
            gas_storage_read_warm: 100,
            gas_sload_cold: 2100,
            gas_access_list_storage_key: 1900,
            decrease_clears_refund: true,
            has_base_fee: true,
            has_push0: true,
            disallow_executable_format: true,
            warm_coinbase_address: true,
            // 2 * 24576 as per EIP-3860
            max_initcode_size: Some(0xC000),
            has_blob_base_fee: false,
            has_shard_blob_transactions: false,
            has_transient_storage: false,
            has_mcopy: false,
            has_restricted_selfdestruct: false,
            has_authorization_list: false,
            gas_per_auth_base_cost: 0,
            gas_per_empty_account_cost: 0,
            has_floor_gas: false,
            total_cost_floor_per_token: 0,
        }
    }

    const fn cancun() -> Self {
        let mut config = Self::shanghai();
        config.has_blob_base_fee = true;
        config.has_shard_blob_transactions = true;
        config.has_transient_storage = true;
        config.has_mcopy = true;
        config.has_restricted_selfdestruct = true;
        config
    }

    const fn prague() -> Self {
        let mut config = Self::cancun();
        config.has_authorization_list = true;
        config.gas_per_empty_account_cost = 25000;
        config.gas_per_auth_base_cost = 12500;
        config.has_floor_gas = true;
        config.total_cost_floor_per_token = 10;
        config
    }
}
