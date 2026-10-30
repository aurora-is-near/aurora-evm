//! VM gasometer.

#[cfg(not(feature = "std"))]
pub mod prelude {
    pub use alloc::vec::Vec;
}

#[cfg(feature = "std")]
pub mod prelude {
    pub use std::vec::Vec;
}

#[cfg(feature = "tracing")]
pub mod tracing;

#[cfg(feature = "tracing")]
macro_rules! event {
    ($x:expr) => {
        use self::tracing::Event::*;
        self::tracing::with(|listener| listener.event($x));
    };
}
#[cfg(feature = "force-debug")]
macro_rules! log_gas {
	($self:expr, $($arg:tt)*) => (
	log::trace!(target: "evm", "Gasometer {} [Gas used: {}, Gas left: {}]", format_args!($($arg)*),
	$self.total_used_gas(), $self.gas());
	#[cfg(feature = "print-debug")]
	println!("\t# {} [{} | {}]", format_args!($($arg)*), $self.total_used_gas(), $self.gas());
	);
}

#[cfg(not(feature = "force-debug"))]
macro_rules! log_gas {
    ($self:expr, $($arg:tt)*) => {};
}

#[cfg(not(feature = "tracing"))]
macro_rules! event {
    ($x:expr) => {};
}

mod consts;
mod costs;
mod memory;
mod utils;

use crate::core::utils::U256_ZERO;
use crate::core::{ExitError, Opcode, Stack};
use crate::prelude::*;
use crate::runtime::{Config, Handler};
use core::cmp::max;
use primitive_types::{H160, H256, U256};

macro_rules! try_or_fail {
    ( $inner:expr, $e:expr ) => {
        match $e {
            Ok(value) => value,
            Err(e) => {
                $inner = Err(e.clone());
                return Err(e);
            }
        }
    };
}

#[cfg(feature = "tracing")]
#[derive(Debug, Copy, Clone)]
pub struct Snapshot {
    pub gas_limit: u64,
    pub memory_gas: u64,
    pub used_gas: u64,
    pub refunded_gas: i64,
}

#[cfg(feature = "tracing")]
impl Snapshot {
    #[must_use]
    const fn new<'config>(gas_limit: u64, inner: &'config Inner<'config>) -> Self {
        Self {
            gas_limit,
            memory_gas: inner.memory_gas,
            used_gas: inner.used_gas,
            refunded_gas: inner.refunded_gas,
        }
    }
}

/// EVM gasometer.
#[derive(Clone, Debug)]
pub struct Gasometer<'config> {
    gas_limit: u64,
    config: &'config Config,
    inner: Result<Inner<'config>, ExitError>,
}

impl<'config> Gasometer<'config> {
    /// Create a new gasometer with given gas limit and config.
    #[must_use]
    pub const fn new(gas_limit: u64, config: &'config Config) -> Self {
        Self {
            gas_limit,
            config,
            inner: Ok(Inner {
                memory_gas: 0,
                used_gas: 0,
                refunded_gas: 0,
                floor_gas: 0,
                config,
            }),
        }
    }

    /// Returns the numerical gas cost value.
    ///
    /// # Errors
    /// Return `ExitError`
    #[inline]
    pub fn gas_cost(&self, cost: GasCost, gas: u64) -> Result<u64, ExitError> {
        match self.inner.as_ref() {
            Ok(inner) => inner.gas_cost(cost, gas),
            Err(e) => Err(e.clone()),
        }
    }

    #[inline]
    fn inner_mut(&mut self) -> Result<&mut Inner<'config>, ExitError> {
        self.inner.as_mut().map_err(|e| e.clone())
    }

    /// Reference of the config.
    #[inline]
    #[must_use]
    pub const fn config(&self) -> &'config Config {
        self.config
    }

    /// Gas limit.
    #[inline]
    #[must_use]
    pub const fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    /// Get floor gas
    #[inline]
    #[must_use]
    pub fn floor_gas(&self) -> u64 {
        self.inner.as_ref().map_or(0, |inner| inner.floor_gas)
    }

    /// Remaining gas.
    #[inline]
    #[must_use]
    pub fn gas(&self) -> u64 {
        self.inner.as_ref().map_or(0, |inner| {
            self.gas_limit - inner.used_gas - inner.memory_gas
        })
    }

    /// Total used gas.
    #[inline]
    #[must_use]
    pub const fn total_used_gas(&self) -> u64 {
        match self.inner.as_ref() {
            Ok(inner) => inner.used_gas + inner.memory_gas,
            Err(_) => self.gas_limit,
        }
    }

    /// Refunded gas.
    #[inline]
    #[must_use]
    pub fn refunded_gas(&self) -> i64 {
        self.inner.as_ref().map_or(0, |inner| inner.refunded_gas)
    }

    /// Explicitly fail the gasometer with out of gas. Return `OutOfGas` error.
    pub fn fail(&mut self) -> ExitError {
        self.inner = Err(ExitError::OutOfGas);
        ExitError::OutOfGas
    }

    /// Record an explicit cost.
    ///
    /// # Errors
    /// Return `ExitError`
    #[inline]
    pub fn record_cost(&mut self, cost: u64) -> Result<(), ExitError> {
        event!(RecordCost {
            cost,
            snapshot: self.snapshot(),
        });

        let all_gas_cost = self.total_used_gas() + cost;
        if self.gas_limit < all_gas_cost {
            self.inner = Err(ExitError::OutOfGas);
            return Err(ExitError::OutOfGas);
        }

        self.inner_mut()?.used_gas += cost;
        log_gas!(self, "record_cost: {}", cost);
        Ok(())
    }

    #[inline]
    /// Record an explicit refund.
    ///
    /// # Errors
    /// Return `ExitError` that is thrown by gasometer gas calculation errors.
    pub fn record_refund(&mut self, refund: i64) -> Result<(), ExitError> {
        event!(RecordRefund {
            refund,
            snapshot: self.snapshot(),
        });
        log_gas!(self, "record_refund: -{}", refund);

        self.inner_mut()?.refunded_gas += refund;
        Ok(())
    }

    /// Record refund for `authority` - EIP-7702
    /// `refunded_accounts` represent count of valid `authority`  accounts.
    ///
    /// ## Errors
    /// Return `ExitError` if `record_refund` operation fails.
    pub fn record_authority_refund(&mut self, refunded_accounts: u64) -> Result<(), ExitError> {
        let refund = i64::try_from(
            refunded_accounts
                * (self.config.gas_per_empty_account_cost - self.config.gas_per_auth_base_cost),
        )
        .unwrap_or(i64::MAX);
        self.record_refund(refund)
    }

    /// Record `CREATE` code deposit.
    ///
    /// # Errors
    /// Return `ExitError`
    /// NOTE: in that context usize->u64 `as_conversions` is save
    #[allow(clippy::as_conversions)]
    #[inline]
    pub fn record_deposit(&mut self, len: usize) -> Result<(), ExitError> {
        let cost = len as u64 * u64::from(consts::G_CODEDEPOSIT);
        self.record_cost(cost)
    }

    /// Fails with `OutOfGas` unless the remaining gas covers `gas` plus the expansion to
    /// `memory_cost`. Nothing is recorded: the caller records the full cost afterwards, and a
    /// failure leaves the gasometer failed. With the `tracing` feature, a failure emits one
    /// `RecordDynamicCost` event with `gas` and the memory gas, as a failed `record_cost`
    /// reports its cost, so a trace shows the rejected step.
    ///
    /// An opcode checks the part of its cost that needs no state before its first state access,
    /// so an opcode that cannot pay it never touches the state it targets: the order the
    /// execution specs (Amsterdam hardfork `check_gas`) and EIP-7928 fix for every access a block access
    /// list, or an execution witness, has to carry. Normal gas accounting still applies the
    /// full opcode cost and the EIP-2200 stipend rule afterwards.
    /// See also Yellow Paper Appendix H.2, CALL and SELFDESTRUCT gas costs.
    ///
    /// Returns the calculated total memory gas for the subsequent full charge.
    /// See <https://ethereum.github.io/execution-specs/src/ethereum/forks/amsterdam/vm/gas.py.html>.
    ///
    /// # Errors
    /// Return the error of an already failed gasometer, or `ExitError::OutOfGas` when the gas is
    /// not affordable; the gasometer is then failed.
    pub(crate) fn check_gas(
        &mut self,
        gas: u64,
        memory_cost: Option<MemoryCost>,
    ) -> Result<u64, ExitError> {
        let inner = match &self.inner {
            Ok(inner) => inner,
            Err(err) => return Err(err.clone()),
        };
        let memory_gas = match memory_cost {
            Some(memory_cost) => try_or_fail!(self.inner, inner.memory_gas(memory_cost)),
            None => inner.memory_gas,
        };
        // Memory gas never shrinks, so this is exactly the expansion the opcode would pay.
        let required = try_or_fail!(
            self.inner,
            (memory_gas - inner.memory_gas)
                .checked_add(gas)
                .ok_or(ExitError::OutOfGas)
        );
        if self.gas() < required {
            // The step's only gas event: the cost known before the state access, reported
            // the way `record_cost` and `record_dynamic_cost` report the cost they fail on.
            event!(RecordDynamicCost {
                gas_cost: gas,
                memory_gas,
                gas_refund: 0,
                snapshot: self.snapshot(),
            });
            self.inner = Err(ExitError::OutOfGas);
            return Err(ExitError::OutOfGas);
        }
        Ok(memory_gas)
    }

    /// Record opcode gas cost.
    ///
    /// # Errors
    /// Return `ExitError`
    pub fn record_dynamic_cost(
        &mut self,
        cost: GasCost,
        memory: Option<MemoryCost>,
    ) -> Result<(), ExitError> {
        self.record_dynamic_cost_prepared(cost, memory, None)
    }

    /// Records the full cost, reusing memory gas calculated by the state-access check.
    pub(crate) fn record_dynamic_cost_prepared(
        &mut self,
        cost: GasCost,
        memory: Option<MemoryCost>,
        prepared_memory_gas: Option<u64>,
    ) -> Result<(), ExitError> {
        let gas = self.gas();
        // Extract a mutable reference to `Inner` to avoid checking `Result`
        // repeatedly. Tuning performance as this function is on the hot path.
        let inner_mut = match &mut self.inner {
            Ok(inner) => inner,
            Err(err) => return Err(err.clone()),
        };

        let memory_gas = match prepared_memory_gas {
            Some(prepared_gas) => {
                debug_assert_eq!(
                    memory.map_or(Ok(inner_mut.memory_gas), |memory| inner_mut
                        .memory_gas(memory)),
                    Ok(prepared_gas),
                    "the prepared memory gas must be the gas of the recorded memory"
                );
                prepared_gas
            }
            None => match memory {
                Some(memory) => try_or_fail!(self.inner, inner_mut.memory_gas(memory)),
                None => inner_mut.memory_gas,
            },
        };
        let gas_cost = try_or_fail!(self.inner, inner_mut.gas_cost(cost, gas));
        let gas_refund = inner_mut.gas_refund(cost);
        let used_gas = inner_mut.used_gas;

        #[cfg(feature = "tracing")]
        let gas_limit = self.gas_limit;
        event!(RecordDynamicCost {
            gas_cost,
            memory_gas,
            gas_refund,
            snapshot: Some(Snapshot::new(gas_limit, inner_mut)),
        });

        let all_gas_cost = memory_gas
            .checked_add(used_gas.saturating_add(gas_cost))
            .ok_or(ExitError::OutOfGas)?;
        if self.gas_limit < all_gas_cost {
            self.inner = Err(ExitError::OutOfGas);
            return Err(ExitError::OutOfGas);
        }

        let after_gas = self.gas_limit - all_gas_cost;
        try_or_fail!(self.inner, inner_mut.extra_check(cost, after_gas));

        inner_mut.used_gas += gas_cost;
        inner_mut.memory_gas = memory_gas;
        inner_mut.refunded_gas += gas_refund;

        // NOTE Extended meesage: "Record dynamic cost {gas_cost} - memory_gas {} - gas_refund {}",
        log_gas!(
            self,
            "record_dynamic_cost: {gas_cost} - {memory_gas} - {gas_refund}"
        );

        Ok(())
    }

    /// Record opcode stipend.
    ///
    /// # Errors
    /// Return `ExitError` that is thrown by gasometer gas calculation errors.
    #[inline]
    pub fn record_stipend(&mut self, stipend: u64) -> Result<(), ExitError> {
        event!(RecordStipend {
            stipend,
            snapshot: self.snapshot(),
        });

        self.inner_mut()?.used_gas -= stipend;
        log_gas!(self, "record_stipent: {}", stipend);
        Ok(())
    }

    /// Calculate intrinsic gas and gas floor based on transaction data.
    /// Returns intrinsic gas cost and gas floor.
    #[must_use]
    pub fn calculate_intrinsic_gas_and_gas_floor(
        data: &[u8],
        access_list: &[(H160, Vec<H256>)],
        authorization_list_len: usize,
        config: &Config,
        is_contract_creation: bool,
    ) -> (u64, u64) {
        let cost = if is_contract_creation {
            create_transaction_cost(data, access_list)
        } else {
            call_transaction_cost(data, access_list, authorization_list_len)
        };
        Self::intrinsic_gas_and_gas_floor(cost, config)
    }

    /// Calculate intrinsic gas and gas floor based on `TransactionCost` type and config.
    /// Returns intrinsic gas cost and gas floor.
    /// Related EIPs:
    /// - [EIP-2028](https://eips.ethereum.org/EIPS/eip-2028)
    /// - [EIP-7623](https://eips.ethereum.org/EIPS/eip-7623)
    ///
    /// Uses ordinary `u64` arithmetic. Callers must ensure that intermediate values and totals
    /// fit in `u64`, including when supplying synthetic counts or custom gas prices.
    /// Overflow wraps when overflow checks are disabled; it does not saturate.
    #[must_use]
    #[allow(clippy::as_conversions)] // NOTE: in that context usize->u64 `as_conversions` is safe
    pub const fn intrinsic_gas_and_gas_floor(cost: TransactionCost, config: &Config) -> (u64, u64) {
        const fn floor_gas_calc(
            config: &Config,
            zero_data_len: usize,
            non_zero_data_len: usize,
        ) -> u64 {
            if config.has_floor_gas {
                // According to EIP-2028: non-zero byte = 16, zero-byte = 4
                // According to EIP-7623: tokens_in_calldata = zero_bytes_in_calldata + nonzero_bytes_in_calldata * 4
                // NOTE: widen to u64 before multiplying so a 32-bit `usize` cannot truncate the token count.
                let tokens_in_calldata = non_zero_data_len as u64 * 4 + zero_data_len as u64;

                tokens_in_calldata * config.total_cost_floor_per_token + config.gas_transaction_call
            } else {
                0
            }
        }

        match cost {
            TransactionCost::Call {
                zero_data_len,
                non_zero_data_len,
                access_list_address_len,
                access_list_storage_len,
                authorization_list_len,
            } => {
                let cost = config.gas_transaction_call
                    + config.gas_transaction_zero_data * zero_data_len as u64
                    + config.gas_transaction_non_zero_data * non_zero_data_len as u64
                    + config.gas_access_list_address * access_list_address_len as u64
                    + config.gas_access_list_storage_key * access_list_storage_len as u64
                    + config.gas_per_empty_account_cost * authorization_list_len as u64;
                let floor_gas = floor_gas_calc(config, zero_data_len, non_zero_data_len);

                (cost, floor_gas)
            }
            TransactionCost::Create {
                zero_data_len,
                non_zero_data_len,
                access_list_address_len,
                access_list_storage_len,
                initcode_cost,
            } => {
                let mut cost = config.gas_transaction_create
                    + config.gas_transaction_zero_data * zero_data_len as u64
                    + config.gas_transaction_non_zero_data * non_zero_data_len as u64
                    + config.gas_access_list_address * access_list_address_len as u64
                    + config.gas_access_list_storage_key * access_list_storage_len as u64;

                if config.max_initcode_size.is_some() {
                    cost += initcode_cost;
                }

                let floor_gas = floor_gas_calc(config, zero_data_len, non_zero_data_len);

                (cost, floor_gas)
            }
        }
    }

    /// Verify transaction cost against gas limit and gas floor based on `TransactionCost` type.
    /// Returns intrinsic gas cost.
    /// For `force-debug` feature, it will log the transaction cost details.
    /// Related EIPs:
    /// - [EIP-2028](https://eips.ethereum.org/EIPS/eip-2028)
    /// - [EIP-7623](https://eips.ethereum.org/EIPS/eip-7623)
    ///
    /// ## Errors
    /// Return `ExitError` if gas limit is less than intrinsic gas or gas floor.
    pub fn verify_transaction(&mut self, cost: TransactionCost) -> Result<(u64, u64), ExitError> {
        let (gas_cost, floor_gas) = Self::intrinsic_gas_and_gas_floor(cost, self.config);
        #[cfg(feature = "force-debug")]
        match cost {
            TransactionCost::Call {
                zero_data_len,
                non_zero_data_len,
                access_list_address_len,
                access_list_storage_len,
                authorization_list_len,
            } => {
                log_gas!(
					self,
					"Record Call {} [gas_transaction_call: {}, zero_data_len: {}, non_zero_data_len: {}, access_list_address_len: {}, access_list_storage_len: {}, authorization_list_len: {}]",
					cost,
					self.config.gas_transaction_call,
					zero_data_len,
					non_zero_data_len,
					access_list_address_len,
					access_list_storage_len,
					authorization_list_len
				);
            }
            TransactionCost::Create {
                zero_data_len,
                non_zero_data_len,
                access_list_address_len,
                access_list_storage_len,
                initcode_cost,
            } => {
                log_gas!(
					self,
					"Record Create {} [gas_transaction_create: {}, zero_data_len: {}, non_zero_data_len: {}, access_list_address_len: {}, access_list_storage_len: {}, initcode_cost: {}]",
					cost,
					self.config.gas_transaction_create,
					zero_data_len,
					non_zero_data_len,
					access_list_address_len,
					access_list_storage_len,
					initcode_cost
				);
            }
        }
        if self.gas() < gas_cost {
            self.inner = Err(ExitError::OutOfGas);
            return Err(ExitError::OutOfGas);
        }
        // EIP-7623 gas floor check for gas_limit
        // It's equivalent to checking: max(gas_cost, floor_gas). But as we need to check
        // `config.has_floor_gas` anyway, we can do it this way to avoid an extra max() call.
        if self.config.has_floor_gas && self.gas_limit() < floor_gas {
            self.inner = Err(ExitError::OutOfGas);
            return Err(ExitError::OutOfGas);
        }

        Ok((gas_cost, floor_gas))
    }

    /// Record transaction cost.
    /// Related EIPs:
    /// - [EIP-2028](https://eips.ethereum.org/EIPS/eip-2028)
    /// - [EIP-7623](https://eips.ethereum.org/EIPS/eip-7623)
    ///
    /// # Errors
    /// Return `ExitError`
    pub fn record_transaction(&mut self, cost: TransactionCost) -> Result<(), ExitError> {
        let (gas_cost, floor_gas) = self.verify_transaction(cost)?;

        event!(RecordTransaction {
            cost: gas_cost,
            snapshot: self.snapshot(),
        });

        // EIP-7623 gas floor update
        if self.config.has_floor_gas {
            self.inner_mut()?.floor_gas = floor_gas;
        }

        self.inner_mut()?.used_gas += gas_cost;
        Ok(())
    }

    #[cfg(feature = "tracing")]
    #[must_use]
    pub fn snapshot(&self) -> Option<Snapshot> {
        self.inner
            .as_ref()
            .ok()
            .map(|inner| Snapshot::new(self.gas_limit, inner))
    }
}

/// Calculate the call transaction cost.
#[allow(clippy::naive_bytecount)]
#[must_use]
pub fn call_transaction_cost(
    data: &[u8],
    access_list: &[(H160, Vec<H256>)],
    authorization_list_len: usize,
) -> TransactionCost {
    let zero_data_len = data.iter().filter(|v| **v == 0).count();
    let non_zero_data_len = data.len() - zero_data_len;
    let (access_list_address_len, access_list_storage_len) = count_access_list(access_list);

    TransactionCost::Call {
        zero_data_len,
        non_zero_data_len,
        access_list_address_len,
        access_list_storage_len,
        authorization_list_len,
    }
}

/// Calculate the create transaction cost.
#[allow(clippy::naive_bytecount)]
#[must_use]
pub fn create_transaction_cost(data: &[u8], access_list: &[(H160, Vec<H256>)]) -> TransactionCost {
    let zero_data_len = data.iter().filter(|v| **v == 0).count();
    let non_zero_data_len = data.len() - zero_data_len;
    let (access_list_address_len, access_list_storage_len) = count_access_list(access_list);
    let initcode_cost = init_code_cost(data);

    TransactionCost::Create {
        zero_data_len,
        non_zero_data_len,
        access_list_address_len,
        access_list_storage_len,
        initcode_cost,
    }
}

/// Init code cost, related to `EIP-3860`
/// NOTE: in that context `as-conversion` is safe for `usize->u64`
#[allow(clippy::as_conversions)]
#[must_use]
pub const fn init_code_cost(data: &[u8]) -> u64 {
    // As per EIP-3860:
    // > We define initcode_cost(initcode) to equal INITCODE_WORD_COST * ceil(len(initcode) / 32).
    // where INITCODE_WORD_COST is 2.
    2 * (data.len() as u64).div_ceil(32)
}

/// Counts the number of addresses and storage keys in the access list
fn count_access_list(access_list: &[(H160, Vec<H256>)]) -> (usize, usize) {
    let access_list_address_len = access_list.len();
    let access_list_storage_len = access_list.iter().map(|(_, keys)| keys.len()).sum();

    (access_list_address_len, access_list_storage_len)
}

#[allow(clippy::too_many_lines)]
#[inline]
#[must_use]
pub fn static_opcode_cost(opcode: Opcode) -> Option<u32> {
    static TABLE: [Option<u32>; 256] = {
        let mut table = [None; 256];

        table[Opcode::STOP.as_usize()] = Some(consts::G_ZERO);
        table[Opcode::CALLDATASIZE.as_usize()] = Some(consts::G_BASE);
        table[Opcode::CODESIZE.as_usize()] = Some(consts::G_BASE);
        table[Opcode::POP.as_usize()] = Some(consts::G_BASE);
        table[Opcode::PC.as_usize()] = Some(consts::G_BASE);
        table[Opcode::MSIZE.as_usize()] = Some(consts::G_BASE);

        table[Opcode::ADDRESS.as_usize()] = Some(consts::G_BASE);
        table[Opcode::ORIGIN.as_usize()] = Some(consts::G_BASE);
        table[Opcode::CALLER.as_usize()] = Some(consts::G_BASE);
        table[Opcode::CALLVALUE.as_usize()] = Some(consts::G_BASE);
        table[Opcode::COINBASE.as_usize()] = Some(consts::G_BASE);
        table[Opcode::TIMESTAMP.as_usize()] = Some(consts::G_BASE);
        table[Opcode::NUMBER.as_usize()] = Some(consts::G_BASE);
        table[Opcode::PREVRANDAO.as_usize()] = Some(consts::G_BASE);
        table[Opcode::GASLIMIT.as_usize()] = Some(consts::G_BASE);
        table[Opcode::GASPRICE.as_usize()] = Some(consts::G_BASE);
        table[Opcode::GAS.as_usize()] = Some(consts::G_BASE);

        table[Opcode::ADD.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SUB.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::NOT.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::LT.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::GT.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SLT.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SGT.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::EQ.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::ISZERO.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::AND.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::OR.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::XOR.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::BYTE.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::CALLDATALOAD.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH1.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH2.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH3.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH4.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH5.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH6.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH7.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH8.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH9.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH10.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH11.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH12.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH13.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH14.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH15.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH16.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH17.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH18.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH19.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH20.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH21.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH22.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH23.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH24.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH25.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH26.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH27.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH28.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH29.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH30.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH31.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::PUSH32.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP1.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP2.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP3.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP4.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP5.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP6.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP7.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP8.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP9.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP10.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP11.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP12.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP13.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP14.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP15.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::DUP16.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP1.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP2.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP3.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP4.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP5.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP6.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP7.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP8.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP9.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP10.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP11.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP12.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP13.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP14.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP15.as_usize()] = Some(consts::G_VERYLOW);
        table[Opcode::SWAP16.as_usize()] = Some(consts::G_VERYLOW);

        table[Opcode::MUL.as_usize()] = Some(consts::G_LOW);
        table[Opcode::DIV.as_usize()] = Some(consts::G_LOW);
        table[Opcode::SDIV.as_usize()] = Some(consts::G_LOW);
        table[Opcode::MOD.as_usize()] = Some(consts::G_LOW);
        table[Opcode::SMOD.as_usize()] = Some(consts::G_LOW);
        table[Opcode::SIGNEXTEND.as_usize()] = Some(consts::G_LOW);

        table[Opcode::ADDMOD.as_usize()] = Some(consts::G_MID);
        table[Opcode::MULMOD.as_usize()] = Some(consts::G_MID);
        table[Opcode::JUMP.as_usize()] = Some(consts::G_MID);

        table[Opcode::JUMPI.as_usize()] = Some(consts::G_HIGH);
        table[Opcode::JUMPDEST.as_usize()] = Some(consts::G_JUMPDEST);

        table
    };

    TABLE[opcode.as_usize()]
}

/// Warm the target, cold until now when `target_is_cold`, and its EIP-7702 delegate; returns
/// whether the delegate was cold, for a delegating target.
pub(crate) fn get_and_set_warm<H: Handler>(
    handler: &mut H,
    target: H160,
    target_is_cold: bool,
) -> Option<bool> {
    if target_is_cold {
        handler.warm_target((target, None));
    }
    handler
        .get_authority_target(target)
        .map(|authority_target| {
            if handler.is_cold(authority_target, None) {
                handler.warm_target((authority_target, None));
                true
            } else {
                false
            }
        })
}

/// Get and set warm address if it's not warmed for non-delegated opcodes like `EXT*`.
/// NOTE: Related to EIP-7702
fn get_and_set_non_delegated_warm<H: Handler>(handler: &mut H, target: H160) -> bool {
    let target_is_cold = handler.is_cold(target, None);
    if target_is_cold {
        handler.warm_target((target, None));
    }
    target_is_cold
}

/// The gas a `CALL`-family opcode owes before its first state access: the target's access cost
/// and the value transfer (Yellow Paper `C_EXTRA` without `C_NEW`).
pub(crate) fn call_access_gas(target_is_cold: bool, transfers_value: bool, config: &Config) -> u64 {
    let mut gas = costs::address_access_cost(target_is_cold, None, config.gas_call, config);
    if transfers_value {
        gas += u64::from(consts::G_CALLVALUE);
    }
    gas
}

/// The gas `SELFDESTRUCT` owes before its first state access: its base cost and the
/// beneficiary's cold access.
const fn selfdestruct_access_gas(target_is_cold: bool, config: &Config) -> u64 {
    if config.increase_state_access_gas && target_is_cold {
        config.gas_suicide + config.gas_account_access_cold
    } else {
        config.gas_suicide
    }
}

/// Prices an opcode with an internal check before state access (EELS Amsterdam).
#[allow(
    clippy::too_many_lines,
    clippy::nonminimal_bool,
    clippy::match_same_arms
)]
pub(crate) fn dynamic_opcode_cost<H: Handler>(
    address: H160,
    opcode: Opcode,
    stack: &Stack,
    is_static: bool,
    config: &Config,
    handler: &mut H,
    mut check_gas: impl FnMut(&mut H, u64, Option<MemoryCost>) -> Result<(), ExitError>,
) -> Result<(GasCost, Option<MemoryCost>), ExitError> {
    let mut call_memory = None;
    let gas_cost = match opcode {
        Opcode::RETURN => GasCost::Zero,

        Opcode::MLOAD | Opcode::MSTORE | Opcode::MSTORE8 => GasCost::VeryLow,

        Opcode::REVERT if config.has_revert => GasCost::Zero,
        Opcode::REVERT => GasCost::Invalid(opcode),

        Opcode::CHAINID if config.has_chain_id => GasCost::Base,
        Opcode::CHAINID => GasCost::Invalid(opcode),

        Opcode::SHL | Opcode::SHR | Opcode::SAR if config.has_bitwise_shifting => GasCost::VeryLow,
        Opcode::SHL | Opcode::SHR | Opcode::SAR => GasCost::Invalid(opcode),

        Opcode::CLZ if config.has_clz => GasCost::Low,
        Opcode::CLZ => GasCost::Invalid(opcode),

        Opcode::SELFBALANCE if config.has_self_balance => GasCost::Low,
        Opcode::SELFBALANCE => GasCost::Invalid(opcode),

        Opcode::BASEFEE if config.has_base_fee => GasCost::Base,
        Opcode::BASEFEE => GasCost::Invalid(opcode),

        Opcode::BLOBBASEFEE if config.has_blob_base_fee => GasCost::Base,
        Opcode::BLOBBASEFEE => GasCost::Invalid(opcode),

        Opcode::BLOBHASH if config.has_shard_blob_transactions => GasCost::VeryLow,
        Opcode::BLOBHASH => GasCost::Invalid(opcode),

        Opcode::TLOAD if config.has_transient_storage => GasCost::WarmStorageRead,
        Opcode::TLOAD => GasCost::Invalid(opcode),

        Opcode::TSTORE if !is_static && config.has_transient_storage => GasCost::WarmStorageRead,
        Opcode::TSTORE => GasCost::Invalid(opcode),

        Opcode::MCOPY if config.has_mcopy => GasCost::VeryLowCopy {
            len: stack.peek(2)?,
        },
        Opcode::MCOPY => GasCost::Invalid(opcode),

        Opcode::EXTCODESIZE => {
            let target = stack.peek_h256(0)?.into();
            let target_is_cold = get_and_set_non_delegated_warm(handler, target);
            GasCost::ExtCodeSize { target_is_cold }
        }
        Opcode::BALANCE => {
            let target = stack.peek_h256(0)?.into();
            let target_is_cold = handler.is_cold(target, None);
            if target_is_cold {
                handler.warm_target((target, None));
            }
            GasCost::Balance { target_is_cold }
        }
        Opcode::BLOCKHASH => GasCost::BlockHash,

        Opcode::EXTCODEHASH if config.has_ext_code_hash => {
            let target = stack.peek_h256(0)?.into();
            let target_is_cold = get_and_set_non_delegated_warm(handler, target);
            GasCost::ExtCodeHash { target_is_cold }
        }
        Opcode::EXTCODEHASH => GasCost::Invalid(opcode),

        Opcode::CALLCODE => {
            let target = stack.peek_h256(1)?.into();
            let value = stack.peek(2)?;
            call_memory = Some(peek_memory_cost(stack, 3, 4)?.join(peek_memory_cost(stack, 5, 6)?));
            let target_is_cold = handler.is_cold(target, None);
            check_gas(
                handler,
                call_access_gas(target_is_cold, !value.is_zero(), config),
                call_memory,
            )?;
            let delegated_designator_is_cold = get_and_set_warm(handler, target, target_is_cold);
            GasCost::CallCode {
                value,
                gas: stack.peek(0)?,
                target_is_cold,
                delegated_designator_is_cold,
                target_exists: {
                    handler.record_external_operation(crate::core::ExternalOperation::IsEmpty)?;
                    handler.exists(target)
                },
            }
        }
        Opcode::STATICCALL => {
            let target = stack.peek_h256(1)?.into();
            call_memory = Some(peek_memory_cost(stack, 2, 3)?.join(peek_memory_cost(stack, 4, 5)?));
            let target_is_cold = handler.is_cold(target, None);
            check_gas(
                handler,
                call_access_gas(target_is_cold, false, config),
                call_memory,
            )?;
            let delegated_designator_is_cold = get_and_set_warm(handler, target, target_is_cold);
            GasCost::StaticCall {
                gas: stack.peek(0)?,
                target_is_cold,
                delegated_designator_is_cold,
                target_exists: {
                    handler.record_external_operation(crate::core::ExternalOperation::IsEmpty)?;
                    handler.exists(target)
                },
            }
        }
        Opcode::SHA3 => GasCost::Sha3 {
            len: stack.peek(1)?,
        },
        Opcode::EXTCODECOPY => {
            let target = stack.peek_h256(0)?.into();
            let target_is_cold = get_and_set_non_delegated_warm(handler, target);
            GasCost::ExtCodeCopy {
                target_is_cold,
                len: stack.peek(3)?,
            }
        }
        Opcode::CALLDATACOPY | Opcode::CODECOPY => GasCost::VeryLowCopy {
            len: stack.peek(2)?,
        },
        Opcode::EXP => GasCost::Exp {
            power: stack.peek(1)?,
        },
        Opcode::SLOAD => {
            let index = stack.peek_h256(0)?;
            let target_is_cold = handler.is_cold(address, Some(index));
            if target_is_cold {
                handler.warm_target((address, Some(index)));
            }
            GasCost::SLoad { target_is_cold }
        }

        Opcode::DELEGATECALL if config.has_delegate_call => {
            let target = stack.peek_h256(1)?.into();
            call_memory = Some(peek_memory_cost(stack, 2, 3)?.join(peek_memory_cost(stack, 4, 5)?));
            let target_is_cold = handler.is_cold(target, None);
            check_gas(
                handler,
                call_access_gas(target_is_cold, false, config),
                call_memory,
            )?;
            let delegated_designator_is_cold = get_and_set_warm(handler, target, target_is_cold);
            GasCost::DelegateCall {
                gas: stack.peek(0)?,
                target_is_cold,
                delegated_designator_is_cold,
                target_exists: {
                    handler.record_external_operation(crate::core::ExternalOperation::IsEmpty)?;
                    handler.exists(target)
                },
            }
        }
        Opcode::DELEGATECALL => GasCost::Invalid(opcode),

        Opcode::RETURNDATASIZE if config.has_return_data => GasCost::Base,
        Opcode::RETURNDATACOPY if config.has_return_data => GasCost::VeryLowCopy {
            len: stack.peek(2)?,
        },
        Opcode::RETURNDATASIZE | Opcode::RETURNDATACOPY => GasCost::Invalid(opcode),

        Opcode::SSTORE if !is_static => {
            let index = stack.peek_h256(0)?;
            let value = stack.peek_h256(1)?;
            // EIP-2200: the store needs strictly more than the call stipend, checked before its
            // slot is read.
            if !config.estimate && config.sstore_gas_metering && config.sstore_revert_under_stipend
            {
                check_gas(handler, config.call_stipend + 1, None)?;
            }
            let target_is_cold = handler.is_cold(address, Some(index));
            if target_is_cold {
                handler.warm_target((address, Some(index)));
            }
            GasCost::SStore {
                original: handler.original_storage(address, index),
                current: handler.storage(address, index),
                new: value,
                target_is_cold,
            }
        }
        Opcode::LOG0 if !is_static => GasCost::Log {
            n: 0,
            len: stack.peek(1)?,
        },
        Opcode::LOG1 if !is_static => GasCost::Log {
            n: 1,
            len: stack.peek(1)?,
        },
        Opcode::LOG2 if !is_static => GasCost::Log {
            n: 2,
            len: stack.peek(1)?,
        },
        Opcode::LOG3 if !is_static => GasCost::Log {
            n: 3,
            len: stack.peek(1)?,
        },
        Opcode::LOG4 if !is_static => GasCost::Log {
            n: 4,
            len: stack.peek(1)?,
        },
        Opcode::CREATE if !is_static => GasCost::Create,
        Opcode::CREATE2 if !is_static && config.has_create2 => GasCost::Create2 {
            len: stack.peek(2)?,
        },
        Opcode::SELFDESTRUCT if !is_static => {
            let target = stack.peek_h256(0)?.into();
            let target_is_cold = handler.is_cold(target, None);
            check_gas(
                handler,
                selfdestruct_access_gas(target_is_cold, config),
                None,
            )?;
            if target_is_cold {
                handler.warm_target((target, None));
            }
            GasCost::Suicide {
                value: handler.balance(address),
                target_is_cold,
                target_exists: {
                    handler.record_external_operation(crate::core::ExternalOperation::IsEmpty)?;
                    handler.exists(target)
                },
                already_removed: handler.deleted(address),
            }
        }
        Opcode::CALL if !is_static || (is_static && stack.peek(2)? == U256_ZERO) => {
            let target = stack.peek_h256(1)?.into();
            let value = stack.peek(2)?;
            call_memory = Some(peek_memory_cost(stack, 3, 4)?.join(peek_memory_cost(stack, 5, 6)?));
            let target_is_cold = handler.is_cold(target, None);
            check_gas(
                handler,
                call_access_gas(target_is_cold, !value.is_zero(), config),
                call_memory,
            )?;
            let delegated_designator_is_cold = get_and_set_warm(handler, target, target_is_cold);
            GasCost::Call {
                value,
                gas: stack.peek(0)?,
                target_is_cold,
                delegated_designator_is_cold,
                target_exists: {
                    handler.record_external_operation(crate::core::ExternalOperation::IsEmpty)?;
                    handler.exists(target)
                },
            }
        }

        Opcode::PUSH0 if config.has_push0 => GasCost::Base,

        _ => GasCost::Invalid(opcode),
    };

    let memory_cost = match opcode {
        // The CALL family reads its memory operands in its pricing arm, before the check.
        Opcode::CALL | Opcode::CALLCODE | Opcode::DELEGATECALL | Opcode::STATICCALL => call_memory,

        Opcode::SHA3
        | Opcode::RETURN
        | Opcode::REVERT
        | Opcode::LOG0
        | Opcode::LOG1
        | Opcode::LOG2
        | Opcode::LOG3
        | Opcode::LOG4 => Some(peek_memory_cost(stack, 0, 1)?),

        Opcode::CODECOPY | Opcode::CALLDATACOPY | Opcode::RETURNDATACOPY => {
            Some(peek_memory_cost(stack, 0, 2)?)
        }

        Opcode::EXTCODECOPY => Some(peek_memory_cost(stack, 1, 3)?),

        Opcode::MLOAD | Opcode::MSTORE => Some(MemoryCost {
            offset: stack.peek_usize(0)?,
            len: 32,
        }),

        Opcode::MCOPY => {
            let len = stack.peek_usize(2)?;
            if len == 0 {
                None
            } else {
                Some(MemoryCost {
                    offset: {
                        let src = stack.peek_usize(0)?;
                        let dst = stack.peek_usize(1)?;
                        max(src, dst)
                    },
                    len,
                })
            }
        }

        Opcode::MSTORE8 => Some(MemoryCost {
            offset: stack.peek_usize(0)?,
            len: 1,
        }),

        Opcode::CREATE | Opcode::CREATE2 => Some(peek_memory_cost(stack, 1, 2)?),

        _ => None,
    };

    Ok((gas_cost, memory_cost))
}

fn peek_memory_cost(
    stack: &Stack,
    offset_index: usize,
    len_index: usize,
) -> Result<MemoryCost, ExitError> {
    let len = stack.peek_usize(len_index)?;

    if len == 0 {
        return Ok(MemoryCost {
            offset: usize::MAX,
            len,
        });
    }

    let offset = stack.peek_usize(offset_index)?;
    Ok(MemoryCost { offset, len })
}

/// Holds the gas consumption for a Gasometer instance.
#[derive(Clone, Debug)]
struct Inner<'config> {
    memory_gas: u64,
    used_gas: u64,
    refunded_gas: i64,
    config: &'config Config,
    floor_gas: u64,
}

impl Inner<'_> {
    fn memory_gas(&self, memory: MemoryCost) -> Result<u64, ExitError> {
        let from = memory.offset;
        let len = memory.len;

        if len == 0 {
            return Ok(self.memory_gas);
        }

        let end = from.checked_add(len).ok_or(ExitError::OutOfGas)?;

        let rem = end % 32;
        let new = if rem == 0 { end / 32 } else { end / 32 + 1 };

        Ok(max(self.memory_gas, memory::memory_gas(new)?))
    }

    fn extra_check(&self, cost: GasCost, after_gas: u64) -> Result<(), ExitError> {
        match cost {
            GasCost::Call { gas, .. }
            | GasCost::CallCode { gas, .. }
            | GasCost::DelegateCall { gas, .. }
            | GasCost::StaticCall { gas, .. } => {
                costs::call_extra_check(gas, after_gas, self.config)
            }
            _ => Ok(()),
        }
    }

    /// Returns the gas cost numerical value.
    #[allow(clippy::too_many_lines)]
    fn gas_cost(&self, cost: GasCost, gas: u64) -> Result<u64, ExitError> {
        Ok(match cost {
            GasCost::Call {
                value,
                target_is_cold,
                delegated_designator_is_cold,
                target_exists,
                ..
            } => costs::call_cost(
                value,
                target_is_cold,
                delegated_designator_is_cold,
                true,
                true,
                !target_exists,
                self.config,
            ),
            GasCost::CallCode {
                value,
                target_is_cold,
                delegated_designator_is_cold,
                target_exists,
                ..
            } => costs::call_cost(
                value,
                target_is_cold,
                delegated_designator_is_cold,
                true,
                false,
                !target_exists,
                self.config,
            ),
            GasCost::DelegateCall {
                target_is_cold,
                delegated_designator_is_cold,
                target_exists,
                ..
            } => costs::call_cost(
                U256_ZERO,
                target_is_cold,
                delegated_designator_is_cold,
                false,
                false,
                !target_exists,
                self.config,
            ),
            GasCost::StaticCall {
                target_is_cold,
                delegated_designator_is_cold,
                target_exists,
                ..
            } => costs::call_cost(
                U256_ZERO,
                target_is_cold,
                delegated_designator_is_cold,
                false,
                true,
                !target_exists,
                self.config,
            ),

            GasCost::Suicide {
                value,
                target_is_cold,
                target_exists,
                ..
            } => costs::suicide_cost(value, target_is_cold, target_exists, self.config),
            GasCost::SStore {
                original,
                current,
                new,
                target_is_cold,
            } => costs::sstore_cost(original, current, new, gas, target_is_cold, self.config)?,

            GasCost::Sha3 { len } => costs::sha3_cost(len)?,
            GasCost::Log { n, len } => costs::log_cost(n, len)?,
            GasCost::VeryLowCopy { len } => costs::verylowcopy_cost(len)?,
            GasCost::Exp { power } => costs::exp_cost(power, self.config)?,
            GasCost::Create => u64::from(consts::G_CREATE),
            GasCost::Create2 { len } => costs::create2_cost(len)?,
            GasCost::SLoad { target_is_cold } => costs::sload_cost(target_is_cold, self.config),

            GasCost::Zero => u64::from(consts::G_ZERO),
            GasCost::Base => u64::from(consts::G_BASE),
            GasCost::VeryLow => u64::from(consts::G_VERYLOW),
            GasCost::Low => u64::from(consts::G_LOW),
            GasCost::Invalid(opcode) => return Err(ExitError::InvalidCode(opcode)),

            GasCost::ExtCodeSize { target_is_cold } => costs::non_delegated_access_cost(
                target_is_cold,
                self.config.gas_ext_code,
                self.config,
            ),
            GasCost::ExtCodeCopy {
                target_is_cold,
                len,
            } => costs::ext_codecopy_cost(len, target_is_cold, self.config)?,
            GasCost::ExtCodeHash { target_is_cold } => costs::non_delegated_access_cost(
                target_is_cold,
                self.config.gas_ext_code_hash,
                self.config,
            ),

            GasCost::Balance { target_is_cold } => costs::non_delegated_access_cost(
                target_is_cold,
                self.config.gas_balance,
                self.config,
            ),
            GasCost::BlockHash => u64::from(consts::G_BLOCKHASH),
            GasCost::WarmStorageRead => costs::storage_read_warm(self.config),
        })
    }

    fn gas_refund(&self, cost: GasCost) -> i64 {
        match cost {
            _ if self.config.estimate => 0,

            GasCost::SStore {
                original,
                current,
                new,
                ..
            } => costs::sstore_refund(original, current, new, self.config),
            GasCost::Suicide {
                already_removed, ..
            } if !self.config.decrease_clears_refund => costs::suicide_refund(already_removed),
            _ => 0,
        }
    }
}

/// Gas cost.
#[derive(Debug, Clone, Copy)]
pub enum GasCost {
    /// Zero gas cost.
    Zero,
    /// Base gas cost.
    Base,
    /// Very low gas cost.
    VeryLow,
    /// Low gas cost.
    Low,
    /// Fail the gasometer.
    Invalid(Opcode),

    /// Gas cost for `EXTCODESIZE`.
    ExtCodeSize {
        /// True if address has not been previously accessed in this transaction
        target_is_cold: bool,
    },
    /// Gas cost for `BALANCE`.
    Balance {
        /// True if address has not been previously accessed in this transaction
        target_is_cold: bool,
    },
    /// Gas cost for `BLOCKHASH`.
    BlockHash,
    /// Gas cost for `EXTBLOCKHASH`.
    ExtCodeHash {
        /// True if address has not been previously accessed in this transaction
        target_is_cold: bool,
    },

    /// Gas cost for `CALL`.
    Call {
        /// Call value.
        value: U256,
        /// Call gas.
        gas: U256,
        /// True if target has not been previously accessed in this transaction
        target_is_cold: bool,
        /// True if delegated designator of authority has not been previously accessed in this transaction (EIP-7702)
        delegated_designator_is_cold: Option<bool>,
        /// Whether the target exists.
        target_exists: bool,
    },
    /// Gas cost for `CALLCODE`.
    CallCode {
        /// Call value.
        value: U256,
        /// Call gas.
        gas: U256,
        /// True if target has not been previously accessed in this transaction
        target_is_cold: bool,
        /// True if delegated designator of authority has not been previously accessed in this transaction (EIP-7702)
        delegated_designator_is_cold: Option<bool>,
        /// Whether the target exists.
        target_exists: bool,
    },
    /// Gas cost for `DELEGATECALL`.
    DelegateCall {
        /// Call gas.
        gas: U256,
        /// True if target has not been previously accessed in this transaction
        target_is_cold: bool,
        /// True if delegated designator of authority has not been previously accessed in this transaction (EIP-7702)
        delegated_designator_is_cold: Option<bool>,
        /// Whether the target exists.
        target_exists: bool,
    },
    /// Gas cost for `STATICCALL`.
    StaticCall {
        /// Call gas.
        gas: U256,
        /// True if target has not been previously accessed in this transaction
        target_is_cold: bool,
        /// True if delegated designator of authority has not been previously accessed in this transaction (EIP-7702)
        delegated_designator_is_cold: Option<bool>,
        /// Whether the target exists.
        target_exists: bool,
    },
    /// Gas cost for `SUICIDE`.
    Suicide {
        /// Value.
        value: U256,
        /// True if target has not been previously accessed in this transaction
        target_is_cold: bool,
        /// Whether the target exists.
        target_exists: bool,
        /// Whether the target has already been removed.
        already_removed: bool,
    },
    /// Gas cost for `SSTORE`.
    SStore {
        /// Original value.
        original: H256,
        /// Current value.
        current: H256,
        /// New value.
        new: H256,
        /// True if target has not been previously accessed in this transaction
        target_is_cold: bool,
    },
    /// Gas cost for `SHA3`.
    Sha3 {
        /// Length of the data.
        len: U256,
    },
    /// Gas cost for `LOG`.
    Log {
        /// Topic length.
        n: u8,
        /// Data length.
        len: U256,
    },
    /// Gas cost for `EXTCODECOPY`.
    ExtCodeCopy {
        /// True if target has not been previously accessed in this transaction
        target_is_cold: bool,
        /// Length.
        len: U256,
    },
    /// Gas cost for some copy opcodes that is documented as `VERYLOW`.
    VeryLowCopy {
        /// Length.
        len: U256,
    },
    /// Gas cost for `EXP`.
    Exp {
        /// Power of `EXP`.
        power: U256,
    },
    /// Gas cost for `CREATE`.
    Create,
    /// Gas cost for `CREATE2`.
    Create2 {
        /// Length.
        len: U256,
    },
    /// Gas cost for `SLOAD`.
    SLoad {
        /// True if target has not been previously accessed in this transaction
        target_is_cold: bool,
    },
    WarmStorageRead,
}

/// Storage opcode will access. Used for tracking accessed storage (EIP-2929).
#[derive(Debug, Clone, Copy)]
pub enum StorageTarget {
    /// No storage access
    None,
    /// Accessing address
    Address(H160),
    /// Accessing storage slot within an address
    Slot(H160, H256),
}

/// Memory cost.
#[derive(Debug, Clone, Copy)]
pub struct MemoryCost {
    /// Affected memory offset.
    pub offset: usize,
    /// Affected length.
    pub len: usize,
}

/// Transaction cost.
#[derive(Debug, Clone, Copy)]
pub enum TransactionCost {
    /// Call transaction cost.
    Call {
        /// Length of zeros in transaction data.
        zero_data_len: usize,
        /// Length of non-zeros in transaction data.
        non_zero_data_len: usize,
        /// Number of addresses in transaction access list (see EIP-2930)
        access_list_address_len: usize,
        /// Total number of storage keys in transaction access list (see EIP-2930)
        access_list_storage_len: usize,
        /// Number of authorities in transaction authorization list (see EIP-7702)
        authorization_list_len: usize,
    },
    /// Create transaction cost.
    Create {
        /// Length of zeros in transaction data.
        zero_data_len: usize,
        /// Length of non-zeros in transaction data.
        non_zero_data_len: usize,
        /// Number of addresses in transaction access list (see EIP-2930)
        access_list_address_len: usize,
        /// Total number of storage keys in transaction access list (see EIP-2930)
        access_list_storage_len: usize,
        /// Cost of initcode = 2 * ceil(len(initcode) / 32) (see EIP-3860)
        initcode_cost: u64,
    },
}

impl MemoryCost {
    /// Join two memory cost together.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        if self.len == 0 {
            return other;
        }

        if other.len == 0 {
            return self;
        }

        let self_end = self.offset.saturating_add(self.len);
        let other_end = other.offset.saturating_add(other.len);

        if self_end >= other_end {
            self
        } else {
            other
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intrinsic_gas_for_call_follows_eip_2028_2930_7702_and_7623() {
        let config = Config::prague();
        // 3 zero bytes, 5 non-zero bytes.
        let data = [0u8, 0, 0, 1, 2, 3, 4, 5];
        let access_list = vec![
            (
                H160::repeat_byte(1),
                vec![H256::repeat_byte(1), H256::repeat_byte(2)],
            ),
            (H160::repeat_byte(2), vec![H256::repeat_byte(3)]),
        ];
        let cost = call_transaction_cost(&data, &access_list, 1);

        let (gas, floor) = Gasometer::intrinsic_gas_and_gas_floor(cost, &config);

        assert_eq!(gas, 21000 + 4 * 3 + 16 * 5 + 2400 * 2 + 1900 * 3 + 25000);
        assert_eq!(floor, (5 * 4 + 3) * 10 + 21000);
    }

    #[test]
    fn intrinsic_gas_for_create_adds_initcode_cost_only_with_eip_3860() {
        // 33 bytes of initcode: 2 words, so EIP-3860 adds 2 * 2 = 4 gas.
        let data = [1u8; 33];
        let cost = create_transaction_cost(&data, &[]);

        let (shanghai_gas, shanghai_floor) =
            Gasometer::intrinsic_gas_and_gas_floor(cost, &Config::shanghai());
        let (istanbul_gas, istanbul_floor) =
            Gasometer::intrinsic_gas_and_gas_floor(cost, &Config::istanbul());

        assert_eq!(shanghai_gas, 53000 + 16 * 33 + 4);
        assert_eq!(shanghai_floor, 0);
        assert_eq!(istanbul_gas, 53000 + 16 * 33);
        assert_eq!(istanbul_floor, 0);
    }

    #[test]
    fn gas_floor_tokens_are_counted_in_u64() {
        // 2^30 non-zero bytes give 2^32 tokens, which does not fit a 32-bit `usize`.
        let cost = TransactionCost::Call {
            zero_data_len: 0,
            non_zero_data_len: 1 << 30,
            access_list_address_len: 0,
            access_list_storage_len: 0,
            authorization_list_len: 0,
        };

        let (_, floor) = Gasometer::intrinsic_gas_and_gas_floor(cost, &Config::prague());

        assert_eq!(floor, (1u64 << 32) * 10 + 21000);
    }

    #[test]
    fn check_gas_returns_memory_gas_and_fails_on_overflow() {
        let config = Config::prague();
        let mut gasometer = Gasometer::new(100, &config);
        let memory = Some(MemoryCost { offset: 0, len: 64 });
        let prepared = gasometer.check_gas(94, memory).unwrap();
        assert_eq!(prepared, 6);
        assert_eq!(gasometer.gas(), 100);
        gasometer
            .record_dynamic_cost_prepared(GasCost::Zero, memory, Some(prepared))
            .unwrap();
        assert_eq!(gasometer.gas(), 94);
        assert_eq!(gasometer.check_gas(94, memory), Ok(6));

        let mut unlimited = Gasometer::new(u64::MAX, &config);
        assert_eq!(
            unlimited.check_gas(u64::MAX, memory),
            Err(ExitError::OutOfGas)
        );
        assert_eq!(unlimited.gas(), 0);
    }
}
