//! Transaction validation and fee calculations derived from a block environment.
//!
//! [`EvmContext`] combines a [`BlockEnv`], a [`TxEnv`] and the active [`Spec`]. It validates the
//! transaction fields that do not require mutable world state; sender nonce, balance and code checks
//! remain in the block executor.

use crate::block::BlockEnv;
use crate::eips::eip4844;
use crate::eips::eip4844::DATA_GAS_PER_BLOB;
use crate::eips::eip7825;
use crate::errors::{InvalidHeader, InvalidTransaction};
use crate::spec::Spec;
use crate::transaction::{TxEnv, TxType};

use aurora_evm::Config;
use aurora_evm::gasometer::Gasometer;
use core::fmt;
use primitive_types::{H256, U256};

/// Blob gas a transaction consumes for `blob_count` blobs.
///
/// Saturating: a blob count large enough to overflow cannot come from a decoded transaction, and a
/// saturated value only ever exceeds a limit, never slips under one.
fn total_blob_gas(blob_count: usize) -> u64 {
    u64::try_from(blob_count)
        .unwrap_or(u64::MAX)
        .saturating_mul(DATA_GAS_PER_BLOB)
}

/// A transaction's intrinsic gas and, from Prague, EIP-7623 floor gas.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IntrinsicAndFloorGas {
    /// Gas charged before execution.
    pub intrinsic_gas: u64,
    /// Minimum total gas charged under EIP-7623.
    pub floor_gas: u64,
}

impl IntrinsicAndFloorGas {
    #[must_use]
    #[inline]
    pub const fn new(intrinsic_gas: u64, floor_gas: u64) -> Self {
        Self {
            intrinsic_gas,
            floor_gas,
        }
    }
}

/// Immutable validation context for one transaction in one block.
#[derive(Clone, Debug)]
pub struct EvmContext<'block, 'tx> {
    /// EIP-155 chain id.
    pub chain_id: u64,
    /// Current block environment.
    pub block: &'block BlockEnv,
    /// Transaction being validated.
    pub tx: &'tx TxEnv,
    /// Aurora EVM gas rules for the active hardfork.
    pub gas_config: Config,
    /// Active hardfork.
    pub spec: Spec,

    /// Optional override for the Osaka EIP-7825 transaction gas cap.
    pub tx_gas_limit_cap: Option<u64>,
}

impl<'block, 'tx> EvmContext<'block, 'tx> {
    #[must_use]
    pub const fn new(
        chain_id: u64,
        block: &'block BlockEnv,
        tx: &'tx TxEnv,
        spec: &Spec,
        tx_gas_limit_cap: Option<u64>,
    ) -> Self {
        Self {
            chain_id,
            block,
            tx,
            gas_config: spec.get_gasometer_config(),
            spec: *spec,
            tx_gas_limit_cap,
        }
    }

    /// Whether EIP-2930 is active and this is an EIP-2930 transaction.
    #[must_use]
    #[inline]
    pub fn is_tx_eip2930(&self) -> bool {
        self.spec >= Spec::Berlin && self.tx.tx_type == TxType::Eip2930
    }

    /// Whether EIP-1559 is active and this is an EIP-1559 transaction.
    #[must_use]
    #[inline]
    pub fn is_tx_eip1559(&self) -> bool {
        self.spec >= Spec::London && self.tx.tx_type == TxType::Eip1559
    }

    /// Whether EIP-4844 is active and this is a blob transaction.
    #[must_use]
    #[inline]
    pub fn is_tx_eip4844(&self) -> bool {
        self.spec >= Spec::Cancun && self.tx.tx_type == TxType::Eip4844
    }

    /// Whether EIP-7702 is active and this is a set-code transaction.
    #[must_use]
    #[inline]
    pub fn is_tx_eip7702(&self) -> bool {
        self.spec >= Spec::Prague && self.tx.tx_type == TxType::Eip7702
    }

    /// Calculates the **maximum** [EIP-4844] blob `data_fee`, at the transaction's
    /// `max_fee_per_blob_gas`. This is the amount reserved up front against the sender's balance;
    /// the amount actually charged and burned is [`Self::calc_data_fee`], computed at the block's
    /// current blob gas price (which is `<=` the max after validation). `None` for non-blob
    /// transactions.
    ///
    /// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
    #[inline]
    #[must_use]
    pub fn calc_max_data_fee(&self) -> Option<U256> {
        self.is_tx_eip4844().then(|| {
            U256::from(self.tx.max_fee_per_blob_gas).saturating_mul(U256::from(total_blob_gas(
                self.tx.blob_versioned_hashes.len(),
            )))
        })
    }

    /// Calculates the **actual** [EIP-4844] blob `data_fee`, at the block's current blob gas price.
    /// This is the amount charged and burned — contrast [`Self::calc_max_data_fee`], which reserves
    /// up front at the transaction's `max_fee_per_blob_gas`. `None` for non-blob transactions.
    ///
    /// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
    #[inline]
    #[must_use]
    pub fn calc_data_fee(&self) -> Option<U256> {
        self.is_tx_eip4844().then(|| {
            let blob_gas_price = self
                .block
                .blob_excess_gas_and_price
                .unwrap_or_default()
                .blob_gas_price;
            U256::from(blob_gas_price).saturating_mul(U256::from(total_blob_gas(
                self.tx.blob_versioned_hashes.len(),
            )))
        })
    }

    /// Returns the transaction gas limit as a [`U256`].
    #[must_use]
    pub fn get_gas_limit(&self) -> U256 {
        U256::from(self.tx.gas_limit)
    }

    /// Validates that the caller can cover gas, value and the maximum blob fee.
    ///
    /// # Errors
    /// Returns [`InvalidTransaction::OutOfFunds`] if the sum overflows or exceeds
    /// `caller_balance`.
    pub fn validate_required_funds(
        &self,
        caller_balance: U256,
    ) -> Result<&Self, InvalidEvmContext> {
        let required_funds = self
            .get_gas_limit()
            .checked_mul(self.get_gas_price())
            .and_then(|v| v.checked_add(self.tx.value))
            .ok_or(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::OutOfFunds,
            ))
            .and_then(|funds| {
                // Upfront balance check must reserve the MAX blob fee (max_fee_per_blob_gas),
                // not the current effective blob price.
                self.calc_max_data_fee()
                    .map(|data_fee| {
                        funds
                            .checked_add(data_fee)
                            .ok_or(InvalidEvmContext::InvalidTransaction(
                                InvalidTransaction::OutOfFunds,
                            ))
                    })
                    .transpose()
                    .map(|opt| opt.unwrap_or(funds))
            })?;

        if caller_balance < required_funds {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::OutOfFunds,
            ));
        }

        Ok(self)
    }

    /// Validates the transaction's header-dependent, type-specific and intrinsic-gas rules.
    ///
    /// # Errors
    /// Returns [`InvalidEvmContext`] for the first invalid header or transaction rule.
    pub fn validate_tx(&self) -> Result<&Self, InvalidEvmContext> {
        if self.spec >= Spec::Merge && self.block.block_randomness.is_none() {
            return Err(InvalidEvmContext::InvalidHeader(
                InvalidHeader::PrevrandaoNotSet,
            ));
        }

        // EIP-4844: Blob Transactions
        if self.spec >= Spec::Cancun && self.block.blob_excess_gas_and_price.is_none() {
            return Err(InvalidEvmContext::InvalidHeader(
                InvalidHeader::ExcessBlobGasNotSet,
            ));
        }

        if self.spec < Spec::Cancun && self.block.blob_excess_gas_and_price.is_some() {
            return Err(InvalidEvmContext::InvalidHeader(
                InvalidHeader::ExcessBlobGasNotSupported,
            ));
        }

        // EIP-155: simple replay attack protection. Unconditional — the chain a block belongs to
        // is not optional. Only a legacy transaction may omit its own `chain_id`, which selects the
        // six-field signing preimage over the nine-field one; every typed transaction must carry it.
        if self.tx.tx_type != TxType::Legacy && self.tx.chain_id.is_none() {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::MissingChainId,
            ));
        }
        if self.tx.chain_id.is_some_and(|id| id != self.chain_id) {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::InvalidChainId,
            ));
        }

        // EIP-7825: Transaction Gas Limit Cap.
        if self.spec >= Spec::Osaka {
            let cap = self.tx_gas_limit_cap.unwrap_or(eip7825::TX_GAS_LIMIT_CAP);
            if self.tx.gas_limit > cap {
                return Err(InvalidEvmContext::InvalidTransaction(
                    InvalidTransaction::TxGasLimitGreaterThanCap {
                        gas_limit: self.tx.gas_limit,
                        cap,
                    },
                ));
            }
        }

        if self.tx.gas_limit > self.block.block_gas_limit {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::CallerGasLimitMoreThanBlock,
            ));
        }

        match self.tx.tx_type {
            TxType::Legacy => {
                self.validate_legacy_tx()?;
            }
            TxType::Eip2930 => {
                self.validate_eip2930_tx()?;
            }
            TxType::Eip1559 => {
                self.validate_eip1559_tx()?;
            }
            TxType::Eip4844 => {
                self.validate_eip4844_tx()?;
            }
            TxType::Eip7702 => {
                self.validate_eip7702_tx()?;
            }
        }

        // Authorization List is only supported for EIP-7702 transactions, so if the transaction
        // is not of type EIP-7702 and has non-empty authorization list, it is invalid.
        if !matches!(self.tx.tx_type, TxType::Eip7702) && !self.tx.authorization_list.is_empty() {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::AuthorizationListNotSupported,
            ));
        }

        // Blob versioned hashes are an EIP-4844 field: any other transaction type carrying them
        // is invalid.
        if !matches!(self.tx.tx_type, TxType::Eip4844) && !self.tx.blob_versioned_hashes.is_empty()
        {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::UnexpectedBlobHashes,
            ));
        }

        // An access list is an EIP-2930 field, and a legacy transaction has no field for it: the
        // encoder never writes one, so a non-empty one here is state no signature covered. Unlike the
        // two checks above it is also *read* — it feeds intrinsic gas and pre-warms addresses and
        // slots — so it has to be rejected before the gas computation below.
        if matches!(self.tx.tx_type, TxType::Legacy) && !self.tx.access_list.is_empty() {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::UnexpectedAccessList,
            ));
        }

        // Intrinsic / floor gas (EIP-7623), using the execution-ready access list. Sender-state,
        // required-funds and block-total checks remain with the block executor.
        self.validate_and_get_initial_tx_gas()?;

        Ok(self)
    }

    /// Validates legacy fee fields and the gas price against the block base fee.
    ///
    /// # Errors
    /// Returns [`InvalidEvmContext`] for missing, incompatible or insufficient fee fields.
    #[inline]
    pub fn validate_legacy_gas_price(&self) -> Result<(), InvalidEvmContext> {
        if self.tx.max_fee_per_gas.is_some() || self.tx.max_priority_fee_per_gas.is_some() {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::UnexpectedPriorityFeeFields,
            ));
        }

        let gas_price = self
            .tx
            .gas_price
            .ok_or(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::InvalidGasPrice,
            ))?;
        if gas_price < self.block.block_base_fee_per_gas {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::GasPriceLessThanBasefee,
            ));
        }
        Ok(())
    }

    /// Validates EIP-1559-style fee fields against each other and the block base fee.
    ///
    /// # Errors
    /// Returns [`InvalidEvmContext`] for missing, incompatible or inconsistent fee fields.
    pub fn validate_priority_fee(&self) -> Result<(), InvalidEvmContext> {
        // A typed (EIP-1559/4844/7702) transaction must not carry a legacy `gas_price` field;
        // otherwise the fee source would be ambiguous.
        if self.tx.gas_price.is_some() {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::UnexpectedGasPriceField,
            ));
        }
        let max_fee_per_gas =
            self.tx
                .max_fee_per_gas
                .ok_or(InvalidEvmContext::InvalidTransaction(
                    InvalidTransaction::InvalidMaxFeePerGas,
                ))?;
        let max_priority_fee_per_gas =
            self.tx
                .max_priority_fee_per_gas
                .ok_or(InvalidEvmContext::InvalidTransaction(
                    InvalidTransaction::InvalidMaxPriorityFeePerGas,
                ))?;

        if max_priority_fee_per_gas > max_fee_per_gas {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::PriorityFeeTooLarge,
            ));
        }

        if max_fee_per_gas < self.block.block_base_fee_per_gas {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::GasPriceLessThanBasefee,
            ));
        }

        Ok(())
    }

    /// Validates a legacy transaction.
    ///
    /// # Errors
    /// Returns [`InvalidEvmContext`] if its fee fields are invalid.
    fn validate_legacy_tx(&self) -> Result<(), InvalidEvmContext> {
        self.validate_legacy_gas_price()
    }

    /// Validates an EIP-2930 transaction.
    ///
    /// # Errors
    /// Returns [`InvalidEvmContext`] if the fork or fee fields are invalid.
    pub fn validate_eip2930_tx(&self) -> Result<(), InvalidEvmContext> {
        if self.spec < Spec::Berlin {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::Eip2930NotSupported,
            ));
        }
        self.validate_legacy_gas_price()
    }

    /// Validates an EIP-1559 transaction.
    ///
    /// # Errors
    /// Returns [`InvalidEvmContext`] if the fork or fee fields are invalid.
    pub fn validate_eip1559_tx(&self) -> Result<(), InvalidEvmContext> {
        if self.spec < Spec::London {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::Eip1559NotSupported,
            ));
        }
        self.validate_priority_fee()
    }

    /// Validates EIP-4844 blob fields apart from schedule-dependent count limits.
    ///
    /// # Errors
    /// Returns [`InvalidEvmContext`] for an invalid blob fee, destination or versioned hash.
    pub fn validate_blobs(&self) -> Result<(), InvalidEvmContext> {
        let blob_gas_price = self
            .block
            .blob_excess_gas_and_price
            .unwrap_or_default()
            .blob_gas_price;
        // Ensure that the sender was willing to pay the current blob gas price.
        if blob_gas_price > self.tx.max_fee_per_blob_gas {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::BlobGasPriceGreaterThanMax,
            ));
        }

        // There must be at least one blob
        if self.tx.blob_versioned_hashes.is_empty() {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::EmptyBlobs,
            ));
        }

        // The field `to` deviates slightly from the semantics with the exception
        // that it MUST NOT be nil and therefore must always represent
        // a 20-byte address. This means that blob transactions cannot
        // have the form of a `create` transaction.
        if self.tx.tx_kind.is_create() {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::BlobCreateTransaction,
            ));
        }

        // All versioned blob hashes must start with VERSIONED_HASH_VERSION_KZG
        for blob_hash in &self.tx.blob_versioned_hashes {
            let blob_hash = H256(blob_hash.to_big_endian());
            if blob_hash[0] != eip4844::VERSIONED_HASH_VERSION_KZG {
                return Err(InvalidEvmContext::InvalidTransaction(
                    InvalidTransaction::BlobVersionNotSupported,
                ));
            }
        }

        // The per-transaction and per-block blob-count limits are enforced by the block layer
        // against the active `BlobParams` (EIP-7594 / EIP-7840), not from a `Spec` comparison here.
        Ok(())
    }

    /// Validates an EIP-4844 transaction.
    ///
    /// # Errors
    /// Returns [`InvalidEvmContext`] if the fork, fee or blob fields are invalid.
    pub fn validate_eip4844_tx(&self) -> Result<(), InvalidEvmContext> {
        if self.spec < Spec::Cancun {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::Eip4844NotSupported,
            ));
        }
        self.validate_priority_fee()?;
        self.validate_blobs()?;

        Ok(())
    }

    /// Validates an EIP-7702 transaction.
    ///
    /// # Errors
    /// Returns [`InvalidEvmContext`] if the fork, fee, authorization list or destination is invalid.
    pub fn validate_eip7702_tx(&self) -> Result<(), InvalidEvmContext> {
        if self.spec < Spec::Prague {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::Eip7702NotSupported,
            ));
        }
        self.validate_priority_fee()?;

        // `authorization_list` must be present
        if self.tx.authorization_list.is_empty() {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::EmptyAuthorizationList,
            ));
        }

        // EIP-7702 - if transaction is contract creation - validation fails
        if self.tx.tx_kind.is_create() {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::Eip7702CreateTransaction,
            ));
        }

        Ok(())
    }

    /// Calculates and validates the transaction's intrinsic and EIP-7623 floor gas.
    ///
    /// # Errors
    /// Returns [`InvalidEvmContext`] if either required gas amount exceeds the transaction limit.
    #[inline]
    pub fn validate_and_get_initial_tx_gas(
        &self,
    ) -> Result<IntrinsicAndFloorGas, InvalidEvmContext> {
        let authorization_list_len = self.tx.authorization_list.len();
        let (intrinsic_gas, floor_gas) = Gasometer::calculate_intrinsic_gas_and_gas_floor(
            &self.tx.data,
            &self.tx.access_list,
            authorization_list_len,
            &self.gas_config,
            self.tx.tx_kind.is_create(),
        );

        if intrinsic_gas > self.tx.gas_limit {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::IntrinsicGasMoreThanGasLimit,
            ));
        }

        // EIP-7623 validation
        if self.spec >= Spec::Prague && floor_gas > self.tx.gas_limit {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::FloorGasMoreThanGasLimit,
            ));
        }

        Ok(IntrinsicAndFloorGas {
            intrinsic_gas,
            floor_gas,
        })
    }

    /// Returns the transaction's validated fee cap.
    ///
    /// The fee source is chosen by **transaction type**, never by fork or by which field happens
    /// to be populated: legacy and EIP-2930 use `gas_price`, EIP-1559/4844/7702 use
    /// `max_fee_per_gas`. `validate_tx` rejects the incompatible field combinations, so this is
    /// unambiguous for a validated transaction.
    #[must_use]
    pub fn get_gas_price(&self) -> U256 {
        match self.tx.tx_type {
            TxType::Legacy | TxType::Eip2930 => self.tx.gas_price.unwrap_or_default(),
            TxType::Eip1559 | TxType::Eip4844 | TxType::Eip7702 => {
                self.tx.max_fee_per_gas.unwrap_or_default()
            }
        }
    }

    /// Returns the effective gas price at this block's base fee.
    #[must_use]
    pub fn get_effective_gas_price(&self) -> U256 {
        let gas_price = self.get_gas_price();
        let block_base_fee_per_gas = self.block.block_base_fee_per_gas;
        self.tx
            .max_priority_fee_per_gas
            .map_or(gas_price, |max_priority_fee_per_gas| {
                gas_price.min(max_priority_fee_per_gas.saturating_add(block_base_fee_per_gas))
            })
    }
}

/// A header- or transaction-level failure detected by [`EvmContext`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InvalidEvmContext {
    /// Invalid block environment.
    InvalidHeader(InvalidHeader),
    /// Invalid transaction.
    InvalidTransaction(InvalidTransaction),
}

impl core::error::Error for InvalidEvmContext {}

impl fmt::Display for InvalidEvmContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeader(header) => write!(f, "invalid header: {header}"),
            Self::InvalidTransaction(tx) => write!(f, "invalid transaction: {tx}"),
        }
    }
}
