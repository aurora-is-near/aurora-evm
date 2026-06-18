use crate::blob;
use crate::block::BlockEnv;
use crate::errors::{InvalidHeader, InvalidTransaction};
use crate::spec::Spec;
use crate::transaction::{eip7825, Transaction, TxType};

use aurora_evm::gasometer::Gasometer;
use aurora_evm::Config;
use primitive_types::{H256, U256};
use std::fmt;

/// Init and floor gas from transaction
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IntrinsicAndFloorGas {
    /// Intrinsic gas for transaction.
    pub intrinsic_gas: u64,
    /// If transaction is a Call and Prague is enabled
    /// Floor gas is at least amount of gas that is going to be spent.
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

#[derive(Clone, Debug)]
pub struct EvmContext<'block, 'tx> {
    pub chain_id: Option<u64>,
    pub block: &'block BlockEnv,
    pub tx: &'tx Transaction,
    pub gas_config: Config,
    pub spec: Spec,

    /// Configures the gas limit cap for the transaction.
    /// Introduced in `Osaka` hard fork [EIP-7825: Transaction Gas Limit Cap](https://eips.ethereum.org/EIPS/eip-7825) .
    pub tx_gas_limit_cap: Option<u64>,
}

impl<'block, 'tx> EvmContext<'block, 'tx> {
    #[must_use]
    pub fn new(
        chain_id: Option<u64>,
        block: &'block BlockEnv,
        tx: &'tx Transaction,
        spec: &Spec,
        tx_gas_limit_cap: Option<u64>,
    ) -> Self {
        Self {
            chain_id,
            block,
            tx,
            gas_config: (*spec).get_gasometer_config(),
            spec: spec.clone(),
            tx_gas_limit_cap,
        }
    }

    /// Checks if the transaction is an `EIP-2930` transaction.
    #[must_use]
    #[inline]
    pub fn is_tx_eip2930(&self) -> bool {
        self.spec >= Spec::Berlin && self.tx.tx_type == TxType::Eip2930
    }

    /// Checks if the transaction is an `EIP-1559` transaction.
    #[must_use]
    #[inline]
    pub fn is_tx_eip1559(&self) -> bool {
        self.spec >= Spec::London && self.tx.tx_type == TxType::Eip1559
    }

    /// Checks if the transaction is an `EIP-4844` blob transaction.
    #[must_use]
    #[inline]
    pub fn is_tx_eip4844(&self) -> bool {
        self.spec >= Spec::Cancun && self.tx.tx_type == TxType::Eip4844
    }

    /// Checks if the transaction is an `EIP-7702` transaction.
    #[must_use]
    #[inline]
    pub fn is_tx_eip7702(&self) -> bool {
        self.spec >= Spec::Prague && self.tx.tx_type == TxType::Eip7702
    }

    /// Calculates the [EIP-4844] `data_fee` of the transaction.
    ///
    /// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
    #[inline]
    #[must_use]
    pub fn calc_max_data_fee(&self) -> Option<U256> {
        self.is_tx_eip4844().then(|| {
            U256::from(self.tx.max_fee_per_blob_gas).saturating_mul(U256::from(
                blob::get_total_blob_gas(self.tx.blob_versioned_hashes.len()),
            ))
        })
    }

    /// Calculates the [EIP-4844] `data_fee` of the transaction.
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
            U256::from(blob_gas_price).saturating_mul(U256::from(blob::get_total_blob_gas(
                self.tx.blob_versioned_hashes.len(),
            )))
        })
    }

    /// Get EVM gas limit as `U256` value
    #[must_use]
    pub fn get_gas_limit(&self) -> U256 {
        U256::from(self.tx.gas_limit)
    }

    /// Validates that the caller has enough funds to cover the transaction cost, including gas fee,
    /// value transfer, and data fee (if applicable).
    ///
    /// ## Errors
    /// If the caller does not have enough funds, returns an `OutOfFunds`
    pub fn validate_required_funds(&self, caller_balance: U256) -> Result<(), InvalidEvmContext> {
        let required_funds = self
            .get_gas_limit()
            .checked_mul(self.get_gas_price())
            .and_then(|v| v.checked_add(self.tx.value))
            .ok_or(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::OutOfFunds,
            ))
            .and_then(|funds| {
                self.calc_data_fee()
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

        Ok(())
    }

    /// Calculates the total fee for the caller, including gas fee, value transfer, and
    /// data fee (if applicable).
    #[must_use]
    pub fn calc_total_charge_fee(&self) -> U256 {
        let total_fee =
            self.get_effective_gas_price() * U256::from(self.tx.gas_limit) + self.tx.value;
        self.calc_data_fee()
            .map_or(total_fee, |data_fee| total_fee + data_fee)
    }

    /// Validates the EVM context transaction.
    ///
    /// ## Errors
    /// If the context is invalid, returns an `InvalidEvmContext` error.
    pub fn validate_tx(&self) -> Result<(), InvalidEvmContext> {
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

        if self.spec < Spec::Cancun {
            if self.block.blob_excess_gas_and_price.is_some() {
                return Err(InvalidEvmContext::InvalidHeader(
                    InvalidHeader::MaxFeePerBlobGasNotSupported,
                ));
            }
            if !self.block.blob_hashes.is_empty() {
                return Err(InvalidEvmContext::InvalidHeader(
                    InvalidHeader::BlobVersionedHashesNotSupported,
                ));
            }
        }

        // If `chain_id` not set for `EvmContext` config, skip this check.
        // EIP-155: Simple replay attack protection
        if let Some(cfg_chain_id) = self.chain_id {
            // Legacy transaction are the only one that can omit chain_id.
            if self.tx.tx_type > TxType::Legacy && self.tx.chain_id.is_none() {
                return Err(InvalidEvmContext::InvalidTransaction(
                    InvalidTransaction::MissingChainId,
                ));
            }
            if self.tx.chain_id.is_some_and(|id| id != cfg_chain_id) {
                return Err(InvalidEvmContext::InvalidTransaction(
                    InvalidTransaction::InvalidChainId,
                ));
            }
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

        if let Some(block_gas_limit) = self.block.block_gas_limit {
            if self.tx.gas_limit > block_gas_limit {
                return Err(InvalidEvmContext::InvalidTransaction(
                    InvalidTransaction::CallerGasLimitMoreThanBlock,
                ));
            }
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

        // Validation intrinsic and floor gas
        let _ = self.validate_initial_tx_gas()?;

        Ok(())
    }

    /// Validate legacy transaction gas price against basefee.
    ///
    /// ## Errors
    /// Return validation gas price error.
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

    /// Validate transaction that has `EIP-1559` priority fee
    ///
    /// ### Errors
    /// Returns validation error if the transaction has invalid data.
    pub fn validate_priority_fee(&self) -> Result<(), InvalidEvmContext> {
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

    /// Validate legacy transaction.
    ///
    /// ### Errors
    /// Returns validation error if the transaction has invalid data.
    fn validate_legacy_tx(&self) -> Result<(), InvalidEvmContext> {
        self.validate_legacy_gas_price()
    }

    /// Validate `EIP-2930` transaction.
    ///
    /// ### Errors
    /// Returns validation error if the transaction has invalid data.
    pub fn validate_eip2930_tx(&self) -> Result<(), InvalidEvmContext> {
        if self.spec < Spec::Berlin {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::Eip2930NotSupported,
            ));
        }
        self.validate_legacy_gas_price()
    }

    /// Validate `EIP-1559` transaction.
    ///
    /// ### Errors
    /// Returns validation error if the transaction has invalid data.
    pub fn validate_eip1559_tx(&self) -> Result<(), InvalidEvmContext> {
        if self.spec < Spec::London {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::Eip1559NotSupported,
            ));
        }
        self.validate_priority_fee()
    }

    /// Validate `EIP-4844` blobs.
    ///
    /// ### Errors
    /// Returns validation error if the transaction has invalid data.
    pub fn validate_blobs(&self) -> Result<(), InvalidEvmContext> {
        // NOTE: we already validate that `blob_excess_gas_and_price` is set in `validate_tx` method, so it is safe to unwrap here.
        let blob_gas_price = self
            .block
            .blob_excess_gas_and_price
            .unwrap_or_default()
            .blob_gas_price;
        // Ensure that the user was willing to at least pay the current blob gasprice
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
            if blob_hash[0] != blob::VERSIONED_HASH_VERSION_KZG {
                return Err(InvalidEvmContext::InvalidTransaction(
                    InvalidTransaction::BlobVersionNotSupported,
                ));
            }
        }

        // Ensure the total blob gas spent is at most equal to the limit
        // assert blob_gas_used <= MAX_BLOB_GAS_PER_BLOCK
        // EIP-7691
        let max_blob_len = if self.spec == Spec::Cancun {
            blob::MAX_BLOBS_PER_BLOCK_CANCUN
        } else {
            blob::MAX_BLOBS_PER_BLOCK_ELECTRA
        };
        if self.tx.blob_versioned_hashes.len() > max_blob_len {
            return Err(InvalidEvmContext::InvalidTransaction(
                InvalidTransaction::TooManyBlobs(max_blob_len),
            ));
        }

        Ok(())
    }

    /// Validate `EIP-4844` transaction.
    ///
    /// ### Errors
    /// Returns validation error if the transaction has invalid data.
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

    /// Validate `EIP-7702` transaction.
    ///
    /// ### Errors
    /// Returns validation error if the transaction has invalid data.
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

    /// Calculates the intrinsic and floor gas for the transaction in and validate it.
    ///
    /// ## Errors
    /// Return validation error
    pub fn validate_initial_tx_gas(&self) -> Result<IntrinsicAndFloorGas, InvalidEvmContext> {
        let access_list = self.tx.access_list.flattened();
        let authorization_list_len = self.tx.authorization_list.len();
        let (intrinsic_gas, floor_gas) = Gasometer::calculate_intrinsic_gas_and_gas_floor(
            &self.tx.data,
            &access_list,
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

    /// Get EVM gas price
    #[must_use]
    pub fn get_gas_price(&self) -> U256 {
        if self.spec >= Spec::London {
            self.tx.max_fee_per_gas.unwrap_or_default()
        } else {
            self.tx.gas_price.unwrap_or_default()
        }
    }

    /// Get EVM effective gas price
    #[must_use]
    pub fn get_effective_gas_price(&self) -> U256 {
        let gas_price = self.get_gas_price();
        let block_base_fee_per_gas = self.block.block_base_fee_per_gas;
        self.tx
            .max_priority_fee_per_gas
            .map_or(gas_price, |max_priority_fee_per_gas| {
                gas_price.min(max_priority_fee_per_gas + block_base_fee_per_gas)
            })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InvalidEvmContext {
    InvalidHeader(InvalidHeader),
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
