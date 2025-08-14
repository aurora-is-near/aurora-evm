//! EIP-4844 constants and helpers for blob gas pricing.

use crate::types::transaction::Transaction;
use crate::types::StateEnv;
use aurora_evm::Config;
use primitive_types::U256;
use serde::Deserialize;

/// Controls the maximum rate of change for blob gas price
pub const BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN: u64 = 3_338_477;

/// Controls the maximum rate of change for blob gas price
pub const BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE: u64 = 5_007_716;

/// First version of the blob
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

/// Gas consumption of a single data blob (== blob byte size)
pub const GAS_PER_BLOB: u64 = 1 << 17;

/// Min blob gas price
pub const MIN_BLOB_GASPRICE: u64 = 1;

/// Target number of the blob per block
pub const TARGET_BLOB_NUMBER_PER_BLOCK_CANCUN: u64 = 3;

/// Max number of blobs per block
pub const MAX_BLOB_NUMBER_PER_BLOCK_CANCUN: u64 = 2 * TARGET_BLOB_NUMBER_PER_BLOCK_CANCUN;

/// Maximum consumable blob gas for data blobs per block
pub const MAX_BLOB_GAS_PER_BLOCK_CANCUN: u64 = MAX_BLOB_NUMBER_PER_BLOCK_CANCUN * GAS_PER_BLOB;

/// Target consumable blob gas for data blobs per block: EIP-7691
pub const TARGET_BLOB_GAS_PER_BLOCK: u64 = 786_432;

/// Target number of the blob per block
pub const TARGET_BLOB_NUMBER_PER_BLOCK_PRAGUE: u64 = 6;

/// Max number of blobs per block
pub const MAX_BLOB_NUMBER_PER_BLOCK_PRAGUE: u64 = 9;

/// Maximum consumable blob gas for data blobs per block
pub const MAX_BLOB_GAS_PER_BLOCK_PRAGUE: u64 = MAX_BLOB_NUMBER_PER_BLOCK_PRAGUE * GAS_PER_BLOB;

/// Target consumable blob gas for data blobs per block (for 1559-like pricing)
pub const TARGET_BLOB_GAS_PER_BLOCK_PRAGUE: u64 =
    TARGET_BLOB_NUMBER_PER_BLOCK_PRAGUE * GAS_PER_BLOB;

/// Structure holding block blob excess gas and it calculates blob fee
///
/// Incorporated as part of the Cancun upgrade via [EIP-4844].
///
/// [EIP-4844]: <https://eips.ethereum.org/EIPS/eip-4844>
#[derive(Copy, Clone, Debug, Ord, PartialOrd, PartialEq, Eq, Deserialize)]
pub struct BlobExcessGasAndPrice {
    /// The excess blob gas of the block
    pub excess_blob_gas: u64,
    /// The calculated blob gas price based on the `excess_blob_gas`
    ///
    /// See [`calc_blob_gas_price`]
    pub blob_gas_price: u128,
}

impl BlobExcessGasAndPrice {
    /// Creates a new instance by calculating the blob gas price with [`calc_blob_gasprice`].
    #[must_use]
    pub fn new(excess_blob_gas: u64) -> Self {
        let blob_gas_price = calc_blob_gas_price(excess_blob_gas);
        Self {
            excess_blob_gas,
            blob_gas_price,
        }
    }

    /// Calculate this block excess gas and price from the parent excess gas and gas used
    /// and the target blob gas per block.
    ///
    /// This fields will be used to calculate `excess_blob_gas` with [`calc_excess_blob_gas`] func.
    #[must_use]
    pub fn from_parent(parent_excess_blob_gas: u64, parent_blob_gas_used: u64) -> Self {
        Self::new(calc_excess_blob_gas(
            parent_excess_blob_gas,
            parent_blob_gas_used,
        ))
    }

    /// Initializes the ``BlobExcessGasAndPrice`` from the environment state.
    #[must_use]
    pub fn from_env(env: &StateEnv) -> Option<Self> {
        env.current_excess_blob_gas.map(Self::new).or_else(|| {
            env.parent_blob_gas_used
                .zip(env.parent_excess_blob_gas)
                .map(|(parent_blob_gas_used, parent_excess_blob_gas)| {
                    Self::from_parent(parent_excess_blob_gas, parent_blob_gas_used)
                })
        })
    }
}

/// Calculates the `excess_blob_gas` from the parent header's `blob_gas_used` and `excess_blob_gas`.
///
/// See also [the EIP-4844 helpers]<https://eips.ethereum.org/EIPS/eip-4844#helpers>
#[inline]
#[must_use]
pub const fn calc_excess_blob_gas(parent_excess_blob_gas: u64, parent_blob_gas_used: u64) -> u64 {
    (parent_excess_blob_gas + parent_blob_gas_used).saturating_sub(TARGET_BLOB_GAS_PER_BLOCK)
}

/// Calculates the blob gas price from the header's excess blob gas field.
///
/// See also [the EIP-4844 helpers](https://eips.ethereum.org/EIPS/eip-4844#helpers)
#[inline]
#[must_use]
pub fn calc_blob_gas_price(excess_blob_gas: u64) -> u128 {
    fake_exponential(
        MIN_BLOB_GASPRICE,
        excess_blob_gas,
        BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN,
    )
}

/// Approximates `factor * e ** (numerator / denominator)` using Taylor expansion.
///
/// This is used to calculate the blob price.
///
/// See also [the EIP-4844 helpers](https://eips.ethereum.org/EIPS/eip-4844#helpers)
/// (`fake_exponential`).
///
/// # Panics
///
/// This function panics if `denominator` is zero.
#[inline]
#[must_use]
pub fn fake_exponential(factor: u64, numerator: u64, denominator: u64) -> u128 {
    assert_ne!(denominator, 0, "attempt to divide by zero");
    let factor = u128::from(factor);
    let numerator = u128::from(numerator);
    let denominator = u128::from(denominator);

    let mut i = 1;
    let mut output = 0;
    let mut numerator_accum = factor * denominator;
    while numerator_accum > 0 {
        output += numerator_accum;

        // Denominator is asserted as not zero at the start of the function.
        numerator_accum = (numerator_accum * numerator) / (denominator * i);
        i += 1;
    }
    output / denominator
}

/// Calculates the [EIP-4844] `data_fee` of the transaction.
///
/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
#[inline]
#[must_use]
pub fn calc_max_data_fee(config: &Config, tx: &Transaction) -> Option<U256> {
    config.has_shard_blob_transactions.then(|| {
        tx.max_fee_per_blob_gas
            .unwrap_or_default()
            .saturating_mul(U256::from(get_total_blob_gas(
                tx.blob_versioned_hashes.len(),
            )))
    })
}

/// Calculates the [EIP-4844] `data_fee` of the transaction.
///
/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
#[inline]
#[must_use]
pub fn calc_data_fee(
    config: &Config,
    tx: &Transaction,
    blob_gas_price: Option<&BlobExcessGasAndPrice>,
) -> Option<U256> {
    config.has_shard_blob_transactions.then(|| {
        U256::from(
            blob_gas_price
                .expect("expect blob_gas_price")
                .blob_gas_price,
        )
        .saturating_mul(U256::from(get_total_blob_gas(
            tx.blob_versioned_hashes.len(),
        )))
    })
}

/// See [EIP-4844], [`calc_max_data_fee`]
///
/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
#[inline]
#[must_use]
pub const fn get_total_blob_gas(blob_hashes_len: usize) -> u64 {
    GAS_PER_BLOB * blob_hashes_len as u64
}
