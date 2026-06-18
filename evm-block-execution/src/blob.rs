use serde::{Deserialize, Serialize};

/// EIP-4844 constants
/// Gas consumption of a single data blob (== blob byte size).
pub const GAS_PER_BLOB: u64 = 1 << 17;
/// Max number of blobs per block: EIP-7691
pub const MAX_BLOBS_PER_BLOCK_ELECTRA: usize = 9;
pub const MAX_BLOBS_PER_BLOCK_CANCUN: usize = 6;
/// Target consumable blob gas for data blobs per block: EIP-7691
pub const TARGET_BLOB_GAS_PER_BLOCK: u64 = 786_432;
/// Minimum gas price for data blobs.
pub const MIN_BLOB_GASPRICE: u64 = 1;
/// Controls the maximum rate of change for blob gas price.
pub const BLOB_GASPRICE_UPDATE_FRACTION: u64 = 3_338_477;
/// First version of the blob.
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

/// Structure holding block blob excess gas and it calculates blob fee
///
/// Incorporated as part of the Cancun upgrade via [EIP-4844].
///
/// [EIP-4844]: <https://eips.ethereum.org/EIPS/eip-4844>
#[derive(Copy, Clone, Debug, Ord, PartialOrd, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobExcessGasAndPrice {
    /// The excess blob gas of the block
    pub excess_blob_gas: u64,
    /// The calculated blob gas price based on the `excess_blob_gas`
    ///
    /// See [`calc_blob_gas_price`]
    pub blob_gas_price: u128,
}

impl Default for BlobExcessGasAndPrice {
    fn default() -> Self {
        Self {
            excess_blob_gas: 0,
            blob_gas_price: u128::from(MIN_BLOB_GASPRICE),
        }
    }
}

/// See [EIP-4844], [`calc_max_data_fee`]
///
/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
#[inline]
#[must_use]
pub fn get_total_blob_gas(blob_hashes_len: usize) -> u64 {
    let blob_count = u64::try_from(blob_hashes_len).unwrap_or(u64::MAX);
    GAS_PER_BLOB.saturating_mul(blob_count)
}
