//! [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
use primitive_types::U256;

/// EIP-4844 constants
/// Gas consumption of a single data blob (== blob byte size).
pub const GAS_PER_BLOB: u64 = 1 << 17;
/// Max number of blobs per block: EIP-7691
pub const MAX_BLOBS_PER_BLOCK_ELECTRA: u64 = 9;
pub const MAX_BLOBS_PER_BLOCK_CANCUN: u64 = 6;
/// Target consumable blob gas for data blobs per block: EIP-7691
pub const TARGET_BLOB_GAS_PER_BLOCK: u64 = 786_432;
/// Minimum gas price for data blobs.
pub const MIN_BLOB_GASPRICE: u64 = 1;
/// Controls the maximum rate of change for blob gas price.
pub const BLOB_GASPRICE_UPDATE_FRACTION: u64 = 3_338_477;
/// First version of the blob.
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

/// Calculates the `excess_blob_gas` from the parent header's `blob_gas_used` and `excess_blob_gas`.
///
/// See also [the EIP-4844 helpers]<https://eips.ethereum.org/EIPS/eip-4844#helpers>
/// (`calc_excess_blob_gas`).
#[inline]
#[must_use]
pub const fn calc_excess_blob_gas(parent_excess_blob_gas: u64, parent_blob_gas_used: u64) -> u64 {
    (parent_excess_blob_gas + parent_blob_gas_used).saturating_sub(TARGET_BLOB_GAS_PER_BLOCK)
}

/// Calculates the blob gas price from the header's excess blob gas field.
///
/// See also [the EIP-4844 helpers](https://eips.ethereum.org/EIPS/eip-4844#helpers)
/// (`get_blob_gasprice`).
#[inline]
#[must_use]
pub fn calc_blob_gas_price(excess_blob_gas: u64) -> u128 {
    fake_exponential(
        MIN_BLOB_GASPRICE,
        excess_blob_gas,
        BLOB_GASPRICE_UPDATE_FRACTION,
    )
}

/// See [EIP-4844], [`calc_max_data_fee`]
///
/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
#[inline]
#[must_use]
pub const fn get_total_blob_gas(blob_hashes_len: usize) -> u64 {
    GAS_PER_BLOB * blob_hashes_len as u64
}

/// Calculates the [EIP-4844] `data_fee` of the transaction.
///
/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
#[inline]
#[must_use]
pub fn calc_max_data_fee(max_fee_per_blob_gas: U256, blob_hashes_len: usize) -> U256 {
    max_fee_per_blob_gas.saturating_mul(U256::from(get_total_blob_gas(blob_hashes_len)))
}

/// Calculates the [EIP-4844] `data_fee` of the transaction.
///
/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
#[inline]
#[must_use]
pub fn calc_data_fee(blob_gas_price: u128, blob_hashes_len: usize) -> U256 {
    U256::from(blob_gas_price).saturating_mul(U256::from(get_total_blob_gas(blob_hashes_len)))
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
///
/// # NOTES
/// PLEASE DO NOT USE IN PRODUCTION as not checked overflow. For tests only.
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
