//! [EIP-7691] blob targets, limits and fee parameters for Pectra.
//!
//! [EIP-7691]: https://eips.ethereum.org/EIPS/eip-7691

use crate::eips::eip4844::{BLOB_TX_MIN_BLOB_GASPRICE, fake_exponential};

/// CL-enforced target blobs per block after Pectra hardfork activation.
pub const TARGET_BLOBS_PER_BLOCK_ELECTRA: u64 = 6;

/// CL-enforced maximum blobs per block after Pectra hardfork activation.
pub const MAX_BLOBS_PER_BLOCK_ELECTRA: u64 = 9;

/// Determines the maximum rate of change for blob fee after Pectra hardfork activation.
pub const BLOB_GASPRICE_UPDATE_FRACTION_PECTRA: u64 = 5_007_716;

/// As [`eip4844::calc_blob_gasprice`](crate::eips::eip4844::calc_blob_gasprice), but with the Pectra update
/// fraction.
///
/// # Errors
/// `None` if the price overflows `u128`; see
/// [`eip4844::fake_exponential`](crate::eips::eip4844::fake_exponential).
#[inline]
#[must_use]
pub fn calc_blob_gasprice(excess_blob_gas: u64) -> Option<u128> {
    fake_exponential(
        BLOB_TX_MIN_BLOB_GASPRICE,
        excess_blob_gas,
        BLOB_GASPRICE_UPDATE_FRACTION_PECTRA,
    )
}
