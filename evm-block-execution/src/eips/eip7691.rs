//! [EIP-7691] blob targets, limits and fee parameters for Pectra.
//!
//! [EIP-7691]: https://eips.ethereum.org/EIPS/eip-7691

use crate::eips::eip4844::{BLOB_TX_MIN_BLOB_GASPRICE, fake_exponential};

/// Consensus-layer target blobs per block from Pectra.
pub const TARGET_BLOBS_PER_BLOCK_ELECTRA: u64 = 6;

/// Consensus-layer maximum blobs per block from Pectra.
pub const MAX_BLOBS_PER_BLOCK_ELECTRA: u64 = 9;

/// Blob-fee update fraction from Pectra.
pub const BLOB_GASPRICE_UPDATE_FRACTION_PECTRA: u64 = 5_007_716;

/// Calculates the blob gas price with Pectra's update fraction.
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
