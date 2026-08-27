//! [EIP-4844] blob constants and the blob-gas market helpers.
//!
//! Blob-fee arithmetic is checked because `excess_blob_gas` comes from an untrusted header.
//! [`fake_exponential`] returns `None` on invalid or overflowing inputs.
//!
//! [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844

use crate::eips::eip7840;
use hex_literal::hex;
use primitive_types::{H256, U256};

/// BLS scalar-field modulus; every blob field element must be strictly smaller.
pub const BLS_MODULUS_BYTES: H256 = H256(hex!(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
));

/// [`BLS_MODULUS_BYTES`] as an integer.
///
/// A function rather than a `const`, because `U256::from_big_endian` is not `const` in
/// `primitive-types`.
#[inline]
#[must_use]
pub fn bls_modulus() -> U256 {
    U256::from_big_endian(&BLS_MODULUS_BYTES.0)
}

/// Size of a single field element in bytes.
pub const FIELD_ELEMENT_BYTES: u64 = 32;

/// Size of a single field element in bytes, as a `usize`.
///
/// Written out rather than converted from [`FIELD_ELEMENT_BYTES`]: a `const` cast would be an `as`
/// conversion, which this crate does not use.
pub const FIELD_ELEMENT_BYTES_USIZE: usize = 32;

/// How many field elements are stored in a single data blob.
pub const FIELD_ELEMENTS_PER_BLOB: u64 = 4096;

/// How many field elements are stored in a single data blob, as a `usize`.
pub const FIELD_ELEMENTS_PER_BLOB_USIZE: usize = 4096;

/// Number of usable bits in a field element. The top two bits are always zero.
pub const USABLE_BITS_PER_FIELD_ELEMENT: usize = 254;

/// Usable payload bytes per blob without reaching [`bls_modulus`].
pub const USABLE_BYTES_PER_BLOB: usize =
    USABLE_BITS_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB_USIZE / 8;

/// Gas consumption of a single data blob: `32 * 4096 == 2^17`.
pub const DATA_GAS_PER_BLOB: u64 = 131_072;

/// How many bytes are in a blob. Numerically the same as [`DATA_GAS_PER_BLOB`], as a `usize`.
pub const BYTES_PER_BLOB: usize = 131_072;

/// Maximum data gas for data blobs in a single block (Cancun): `6 * 2^17`.
pub const MAX_DATA_GAS_PER_BLOCK_DENCUN: u64 = 786_432;

/// Target data gas for data blobs in a single block (Cancun): `3 * 2^17`.
pub const TARGET_DATA_GAS_PER_BLOCK_DENCUN: u64 = 393_216;

/// Maximum number of data blobs in a single block (Cancun).
pub const MAX_BLOBS_PER_BLOCK_DENCUN: u64 = MAX_DATA_GAS_PER_BLOCK_DENCUN / DATA_GAS_PER_BLOB;

/// Target number of data blobs in a single block (Cancun).
pub const TARGET_BLOBS_PER_BLOCK_DENCUN: u64 = TARGET_DATA_GAS_PER_BLOCK_DENCUN / DATA_GAS_PER_BLOB;

/// Determines the maximum rate of change for the blob fee (Cancun).
pub const BLOB_GASPRICE_UPDATE_FRACTION: u64 = 3_338_477;

/// Minimum gas price for a data blob.
pub const BLOB_TX_MIN_BLOB_GASPRICE: u64 = 1;

/// Version byte of a KZG versioned hash — the first byte of every entry in a blob transaction's
/// `blob_versioned_hashes`.
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

/// Calculates the `excess_blob_gas` for the next block from the parent's `blob_gas_used` and
/// `excess_blob_gas`, under Cancun parameters.
///
/// See the [EIP-4844 helpers](https://eips.ethereum.org/EIPS/eip-4844#helpers)
/// (`calc_excess_blob_gas`).
///
/// # Errors
/// `None` if the blob fee cannot be computed; see the module docs on arithmetic.
#[inline]
#[must_use]
pub fn calc_excess_blob_gas(parent_excess_blob_gas: u64, parent_blob_gas_used: u64) -> Option<u64> {
    eip7840::BlobParams::cancun().next_block_excess_blob_gas(
        parent_excess_blob_gas,
        parent_blob_gas_used,
        // The EIP-7918 reserve price is an Osaka rule; under Cancun parameters `blob_base_cost` is
        // zero, so the base fee cannot affect the result and any value does.
        0,
    )
}

/// Calculates the blob gas price from a header's `excess_blob_gas`, under Cancun parameters.
///
/// See the [EIP-4844 helpers](https://eips.ethereum.org/EIPS/eip-4844#helpers)
/// (`get_blob_gasprice`).
///
/// # Errors
/// `None` if the price cannot be computed; see the module docs on arithmetic.
#[inline]
#[must_use]
pub fn calc_blob_gasprice(excess_blob_gas: u64) -> Option<u128> {
    eip7840::BlobParams::cancun().calc_blob_fee(excess_blob_gas)
}

/// Approximates `factor * e ** (numerator / denominator)` using EIP-4844's Taylor expansion.
///
/// Checked arithmetic prevents debug/release divergence and bounds adversarial inputs: the function
/// either converges or reports overflow instead of wrapping or running an impractical loop.
///
/// # Errors
/// `None` if `denominator == 0`, or if any intermediate term overflows.
#[inline]
#[must_use]
pub fn fake_exponential(factor: u64, numerator: u64, denominator: u64) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    let factor = u128::from(factor);
    let numerator = u128::from(numerator);
    let denominator = u128::from(denominator);

    let mut i: u128 = 1;
    let mut output: u128 = 0;
    let mut numerator_accum = factor.checked_mul(denominator)?;
    while numerator_accum > 0 {
        output = output.checked_add(numerator_accum)?;
        // `denominator * i > 0` (denominator != 0, i >= 1), so the division is always defined.
        numerator_accum = numerator_accum.checked_mul(numerator)? / denominator.checked_mul(i)?;
        i = i.checked_add(1)?;
    }
    Some(output / denominator)
}

#[cfg(test)]
mod tests {
    use super::{
        BLOB_GASPRICE_UPDATE_FRACTION, DATA_GAS_PER_BLOB, TARGET_DATA_GAS_PER_BLOCK_DENCUN,
        calc_blob_gasprice, calc_excess_blob_gas, fake_exponential,
    };
    use crate::eips::eip7840::BlobParams;

    /// go-ethereum `TestCalcExcessBlobGas`.
    #[test]
    fn calc_excess_blob_gas_matches_geth() {
        const TARGET_BLOBS: u64 = TARGET_DATA_GAS_PER_BLOCK_DENCUN / DATA_GAS_PER_BLOB;
        for &(excess, blobs, expected) in &[
            // Excess must not grow from zero while usage is at or below target.
            (0, 0, 0),
            (0, 1, 0),
            (0, TARGET_BLOBS, 0),
            // Above target it grows by the overshoot.
            (0, TARGET_BLOBS + 1, DATA_GAS_PER_BLOB),
            (1, TARGET_BLOBS + 1, DATA_GAS_PER_BLOB + 1),
            (1, TARGET_BLOBS + 2, 2 * DATA_GAS_PER_BLOB + 1),
            // Below target it shrinks by the undershoot, clamped at zero.
            (
                TARGET_DATA_GAS_PER_BLOCK_DENCUN,
                TARGET_BLOBS,
                TARGET_DATA_GAS_PER_BLOCK_DENCUN,
            ),
            (
                TARGET_DATA_GAS_PER_BLOCK_DENCUN,
                TARGET_BLOBS - 1,
                TARGET_DATA_GAS_PER_BLOCK_DENCUN - DATA_GAS_PER_BLOB,
            ),
            (
                TARGET_DATA_GAS_PER_BLOCK_DENCUN,
                TARGET_BLOBS - 2,
                TARGET_DATA_GAS_PER_BLOCK_DENCUN - 2 * DATA_GAS_PER_BLOB,
            ),
            (DATA_GAS_PER_BLOB - 1, TARGET_BLOBS - 1, 0),
        ] {
            assert_eq!(
                calc_excess_blob_gas(excess, blobs * DATA_GAS_PER_BLOB),
                Some(expected),
                "excess {excess}, blobs {blobs}"
            );
        }
    }

    /// go-ethereum `TestCalcBlobFee`.
    #[test]
    fn calc_blob_gasprice_matches_geth() {
        for &(excess, expected) in &[
            (0u64, 1u128),
            (2_314_057, 1),
            (2_314_058, 2),
            (10 * 1024 * 1024, 23),
            // The approximation crosses a `u64` boundary here; the result is a `u128` for exactly
            // this reason.
            (148_099_578, 18_446_739_238_971_471_609),
            (148_099_579, 18_446_744_762_204_311_910),
            (161_087_488, 902_580_055_246_494_526_580),
        ] {
            assert_eq!(
                calc_blob_gasprice(excess),
                Some(expected),
                "excess {excess}"
            );
        }
    }

    /// go-ethereum `TestFakeExponential`.
    #[test]
    fn fake_exponential_matches_geth() {
        for &(factor, numerator, denominator, expected) in &[
            (1u64, 0u64, 1u64, 1u128),
            (38493, 0, 1000, 38493),
            (0, 1234, 2345, 0),
            (1, 2, 1, 6), // approximates 7.389
            (1, 4, 2, 6),
            (1, 3, 1, 16), // approximates 20.09
            (1, 6, 2, 18),
            (1, 4, 1, 49), // approximates 54.60
            (1, 8, 2, 50),
            (10, 8, 2, 542), // approximates 540.598
            (11, 8, 2, 596), // approximates 600.58
            (1, 5, 1, 136),  // approximates 148.4
            (1, 5, 2, 11),   // approximates 12.18
            (2, 5, 2, 23),   // approximates 24.36
            (1, 50_000_000, 2_225_652, 5_709_098_764),
            (1, 380_928, BLOB_GASPRICE_UPDATE_FRACTION, 1),
        ] {
            assert_eq!(
                fake_exponential(factor, numerator, denominator),
                Some(expected),
                "factor {factor}, numerator {numerator}, denominator {denominator}"
            );
        }
    }

    /// Adversarial excess blob gas must neither wrap nor make the Taylor loop run away.
    #[test]
    fn an_adversarial_numerator_reports_overflow_rather_than_wrapping() {
        assert_eq!(fake_exponential(1, u64::MAX, 5_007_716), None);
        assert_eq!(BlobParams::prague().calc_blob_fee(u64::MAX), None);
        // A zero denominator is a division by zero, reported the same way.
        assert_eq!(fake_exponential(1, 1, 0), None);
    }
}
