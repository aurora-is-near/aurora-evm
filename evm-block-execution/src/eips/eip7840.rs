//! The blob-parameter set a block is executed under — [EIP-7840].
//!
//! Parameters stored as `u64` match their practical range and avoid casts at call sites. Blob fees
//! remain `u128`, and calculations that can overflow return `Option` because `excess_blob_gas`
//! arrives from an untrusted header. See the arithmetic notes in [`eip4844`].
//!
//! [EIP-7840]: https://github.com/ethereum/EIPs/tree/master/EIPS/eip-7840.md

use crate::eips::eip4844::DATA_GAS_PER_BLOB;
use crate::eips::{eip4844, eip7594, eip7691, eip7892};

/// Minimum execution gas required to include a blob in a block.
///
/// Blob gas and execution gas are decoupled, but [EIP-7918] keeps a floor in *execution* gas for
/// including a blob at all, so the blob market cannot be driven arbitrarily cheap relative to it.
///
/// [EIP-7918]: https://eips.ethereum.org/EIPS/eip-7918
pub const BLOB_BASE_COST: u64 = 2_u64.pow(13);

/// Configuration for the blob-related calculations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobParams {
    /// Target blob count for the block.
    pub target_blob_count: u64,
    /// Max blob count for the block.
    pub max_blob_count: u64,
    /// Update fraction for excess blob gas calculation.
    pub update_fraction: u64,
    /// Minimum gas price for a data blob.
    ///
    /// Not required per EIP-7840 and assumed to be the default
    /// [`eip4844::BLOB_TX_MIN_BLOB_GASPRICE`] if not set.
    pub min_blob_fee: u64,
    /// Maximum number of blobs per transaction.
    ///
    /// Defaults to `max_blob_count` unless set otherwise.
    pub max_blobs_per_tx: u64,
    /// Minimum execution gas required to include a blob in a block.
    ///
    /// Defaults to `0` for Cancun and Prague hardforks, and [`BLOB_BASE_COST`] for Osaka and
    /// later.
    pub blob_base_cost: u64,
}

impl BlobParams {
    /// Returns the Ethereum mainnet parameters activated at Cancun.
    #[must_use]
    pub const fn cancun() -> Self {
        Self {
            target_blob_count: eip4844::TARGET_BLOBS_PER_BLOCK_DENCUN,
            max_blob_count: eip4844::MAX_BLOBS_PER_BLOCK_DENCUN,
            update_fraction: eip4844::BLOB_GASPRICE_UPDATE_FRACTION,
            min_blob_fee: eip4844::BLOB_TX_MIN_BLOB_GASPRICE,
            max_blobs_per_tx: eip4844::MAX_BLOBS_PER_BLOCK_DENCUN,
            blob_base_cost: 0,
        }
    }

    /// Returns the Ethereum mainnet parameters activated at Prague.
    #[must_use]
    pub const fn prague() -> Self {
        Self {
            target_blob_count: eip7691::TARGET_BLOBS_PER_BLOCK_ELECTRA,
            max_blob_count: eip7691::MAX_BLOBS_PER_BLOCK_ELECTRA,
            update_fraction: eip7691::BLOB_GASPRICE_UPDATE_FRACTION_PECTRA,
            min_blob_fee: eip4844::BLOB_TX_MIN_BLOB_GASPRICE,
            max_blobs_per_tx: eip7691::MAX_BLOBS_PER_BLOCK_ELECTRA,
            blob_base_cost: 0,
        }
    }

    /// Returns the Ethereum mainnet parameters activated at Osaka.
    #[must_use]
    pub const fn osaka() -> Self {
        Self {
            target_blob_count: eip7691::TARGET_BLOBS_PER_BLOCK_ELECTRA,
            max_blob_count: eip7691::MAX_BLOBS_PER_BLOCK_ELECTRA,
            update_fraction: eip7691::BLOB_GASPRICE_UPDATE_FRACTION_PECTRA,
            min_blob_fee: eip4844::BLOB_TX_MIN_BLOB_GASPRICE,
            max_blobs_per_tx: eip7594::MAX_BLOBS_PER_TX_FUSAKA,
            blob_base_cost: BLOB_BASE_COST,
        }
    }

    /// Returns the EIP-7892 BPO1 parameters.
    #[must_use]
    pub const fn bpo1() -> Self {
        Self {
            target_blob_count: eip7892::BPO1_TARGET_BLOBS_PER_BLOCK,
            max_blob_count: eip7892::BPO1_MAX_BLOBS_PER_BLOCK,
            update_fraction: eip7892::BPO1_BASE_UPDATE_FRACTION,
            ..Self::osaka()
        }
    }

    /// Returns the EIP-7892 BPO2 parameters.
    #[must_use]
    pub const fn bpo2() -> Self {
        Self {
            target_blob_count: eip7892::BPO2_TARGET_BLOBS_PER_BLOCK,
            max_blob_count: eip7892::BPO2_MAX_BLOBS_PER_BLOCK,
            update_fraction: eip7892::BPO2_BASE_UPDATE_FRACTION,
            ..Self::osaka()
        }
    }

    /// Overrides the per-transaction blob limit.
    #[must_use]
    pub const fn with_max_blobs_per_tx(mut self, max_blobs_per_tx: u64) -> Self {
        self.max_blobs_per_tx = max_blobs_per_tx;
        self
    }

    /// Overrides the EIP-7918 blob base cost.
    #[must_use]
    pub const fn with_blob_base_cost(mut self, blob_base_cost: u64) -> Self {
        self.blob_base_cost = blob_base_cost;
        self
    }

    /// Returns the maximum available blob gas in a block: `max_blob_count * DATA_GAS_PER_BLOB`.
    ///
    /// Saturating: a blob count large enough to overflow is far beyond any schedule a chain could
    /// carry, and a saturated maximum only ever rejects more blocks, never fewer.
    #[must_use]
    pub const fn max_blob_gas_per_block(&self) -> u64 {
        self.max_blob_count.saturating_mul(DATA_GAS_PER_BLOB)
    }

    /// Returns the blob gas target per block: `target_blob_count * DATA_GAS_PER_BLOB`.
    ///
    /// Saturating, for the same reason as [`Self::max_blob_gas_per_block`].
    #[must_use]
    pub const fn target_blob_gas_per_block(&self) -> u64 {
        self.target_blob_count.saturating_mul(DATA_GAS_PER_BLOB)
    }

    /// Calculates the next block's `excess_blob_gas` from this block's `excess_blob_gas`,
    /// `blob_gas_used` and `base_fee_per_gas`.
    ///
    /// The under-target clamp runs **first**, before the [EIP-7918] reserve-price branch. That order
    /// is normative: a block whose total usage is below target yields zero regardless of the reserve
    /// price, and swapping the two would return a scaled value where the spec returns zero.
    ///
    /// # Errors
    /// `None` if the blob fee needed by the reserve-price comparison cannot be computed, or if
    /// `max_blob_count` is zero — a schedule that permits no blobs has no scaling factor.
    ///
    /// [EIP-7918]: https://eips.ethereum.org/EIPS/eip-7918
    #[inline]
    #[must_use]
    pub fn next_block_excess_blob_gas(
        &self,
        excess_blob_gas: u64,
        blob_gas_used: u64,
        base_fee_per_gas: u64,
    ) -> Option<u64> {
        let next_excess_blob_gas = excess_blob_gas.checked_add(blob_gas_used)?;
        let target_blob_gas = self.target_blob_gas_per_block();
        if next_excess_blob_gas < target_blob_gas {
            return Some(0);
        }

        // EIP-7918: while the blob fee is small relative to the execution base fee, excess grows by
        // a scaled amount instead of the plain overshoot.
        let reserve = u128::from(self.blob_base_cost).checked_mul(u128::from(base_fee_per_gas))?;
        let blob_side =
            u128::from(DATA_GAS_PER_BLOB).checked_mul(self.calc_blob_fee(excess_blob_gas)?)?;
        if reserve > blob_side {
            let headroom = self.max_blob_count.checked_sub(self.target_blob_count)?;
            let scaled_excess = blob_gas_used
                .checked_mul(headroom)?
                .checked_div(self.max_blob_count)?;
            excess_blob_gas.checked_add(scaled_excess)
        } else {
            next_excess_blob_gas.checked_sub(target_blob_gas)
        }
    }

    /// Calculates the blob fee for a block from its `excess_blob_gas`.
    ///
    /// # Errors
    /// `None` if the fee overflows `u128` or `update_fraction` is zero; see
    /// [`eip4844::fake_exponential`].
    #[inline]
    #[must_use]
    pub fn calc_blob_fee(&self, excess_blob_gas: u64) -> Option<u128> {
        eip4844::fake_exponential(self.min_blob_fee, excess_blob_gas, self.update_fraction)
    }
}
