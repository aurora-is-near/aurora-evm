//! [EIP-7840] blob parameters used for block execution.
//!
//! Parameters use `u64`; blob fees use `u128`. Calculations fed by untrusted header values return
//! `Option` on invalid or overflowing arithmetic. See [`eip4844`].
//!
//! [EIP-7840]: https://github.com/ethereum/EIPs/tree/master/EIPS/eip-7840.md

use crate::eips::eip4844::DATA_GAS_PER_BLOB;
use crate::eips::{eip4844, eip7594, eip7691, eip7892};

/// EIP-7918 execution-gas floor used by the blob reserve-price rule.
///
/// [EIP-7918]: https://eips.ethereum.org/EIPS/eip-7918
pub const BLOB_BASE_COST: u64 = 2_u64.pow(13);

/// Blob-market parameters active for a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobParams {
    /// Target blobs per block.
    pub target_blob_count: u64,
    /// Maximum blobs per block.
    pub max_blob_count: u64,
    /// Blob-fee update fraction.
    pub update_fraction: u64,
    /// Minimum blob gas price.
    ///
    /// Not required per EIP-7840 and assumed to be the default
    /// [`eip4844::BLOB_TX_MIN_BLOB_GASPRICE`] if not set.
    pub min_blob_fee: u64,
    /// Maximum number of blobs per transaction.
    ///
    /// Defaults to `max_blob_count` unless set otherwise.
    pub max_blobs_per_tx: u64,
    /// Execution-gas floor for the EIP-7918 reserve-price rule.
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

    /// Returns `max_blob_count * DATA_GAS_PER_BLOB`.
    ///
    /// Saturation is fail-closed: an unrealistic overflowing schedule can only tighten validation.
    #[must_use]
    pub const fn max_blob_gas_per_block(&self) -> u64 {
        self.max_blob_count.saturating_mul(DATA_GAS_PER_BLOB)
    }

    /// Returns `target_blob_count * DATA_GAS_PER_BLOB`.
    ///
    /// Saturating, for the same reason as [`Self::max_blob_gas_per_block`].
    #[must_use]
    pub const fn target_blob_gas_per_block(&self) -> u64 {
        self.target_blob_count.saturating_mul(DATA_GAS_PER_BLOB)
    }

    /// Calculates the next block's `excess_blob_gas` from the parent header values.
    ///
    /// Per EIP-7918, usage below target clamps to zero before the reserve-price branch.
    ///
    /// # Errors
    /// `None` if fee arithmetic fails or `max_blob_count` is zero.
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

        // EIP-7918 scales excess while blob fees remain below the execution-gas reserve price.
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
