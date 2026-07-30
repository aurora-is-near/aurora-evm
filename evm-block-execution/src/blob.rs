//! EIP-4844 blob-gas parameters, the BPO fee schedule and blob pricing math.
//!
//! Blob gas is a second, independent gas market introduced by [EIP-4844]. Its parameters
//! (per-block target/maximum, the price-update fraction and — from Osaka, [EIP-7594] — a separate
//! per-transaction maximum) are **not** fixed per EVM hardfork: [EIP-7840]/[EIP-7892] let them
//! change at timestamp-activated "blob parameter only" (BPO) forks without a new [`Spec`]. This
//! module therefore models them as data:
//!
//! - [`BlobParams`] — the four active parameters;
//! - [`BlobScheduleEntry`] / [`BlobSchedule`] — a timestamp-ordered schedule resolved via
//!   [`BlobSchedule::blob_params_for_timestamp`].
//!
//! Pricing is pure integer math: [`fake_exponential`] (the [EIP-4844] Taylor approximation),
//! [`calc_blob_gas_price`] (price from excess blob gas) and [`calc_excess_blob_gas`], which
//! includes the [EIP-7918] reserve-price rule coupling blob gas to the execution base fee.
//!
//! # Place in the execution pipeline
//!
//! The resolved [`BlobParams`] are attached to the block environment and drive per-transaction and
//! per-block blob-count limits in transaction validation; [`get_total_blob_gas`] converts a blob
//! count to blob gas for the block's `blob_gas_used` accounting and fee reservation.
//!
//! [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
//! [EIP-7594]: https://eips.ethereum.org/EIPS/eip-7594
//! [EIP-7840]: https://eips.ethereum.org/EIPS/eip-7840
//! [EIP-7892]: https://eips.ethereum.org/EIPS/eip-7892
//! [EIP-7918]: https://eips.ethereum.org/EIPS/eip-7918
//! [`Spec`]: crate::spec::Spec

use core::fmt;
use serde::{Deserialize, Serialize};

/// Gas consumption of a single data blob (== blob byte size).
pub const GAS_PER_BLOB: u64 = 1 << 17;
/// Minimum gas price for data blobs.
pub const MIN_BLOB_GAS_PRICE: u64 = 1;
/// First version byte of a blob versioned hash (KZG).
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;
/// EIP-7918 reserve-price constant coupling blob gas to the execution base fee.
pub const BLOB_BASE_COST: u64 = 1 << 13;

/// Blob gas-price update fraction (Cancun, EIP-4844).
pub const BLOB_GAS_PRICE_UPDATE_FRACTION_CANCUN: u64 = 3_338_477;
/// Blob gas-price update fraction (Prague, EIP-7691).
pub const BLOB_GAS_PRICE_UPDATE_FRACTION_PRAGUE: u64 = 5_007_716;

/// Active blob-gas parameters for one block.
///
/// `max_blobs_per_transaction` is a distinct limit from `max_blobs_per_block` only from Osaka
/// (EIP-7594); earlier forks set it equal to the per-block maximum. The constructors provide the
/// canonical baselines; BPO forks supply their own values through a [`BlobSchedule`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobParams {
    /// Target blob count per block (the price stays flat at this usage).
    pub target_blobs_per_block: u64,
    /// Maximum blob count per block.
    pub max_blobs_per_block: u64,
    /// `fake_exponential` denominator controlling how fast the blob price moves.
    pub base_fee_update_fraction: u64,
    /// Maximum blob count in a single transaction (EIP-7594; == per-block max before Osaka).
    pub max_blobs_per_transaction: u64,
}

impl BlobParams {
    /// Cancun baseline (EIP-4844): target 3, max 6, no separate per-transaction cap.
    #[must_use]
    pub const fn cancun() -> Self {
        Self {
            target_blobs_per_block: 3,
            max_blobs_per_block: 6,
            base_fee_update_fraction: BLOB_GAS_PRICE_UPDATE_FRACTION_CANCUN,
            max_blobs_per_transaction: 6,
        }
    }

    /// Prague baseline (EIP-7691): target 6, max 9, no separate per-transaction cap.
    #[must_use]
    pub const fn prague() -> Self {
        Self {
            target_blobs_per_block: 6,
            max_blobs_per_block: 9,
            base_fee_update_fraction: BLOB_GAS_PRICE_UPDATE_FRACTION_PRAGUE,
            max_blobs_per_transaction: 9,
        }
    }

    /// Osaka baseline (EIP-7594): Prague block limits, with the per-transaction cap of 6.
    #[must_use]
    pub const fn osaka() -> Self {
        Self {
            target_blobs_per_block: 6,
            max_blobs_per_block: 9,
            base_fee_update_fraction: BLOB_GAS_PRICE_UPDATE_FRACTION_PRAGUE,
            max_blobs_per_transaction: 6,
        }
    }

    /// Target blob gas per block (`target_blobs_per_block * GAS_PER_BLOB`).
    #[must_use]
    pub const fn target_blob_gas(&self) -> u64 {
        self.target_blobs_per_block.saturating_mul(GAS_PER_BLOB)
    }

    /// Maximum blob gas per block (`max_blobs_per_block * GAS_PER_BLOB`).
    #[must_use]
    pub const fn max_blob_gas(&self) -> u64 {
        self.max_blobs_per_block.saturating_mul(GAS_PER_BLOB)
    }

    /// Whether these parameters are internally consistent: a non-zero block maximum, a target no
    /// greater than it, a per-transaction cap in `1..=max_blobs_per_block`, a non-zero update
    /// fraction, and blob-gas products (`target/max * GAS_PER_BLOB`) that fit in `u64`. Validated
    /// once when building an `Evm`; the pricing/excess functions (and the `saturating_mul` in
    /// [`Self::target_blob_gas`] / [`Self::max_blob_gas`]) then assume it, so saturation never
    /// triggers for validated parameters.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.max_blobs_per_block > 0
            && self.target_blobs_per_block <= self.max_blobs_per_block
            && self.max_blobs_per_transaction >= 1
            && self.max_blobs_per_transaction <= self.max_blobs_per_block
            && self.base_fee_update_fraction > 0
            && self
                .target_blobs_per_block
                .checked_mul(GAS_PER_BLOB)
                .is_some()
            && self.max_blobs_per_block.checked_mul(GAS_PER_BLOB).is_some()
    }
}

/// A blob-schedule entry: `params` become active at `activation_timestamp`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobScheduleEntry {
    /// Block timestamp at which `params` take effect.
    pub activation_timestamp: u64,
    /// Blob parameters active from `activation_timestamp` onward.
    pub params: BlobParams,
}

/// Blob config error represents reasons why [`BlobSchedule`] cannot be built from a set of entries.
///
/// This is a construction-time (static) configuration error, deliberately distinct from a
/// block-execution error: an invalid schedule is rejected once, when it is built, never while
/// executing a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobConfigError {
    /// Two entries share an activation timestamp (the active entry would be ambiguous).
    DuplicateActivationTimestamp,
    /// An entry's [`BlobParams`] are internally inconsistent (see [`BlobParams::is_valid`]).
    InvalidParams,
}

impl fmt::Display for BlobConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateActivationTimestamp => {
                write!(f, "blob schedule has duplicate activation timestamps")
            }
            Self::InvalidParams => write!(f, "blob schedule has inconsistent blob parameters"),
        }
    }
}

impl core::error::Error for BlobConfigError {}

/// Timestamp-ordered, validated blob schedule (EIP-7840 / EIP-7892 BPO forks).
///
/// Built only through [`BlobSchedule::try_new`], which sorts and validates the entries, so an
/// invalid schedule cannot be represented and the resolved parameters are always well-formed —
/// the inner `Vec` is private for exactly this reason. Blocks before the first entry's activation
/// have no blob parameters (pre-Cancun).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct BlobSchedule(Vec<BlobScheduleEntry>);

// Deserialize routes through `try_new`, so the validation invariant holds on this path too: a
// `BlobSchedule` decoded from external config (JSON, etc.) is sorted and validated exactly as one
// built in code, and an invalid schedule fails to deserialize rather than silently bypassing the
// check. (`Serialize` is derived — a schedule is always valid before it is serialized.)
impl<'de> Deserialize<'de> for BlobSchedule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let entries = Vec::<BlobScheduleEntry>::deserialize(deserializer)?;
        Self::try_new(entries).map_err(serde::de::Error::custom)
    }
}

impl BlobSchedule {
    /// Builds a validated schedule: sorts `entries` by activation timestamp, then checks that no
    /// two share a timestamp and that every [`BlobParams`] entry is internally consistent
    /// ([`BlobParams::is_valid`]). Validating here, once, is what makes an invalid
    /// [`BlobSchedule`] unrepresentable, so downstream pricing/limit code never re-checks.
    ///
    /// ## Errors
    /// [`BlobConfigError::DuplicateActivationTimestamp`] on a repeated activation timestamp;
    /// [`BlobConfigError::InvalidParams`] if any entry's parameters are inconsistent.
    pub fn try_new(mut entries: Vec<BlobScheduleEntry>) -> Result<Self, BlobConfigError> {
        entries.sort_by_key(|entry| entry.activation_timestamp);
        for pair in entries.windows(2) {
            if pair[0].activation_timestamp == pair[1].activation_timestamp {
                return Err(BlobConfigError::DuplicateActivationTimestamp);
            }
        }
        for entry in &entries {
            if !entry.params.is_valid() {
                return Err(BlobConfigError::InvalidParams);
            }
        }
        Ok(Self(entries))
    }

    /// Active blob parameters at `timestamp`: the latest entry whose activation is `<= timestamp`,
    /// or `None` if `timestamp` predates every entry.
    #[must_use]
    pub fn blob_params_for_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        self.0
            .iter()
            .rev()
            .find(|entry| entry.activation_timestamp <= timestamp)
            .map(|entry| entry.params)
    }

    /// The schedule entries, in activation order.
    #[must_use]
    pub fn entries(&self) -> &[BlobScheduleEntry] {
        &self.0
    }
}

/// Block blob excess gas and the blob gas price derived from it.
///
/// Incorporated as part of the Cancun upgrade via [EIP-4844].
///
/// [EIP-4844]: <https://eips.ethereum.org/EIPS/eip-4844>
#[derive(Copy, Clone, Debug, Ord, PartialOrd, PartialEq, Eq)]
pub struct BlobExcessGasAndPrice {
    /// The excess blob gas of the block.
    pub excess_blob_gas: u64,
    /// The blob gas price derived from `excess_blob_gas`.
    pub blob_gas_price: u128,
}

impl BlobExcessGasAndPrice {
    /// Builds from `excess_blob_gas`, deriving the price with the given update fraction.
    ///
    /// Returns `None` if the price computation overflows (see [`fake_exponential`]).
    #[must_use]
    pub fn new(excess_blob_gas: u64, base_fee_update_fraction: u64) -> Option<Self> {
        Some(Self {
            excess_blob_gas,
            blob_gas_price: calc_blob_gas_price(excess_blob_gas, base_fee_update_fraction)?,
        })
    }
}

impl Default for BlobExcessGasAndPrice {
    fn default() -> Self {
        Self {
            excess_blob_gas: 0,
            blob_gas_price: u128::from(MIN_BLOB_GAS_PRICE),
        }
    }
}

/// Total blob gas consumed by a transaction: `GAS_PER_BLOB * blob_count` ([EIP-4844]).
///
/// [EIP-4844]: https://eips.ethereum.org/EIPS/eip-4844
#[inline]
#[must_use]
pub fn get_total_blob_gas(blob_hashes_len: usize) -> u64 {
    let blob_count = u64::try_from(blob_hashes_len).unwrap_or(u64::MAX);
    GAS_PER_BLOB.saturating_mul(blob_count)
}

/// Blob gas price for a given excess blob gas and update fraction (EIP-4844
/// `get_base_fee_per_blob_gas`). `None` if the computation overflows (see [`fake_exponential`]).
#[inline]
#[must_use]
pub fn calc_blob_gas_price(excess_blob_gas: u64, base_fee_update_fraction: u64) -> Option<u128> {
    fake_exponential(
        MIN_BLOB_GAS_PRICE,
        excess_blob_gas,
        base_fee_update_fraction,
    )
}

/// EIP-4844 `fake_exponential`: approximates `factor * e ** (numerator / denominator)` by Taylor
/// expansion, with fully **checked** arithmetic.
///
/// Returns `None` if any intermediate term overflows `u128`. This keeps consensus code free of the
/// debug-panic / release-wrap divergence of raw arithmetic, and — unlike a saturating variant — it
/// also **bounds the work**: a term only overflows once `numerator / denominator` is large, so the
/// loop makes at most a few dozen iterations before it either converges or reports overflow. An
/// adversarially huge `numerator` (e.g. a witness-supplied excess blob gas near `u64::MAX`) can no
/// longer make the loop spin for billions of iterations or silently return a wrong value.
///
/// Returns `None` (rather than panicking) if `denominator == 0`.
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

/// Computes a block's excess blob gas from its parent, including the [EIP-7918] reserve-price rule.
///
/// With `eip7918_active` (Osaka+), when the execution base fee dominates the parent blob base fee
/// (`BLOB_BASE_COST * parent_base_fee > GAS_PER_BLOB * parent_blob_base_fee`) the excess is drawn
/// down more slowly, keeping the blob price from collapsing while execution gas is expensive. Pre-
/// Osaka this reduces to the standard EIP-4844 update.
///
/// All arithmetic is checked: returns `None` on an invalid configuration
/// (`max_blobs_per_block == 0` or `target > max`) or on `u64`/`u128` overflow, rather than
/// silently producing a different number.
///
/// [EIP-7918]: https://eips.ethereum.org/EIPS/eip-7918
#[must_use]
pub fn calc_excess_blob_gas(
    parent_excess_blob_gas: u64,
    parent_blob_gas_used: u64,
    parent_base_fee_per_gas: u128,
    params: &BlobParams,
    eip7918_active: bool,
) -> Option<u64> {
    // Reject an inconsistent configuration up front (independently of which branch is taken), so
    // the documented guarantee holds for every input.
    if params.max_blobs_per_block == 0 || params.target_blobs_per_block > params.max_blobs_per_block
    {
        return None;
    }
    let total = parent_excess_blob_gas.checked_add(parent_blob_gas_used)?;
    let target_blob_gas = params.target_blob_gas();
    if total < target_blob_gas {
        return Some(0);
    }

    if eip7918_active {
        let parent_blob_base_fee =
            calc_blob_gas_price(parent_excess_blob_gas, params.base_fee_update_fraction)?;
        let execution_cost = u128::from(BLOB_BASE_COST).checked_mul(parent_base_fee_per_gas)?;
        let blob_cost = u128::from(GAS_PER_BLOB).checked_mul(parent_blob_base_fee)?;
        if execution_cost > blob_cost {
            let delta = params
                .max_blobs_per_block
                .checked_sub(params.target_blobs_per_block)?;
            let reserved = parent_blob_gas_used.checked_mul(delta)? / params.max_blobs_per_block;
            return parent_excess_blob_gas.checked_add(reserved);
        }
    }

    total.checked_sub(target_blob_gas)
}

#[cfg(test)]
mod tests {
    use super::{
        BLOB_GAS_PRICE_UPDATE_FRACTION_CANCUN, BLOB_GAS_PRICE_UPDATE_FRACTION_PRAGUE,
        BlobConfigError, BlobParams, BlobSchedule, BlobScheduleEntry, GAS_PER_BLOB,
        MIN_BLOB_GAS_PRICE, calc_blob_gas_price, calc_excess_blob_gas, fake_exponential,
        get_total_blob_gas,
    };

    #[test]
    fn total_blob_gas_scales_with_count() {
        assert_eq!(get_total_blob_gas(0), 0);
        assert_eq!(get_total_blob_gas(3), 3 * GAS_PER_BLOB);
    }

    #[test]
    fn fake_exponential_matches_known_vectors() {
        // At zero excess the price is the factor itself.
        assert_eq!(
            fake_exponential(1, 0, BLOB_GAS_PRICE_UPDATE_FRACTION_CANCUN),
            Some(1)
        );
        assert_eq!(
            calc_blob_gas_price(0, BLOB_GAS_PRICE_UPDATE_FRACTION_CANCUN),
            Some(1)
        );
        // e^1 ≈ 2.718 → factor 2 scaled by ~e.
        assert_eq!(fake_exponential(2, 100, 100), Some(5));
    }

    #[test]
    fn fake_exponential_bounds_overflow_instead_of_spinning() {
        // A witness-supplied excess near u64::MAX would make the series terms explode; checked
        // arithmetic reports overflow (`None`) within a few iterations instead of looping for
        // billions of steps or wrapping.
        assert_eq!(
            fake_exponential(1, u64::MAX, BLOB_GAS_PRICE_UPDATE_FRACTION_CANCUN),
            None
        );
        assert_eq!(
            calc_blob_gas_price(u64::MAX, BLOB_GAS_PRICE_UPDATE_FRACTION_PRAGUE),
            None
        );
        // A zero denominator returns `None` rather than panicking.
        assert_eq!(fake_exponential(1, 5, 0), None);
    }

    #[test]
    fn blob_price_is_monotonic_in_excess() {
        let low = calc_blob_gas_price(0, BLOB_GAS_PRICE_UPDATE_FRACTION_PRAGUE).unwrap();
        let mid = calc_blob_gas_price(1_000_000, BLOB_GAS_PRICE_UPDATE_FRACTION_PRAGUE).unwrap();
        let high = calc_blob_gas_price(10_000_000, BLOB_GAS_PRICE_UPDATE_FRACTION_PRAGUE).unwrap();
        assert!(low <= mid && mid <= high);
        assert_eq!(low, u128::from(MIN_BLOB_GAS_PRICE));
    }

    #[test]
    fn blob_params_validity() {
        assert!(BlobParams::cancun().is_valid());
        assert!(BlobParams::prague().is_valid());
        assert!(BlobParams::osaka().is_valid());
        // target > max
        assert!(
            !BlobParams {
                target_blobs_per_block: 10,
                max_blobs_per_block: 5,
                base_fee_update_fraction: BLOB_GAS_PRICE_UPDATE_FRACTION_CANCUN,
                max_blobs_per_transaction: 5,
            }
            .is_valid()
        );
        // zero update fraction
        assert!(
            !BlobParams {
                base_fee_update_fraction: 0,
                ..BlobParams::cancun()
            }
            .is_valid()
        );
        // per-transaction cap above the block max
        assert!(
            !BlobParams {
                max_blobs_per_transaction: 7,
                ..BlobParams::cancun()
            }
            .is_valid()
        );
        // blob-gas product (max_blobs_per_block * GAS_PER_BLOB) overflows u64
        assert!(
            !BlobParams {
                target_blobs_per_block: u64::MAX,
                max_blobs_per_block: u64::MAX,
                base_fee_update_fraction: BLOB_GAS_PRICE_UPDATE_FRACTION_CANCUN,
                max_blobs_per_transaction: u64::MAX,
            }
            .is_valid()
        );
    }

    #[test]
    fn calc_excess_blob_gas_rejects_target_over_max() {
        let params = BlobParams {
            target_blobs_per_block: 5,
            max_blobs_per_block: 3,
            base_fee_update_fraction: BLOB_GAS_PRICE_UPDATE_FRACTION_CANCUN,
            max_blobs_per_transaction: 3,
        };
        // Rejected even on the standard (non-reserve) path.
        assert_eq!(
            calc_excess_blob_gas(0, GAS_PER_BLOB, 0, &params, false),
            None
        );
    }

    #[test]
    fn schedule_selects_latest_active_entry() {
        let schedule = BlobSchedule::try_new(vec![
            BlobScheduleEntry {
                activation_timestamp: 100,
                params: BlobParams::cancun(),
            },
            BlobScheduleEntry {
                activation_timestamp: 300,
                params: BlobParams::prague(),
            },
            BlobScheduleEntry {
                activation_timestamp: 500,
                params: BlobParams::osaka(),
            },
        ])
        .unwrap();
        assert_eq!(schedule.blob_params_for_timestamp(50), None); // before Cancun
        assert_eq!(
            schedule.blob_params_for_timestamp(100),
            Some(BlobParams::cancun())
        );
        assert_eq!(
            schedule.blob_params_for_timestamp(299),
            Some(BlobParams::cancun())
        );
        assert_eq!(
            schedule.blob_params_for_timestamp(300),
            Some(BlobParams::prague())
        );
        assert_eq!(
            schedule.blob_params_for_timestamp(1_000),
            Some(BlobParams::osaka())
        );
    }

    #[test]
    fn schedule_is_sorted_regardless_of_input_order() {
        let schedule = BlobSchedule::try_new(vec![
            BlobScheduleEntry {
                activation_timestamp: 500,
                params: BlobParams::osaka(),
            },
            BlobScheduleEntry {
                activation_timestamp: 100,
                params: BlobParams::cancun(),
            },
        ])
        .unwrap();
        assert_eq!(
            schedule.blob_params_for_timestamp(200),
            Some(BlobParams::cancun())
        );
        assert_eq!(
            schedule.blob_params_for_timestamp(600),
            Some(BlobParams::osaka())
        );
    }

    #[test]
    fn try_new_rejects_duplicate_activation_timestamp() {
        let err = BlobSchedule::try_new(vec![
            BlobScheduleEntry {
                activation_timestamp: 100,
                params: BlobParams::cancun(),
            },
            BlobScheduleEntry {
                activation_timestamp: 100,
                params: BlobParams::prague(),
            },
        ])
        .unwrap_err();
        assert_eq!(err, BlobConfigError::DuplicateActivationTimestamp);
    }

    #[test]
    fn try_new_rejects_inconsistent_params() {
        // target > max is not a valid `BlobParams`.
        let bad = BlobParams {
            target_blobs_per_block: 10,
            max_blobs_per_block: 5,
            base_fee_update_fraction: 3_338_477,
            max_blobs_per_transaction: 5,
        };
        let err = BlobSchedule::try_new(vec![BlobScheduleEntry {
            activation_timestamp: 0,
            params: bad,
        }])
        .unwrap_err();
        assert_eq!(err, BlobConfigError::InvalidParams);
    }

    #[test]
    fn deserialize_routes_through_try_new() {
        // A raw entry list with duplicate timestamps must FAIL to deserialize — validation runs on
        // the serde path too, so an invalid schedule cannot slip in by bypassing `try_new`.
        let dup = vec![
            BlobScheduleEntry {
                activation_timestamp: 100,
                params: BlobParams::cancun(),
            },
            BlobScheduleEntry {
                activation_timestamp: 100,
                params: BlobParams::prague(),
            },
        ];
        let json = serde_json::to_string(&dup).unwrap();
        assert!(serde_json::from_str::<BlobSchedule>(&json).is_err());

        // A valid but unsorted list deserializes and comes out sorted (via `try_new`).
        let unsorted = vec![
            BlobScheduleEntry {
                activation_timestamp: 500,
                params: BlobParams::osaka(),
            },
            BlobScheduleEntry {
                activation_timestamp: 100,
                params: BlobParams::cancun(),
            },
        ];
        let json = serde_json::to_string(&unsorted).unwrap();
        let schedule: BlobSchedule = serde_json::from_str(&json).unwrap();
        assert_eq!(
            schedule.blob_params_for_timestamp(200),
            Some(BlobParams::cancun())
        );
        assert_eq!(
            schedule.blob_params_for_timestamp(600),
            Some(BlobParams::osaka())
        );
    }

    #[test]
    fn params_baselines_and_per_tx_cap() {
        assert_eq!(BlobParams::cancun().max_blobs_per_transaction, 6);
        assert_eq!(BlobParams::prague().max_blobs_per_transaction, 9);
        // EIP-7594: Osaka splits the per-transaction cap from the per-block maximum.
        assert_eq!(BlobParams::osaka().max_blobs_per_transaction, 6);
        assert_eq!(BlobParams::osaka().max_blobs_per_block, 9);
        assert_eq!(BlobParams::cancun().target_blob_gas(), 3 * GAS_PER_BLOB);
    }

    #[test]
    fn excess_blob_gas_below_target_is_zero() {
        let params = BlobParams::prague();
        // Parent used less than target → excess resets to zero.
        assert_eq!(
            calc_excess_blob_gas(0, GAS_PER_BLOB, 0, &params, false),
            Some(0)
        );
    }

    #[test]
    fn excess_blob_gas_standard_update_independent_vector() {
        // Cancun: target = 3 blobs (393216 gas). Parent used 4 blobs (524288 gas), excess 0.
        // Standard update = total - target = 524288 - 393216 = 131072 (one blob of gas).
        // Constants are hand-computed, not derived from the function under test.
        let params = BlobParams::cancun();
        assert_eq!(
            calc_excess_blob_gas(0, 4 * GAS_PER_BLOB, 0, &params, false),
            Some(131_072)
        );
    }

    #[test]
    fn eip7918_reserve_price_independent_vector() {
        // Cancun (target 3, max 6). parent_excess = parent_used = target (393216).
        //   standard  = total - target = 786432 - 393216 = 393216.
        //   reserve   = excess + used*(max-target)/max = 393216 + 393216*3/6 = 393216 + 196608
        //             = 589824.  (hand-computed literals, independent of the formula under test)
        let params = BlobParams::cancun();
        let target = params.target_blob_gas();
        assert_eq!(target, 393_216);

        let standard = calc_excess_blob_gas(target, target, 0, &params, false);
        assert_eq!(standard, Some(393_216));

        // Reserve branch requires the execution base fee to dominate the blob base fee. At this
        // excess the blob base fee is ~1, so blob_cost = GAS_PER_BLOB*1 = 131072; a base fee of
        // 1_000_000 gives execution_cost = BLOB_BASE_COST*1_000_000 = 8_192_000_000 > 131072.
        let reserved = calc_excess_blob_gas(target, target, 1_000_000, &params, true);
        assert_eq!(reserved, Some(589_824));
        assert!(reserved > standard); // strictly slower drawdown

        // Active but low execution base fee → reserve condition false → standard path.
        assert_eq!(
            calc_excess_blob_gas(target, target, 0, &params, true),
            standard
        );

        // An absurd base fee overflows `BLOB_BASE_COST * base_fee`; checked arithmetic returns
        // `None` rather than panicking (debug) or wrapping (release).
        assert_eq!(
            calc_excess_blob_gas(target, target, u128::MAX, &params, true),
            None
        );
    }

    #[test]
    fn eip7918_below_target_clamps_before_reserve_check() {
        // The below-target guard precedes the reserve-price branch in the
        // normative EIP-7918 pseudocode: when `parent_excess + parent_used < target_blob_gas`
        // the result is `0` unconditionally, *before* the reserve condition is evaluated.
        //
        // This vector is chosen so the reserve condition would be TRUE (base fee 1_000_000 makes
        // the execution cost dominate the ~minimum blob base fee), yet total blob gas is a single
        // blob (131072) against the Osaka target of 786432 — so the clamp must still win. A
        // "reserve-before-clamp" reordering would instead return `0 + 131072*3/9 = 43690`, so this
        // test locks the spec order.
        let params = BlobParams::osaka();
        assert_eq!(
            calc_excess_blob_gas(0, GAS_PER_BLOB, 1_000_000, &params, true),
            Some(0),
        );
    }

    #[test]
    fn calc_excess_blob_gas_rejects_zero_max() {
        let params = BlobParams {
            target_blobs_per_block: 0,
            max_blobs_per_block: 0,
            base_fee_update_fraction: BLOB_GAS_PRICE_UPDATE_FRACTION_CANCUN,
            max_blobs_per_transaction: 0,
        };
        assert_eq!(calc_excess_blob_gas(0, 0, 0, &params, false), None);
    }
}
