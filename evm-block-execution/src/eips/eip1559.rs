//! [EIP-1559] base-fee constants and the base-fee / gas-limit transition rules.
//!
//! # What this module deliberately leaves out
//!
//! # Arithmetic
//!
//! The base-fee formula multiplies a fee by a gas amount, so it is computed in `u128` and narrowed
//! back with a checked conversion rather than a truncating cast, so the boundary has a stated outcome
//! instead of a silent one.
//!
//! [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559

/// The default Ethereum block gas limit: 30M.
pub const ETHEREUM_BLOCK_GAS_LIMIT_30M: u64 = 30_000_000;

/// The default Ethereum block gas limit: 36M.
pub const ETHEREUM_BLOCK_GAS_LIMIT_36M: u64 = 36_000_000;

/// The bound divisor of the gas limit, used in the parent-relative gas-limit rule.
pub const GAS_LIMIT_BOUND_DIVISOR: u64 = 1024;

/// The lowest base fee reachable under mainnet EIP-1559 parameters.
///
/// With a max-change denominator of `8` (12.5 %), once the base fee has fallen to `7` Wei it cannot
/// fall further, because 12.5 % of 7 is less than 1.
pub const MIN_PROTOCOL_BASE_FEE: u64 = 7;

/// Initial base fee at the London fork.
pub const INITIAL_BASE_FEE: u64 = 1_000_000_000;

/// Base-fee max-change denominator.
pub const DEFAULT_BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8;

/// Elasticity multiplier: the block gas limit divided by this is the gas target.
pub const DEFAULT_ELASTICITY_MULTIPLIER: u64 = 2;

/// The two parameters that control how the base fee moves between blocks.
///
/// `u64` rather than the`u128`: the real values are `8` and `2`, and the narrower type
/// removes a cast at every use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseFeeParams {
    /// The base-fee max-change denominator.
    pub max_change_denominator: u64,
    /// The elasticity multiplier.
    pub elasticity_multiplier: u64,
}

impl BaseFeeParams {
    /// Builds a parameter pair.
    #[must_use]
    pub const fn new(max_change_denominator: u64, elasticity_multiplier: u64) -> Self {
        Self {
            max_change_denominator,
            elasticity_multiplier,
        }
    }

    /// The parameters Ethereum mainnet uses.
    #[must_use]
    pub const fn ethereum() -> Self {
        Self {
            max_change_denominator: DEFAULT_BASE_FEE_MAX_CHANGE_DENOMINATOR,
            elasticity_multiplier: DEFAULT_ELASTICITY_MULTIPLIER,
        }
    }

    /// The base fee the next block must carry, given this block's usage.
    ///
    /// See [`calc_next_block_base_fee`].
    ///
    /// # Errors
    /// As [`calc_next_block_base_fee`].
    #[inline]
    #[must_use]
    pub fn next_block_base_fee(self, gas_used: u64, gas_limit: u64, base_fee: u64) -> Option<u64> {
        calc_next_block_base_fee(gas_used, gas_limit, base_fee, self)
    }
}

/// The base fee the next block must carry, from this block's gas usage.
///
/// The gas target is the block gas limit divided by the elasticity multiplier. Above target the base
/// fee rises, below target it falls, at target it stays; the movement is capped at
/// `1 / max_change_denominator` of the current fee, and the whole fee is burned rather than paid to
/// the beneficiary.
///
/// # Errors
/// `None` if `elasticity_multiplier` or `max_change_denominator` is zero — a parameter set that makes
/// the formula undefined — or if the resulting fee does not fit in a `u64`.
///
/// See the [EIP-1559 spec](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1559.md).
#[must_use]
pub fn calc_next_block_base_fee(
    gas_used: u64,
    gas_limit: u64,
    base_fee: u64,
    base_fee_params: BaseFeeParams,
) -> Option<u64> {
    let gas_target = gas_limit.checked_div(base_fee_params.elasticity_multiplier)?;
    if gas_target == 0 || base_fee_params.max_change_denominator == 0 {
        // With a zero target every block is "at target"; with a zero denominator the change is
        // undefined. Neither is a parameter set any chain uses.
        return (gas_used == gas_target).then_some(base_fee);
    }

    let denominator =
        u128::from(gas_target).checked_mul(u128::from(base_fee_params.max_change_denominator))?;
    let base_fee_wide = u128::from(base_fee);

    match gas_used.cmp(&gas_target) {
        core::cmp::Ordering::Equal => Some(base_fee),
        core::cmp::Ordering::Greater => {
            let overshoot = u128::from(gas_used.checked_sub(gas_target)?);
            let delta = base_fee_wide.checked_mul(overshoot)? / denominator;
            // The rise is at least 1 Wei, so a congested block always moves the fee.
            let delta = u64::try_from(delta.max(1)).ok()?;
            base_fee.checked_add(delta)
        }
        core::cmp::Ordering::Less => {
            let undershoot = u128::from(gas_target.checked_sub(gas_used)?);
            let delta = base_fee_wide.checked_mul(undershoot)? / denominator;
            // Saturating, not checked: the fee floor is zero, and a decrease larger than the fee
            // itself simply means the fee bottoms out.
            Some(base_fee.saturating_sub(u64::try_from(delta).unwrap_or(u64::MAX)))
        }
    }
}

/// The gas limit the next block may carry, clamped to the parent-relative bound.
///
/// A block may move the gas limit by at most `parent / GAS_LIMIT_BOUND_DIVISOR - 1` in either
/// direction. Validating that bound is a parent-relative header rule; this crate does not run those
/// yet, so nothing calls this — it is the rule stated where the fork defines it.
///
/// See [go-ethereum's `block_validator.go`](https://github.com/ethereum/go-ethereum/blob/88cbfab332c96edfbe99d161d9df6a40721bd786/core/block_validator.go#L166).
#[must_use]
pub fn calculate_block_gas_limit(parent_gas_limit: u64, desired_gas_limit: u64) -> u64 {
    let delta = (parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR).saturating_sub(1);
    let min_gas_limit = parent_gas_limit.saturating_sub(delta);
    let max_gas_limit = parent_gas_limit.saturating_add(delta);
    desired_gas_limit.clamp(min_gas_limit, max_gas_limit)
}

#[cfg(test)]
mod tests {
    use super::{BaseFeeParams, calc_next_block_base_fee};

    /// The published transition vectors: at target, above it, below it, and at the floor.
    #[test]
    fn base_fee_transition_matches_the_published_vectors() {
        for &(gas_used, gas_limit, base_fee, expected) in &[
            (
                10_000_000u64,
                10_000_000u64,
                1_000_000_000u64,
                1_125_000_000u64,
            ),
            (10_000_000, 12_000_000, 1_000_000_000, 1_083_333_333),
            (10_000_000, 14_000_000, 1_000_000_000, 1_053_571_428),
            (9_000_000, 10_000_000, 1_072_671_875, 1_179_939_062),
            (10_001_000, 14_000_000, 1_059_263_476, 1_116_028_649),
            (0, 2_000_000, 1_049_238_967, 918_084_097),
            (10_000_000, 18_000_000, 1_049_238_967, 1_063_811_730),
            // The minimum rise of 1 Wei: a congested block always moves the fee, even from zero.
            (10_000_000, 18_000_000, 0, 1),
            (10_000_000, 18_000_000, 1, 2),
            (10_000_000, 18_000_000, 2, 3),
        ] {
            assert_eq!(
                calc_next_block_base_fee(gas_used, gas_limit, base_fee, BaseFeeParams::ethereum()),
                Some(expected),
                "gas_used {gas_used}, gas_limit {gas_limit}, base_fee {base_fee}"
            );
        }
    }

    /// Degenerate parameter sets are reported, not truncated into a plausible-looking fee.
    #[test]
    fn degenerate_parameters_are_reported() {
        let zero_elasticity = BaseFeeParams::new(8, 0);
        assert_eq!(
            calc_next_block_base_fee(1, 10_000, 100, zero_elasticity),
            None
        );
        // A zero gas target makes every block "at target", so only an unused block has an answer.
        let params = BaseFeeParams::ethereum();
        assert_eq!(calc_next_block_base_fee(0, 0, 100, params), Some(100));
        assert_eq!(calc_next_block_base_fee(1, 0, 100, params), None);
    }

    /// The fee floors at zero rather than wrapping when the decrease exceeds it.
    #[test]
    fn the_fee_floors_at_zero() {
        let params = BaseFeeParams::ethereum();
        assert_eq!(calc_next_block_base_fee(0, 10_000_000, 1, params), Some(1));
        assert_eq!(calc_next_block_base_fee(0, 10_000_000, 0, params), Some(0));
    }
}
