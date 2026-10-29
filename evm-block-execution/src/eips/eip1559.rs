//! [EIP-1559] base-fee constants and the base-fee / gas-limit transition rules.
//!
//! Intermediate fee arithmetic uses `u128` and narrows to `u64` with checked conversions.
//!
//! [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559

/// The default Ethereum block gas limit: 30M.
pub const ETHEREUM_BLOCK_GAS_LIMIT_30M: u64 = 30_000_000;

/// The default Ethereum block gas limit: 36M.
pub const ETHEREUM_BLOCK_GAS_LIMIT_36M: u64 = 36_000_000;

/// The bound divisor of the gas limit, used in the parent-relative gas-limit rule.
pub const GAS_LIMIT_BOUND_DIVISOR: u64 = 1024;

/// Lowest base fee reachable with the mainnet denominator of 8: 12.5% of 7 Wei rounds to zero.
pub const MIN_PROTOCOL_BASE_FEE: u64 = 7;

/// Initial base fee at the London fork.
pub const INITIAL_BASE_FEE: u64 = 1_000_000_000;

/// Base-fee max-change denominator.
pub const DEFAULT_BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8;

/// Elasticity multiplier: the block gas limit divided by this is the gas target.
pub const DEFAULT_ELASTICITY_MULTIPLIER: u64 = 2;

/// Parameters controlling parent-to-child base-fee changes.
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

    /// Returns the base fee required for the next block.
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

/// Calculates the next block's base fee from the parent's gas usage.
///
/// Usage above the elasticity-adjusted target raises the fee; usage below it lowers the fee.
///
/// # Errors
/// `None` if either parameter makes the formula undefined or the result exceeds `u64`.
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
    if base_fee_params.max_change_denominator == 0 {
        // Reject the invalid parameter set even when an at-target block would avoid the division.
        return None;
    }
    if gas_target == 0 {
        // With a zero target, only an unused block has a defined transition.
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
            // A decrease larger than the fee reaches the protocol floor of zero.
            Some(base_fee.saturating_sub(u64::try_from(delta).unwrap_or(u64::MAX)))
        }
    }
}

/// Clamps a desired gas limit to the parent-relative EIP-1559 bound.
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

    /// Published vectors spanning target, increase, decrease and floor cases.
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

    /// Invalid parameters fail instead of producing a plausible fee.
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

        // A zero denominator is invalid even for an at-target block.
        let zero_denominator = BaseFeeParams::new(0, 2);
        assert_eq!(zero_denominator.max_change_denominator, 0);
        for (gas_used, gas_limit) in [(5_000_000, 10_000_000), (1, 10_000_000), (0, 0), (1, 0)] {
            assert_eq!(
                calc_next_block_base_fee(gas_used, gas_limit, 100, zero_denominator),
                None,
                "gas_used {gas_used}, gas_limit {gas_limit}"
            );
        }
    }

    /// The fee floors at zero rather than wrapping when the decrease exceeds it.
    #[test]
    fn the_fee_floors_at_zero() {
        let params = BaseFeeParams::ethereum();
        assert_eq!(calc_next_block_base_fee(0, 10_000_000, 1, params), Some(1));
        assert_eq!(calc_next_block_base_fee(0, 10_000_000, 0, params), Some(0));
    }
}
