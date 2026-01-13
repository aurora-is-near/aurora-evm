use crate::core::utils::{Sign, I256};
use crate::utils::{U256_ONE, U256_VALUE_256, U256_VALUE_32, U256_ZERO};
use primitive_types::U256;

#[inline]
pub fn slt(op1: U256, op2: U256) -> U256 {
    let op1: I256 = op1.into();
    let op2: I256 = op2.into();

    if op1.lt(&op2) {
        U256_ONE
    } else {
        U256_ZERO
    }
}

#[inline]
pub fn sgt(op1: U256, op2: U256) -> U256 {
    let op1: I256 = op1.into();
    let op2: I256 = op2.into();

    if op1.gt(&op2) {
        U256_ONE
    } else {
        U256_ZERO
    }
}

#[inline]
pub fn iszero(op1: U256) -> U256 {
    if op1 == U256_ZERO {
        U256_ONE
    } else {
        U256_ZERO
    }
}

#[inline]
pub fn not(op1: U256) -> U256 {
    !op1
}

#[inline]
pub fn byte(op1: U256, op2: U256) -> U256 {
    let mut ret = U256_ZERO;
    if op1 < U256_VALUE_32 {
        let o = op1.as_usize();
        for i in 0..8 {
            let t = 255 - (7 - i + 8 * o);
            let value = (op2 >> t) & U256_ONE;
            ret = ret.overflowing_add(value << i).0;
        }
    }
    ret
}

#[inline]
pub fn shl(shift: U256, value: U256) -> U256 {
    if value == U256_ZERO || shift >= U256_VALUE_256 {
        U256_ZERO
    } else {
        value << shift.as_usize()
    }
}

#[inline]
pub fn shr(shift: U256, value: U256) -> U256 {
    if value == U256_ZERO || shift >= U256_VALUE_256 {
        U256_ZERO
    } else {
        value >> shift.as_usize()
    }
}

#[inline]
pub fn sar(shift: U256, value: U256) -> U256 {
    let value = I256::from(value);

    if value == I256::zero() || shift >= U256_VALUE_256 {
        let I256(sign, _) = value;
        match sign {
            // value is 0 or >=1, pushing 0
            Sign::Plus | Sign::Zero => U256_ZERO,
            // value is <0, pushing -1
            Sign::Minus => I256(Sign::Minus, U256_ONE).into(),
        }
    } else {
        let shift = shift.as_usize();
        match value.0 {
            Sign::Plus | Sign::Zero => value.1 >> shift,
            Sign::Minus => {
                let shifted = ((value.1.overflowing_sub(U256_ONE).0) >> shift)
                    .overflowing_add(U256_ONE)
                    .0;
                I256(Sign::Minus, shifted).into()
            }
        }
    }
}

/// EIP-7939: CLZ - Count Leading Zeros. Osaka hard fork.
#[inline]
pub fn clz(op1: U256) -> U256 {
    U256::from(op1.leading_zeros())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::cognitive_complexity)]
    #[test]
    fn test_clz() {
        // Zero case (EIP spec: returns 256)
        assert_eq!(clz(U256::zero()), U256::from(256));

        // Max value and MSB cases
        assert_eq!(clz(U256::MAX), U256::zero());
        assert_eq!(clz(U256::one() << 255), U256::zero());
        assert_eq!(clz((U256::one() << 255) | U256::one()), U256::zero());

        // High bit boundaries
        assert_eq!(clz(U256::one() << 254), U256::from(1));
        assert_eq!(clz((U256::one() << 255) - U256::one()), U256::from(1)); // 0x7FFFF...
        assert_eq!(clz(U256::MAX >> 1), U256::from(1));

        // Random high shifts
        assert_eq!(clz(U256::one() << 250), U256::from(5));

        // 192 bit boundary (Transition from word[3] to word[2])
        assert_eq!(clz(U256::one() << 192), U256::from(63));
        assert_eq!(clz(U256::one() << 191), U256::from(64));
        assert_eq!(clz(U256::from(u64::MAX)), U256::from(192)); // Only lowest 64 bits set

        // 128 bit boundary (Transition from word[2] to word[1])
        assert_eq!(clz(U256::one() << 128), U256::from(127));
        assert_eq!(clz(U256::one() << 127), U256::from(128));
        assert_eq!(clz(U256::from(u128::MAX)), U256::from(128));
        assert_eq!(clz(U256::MAX >> 128), U256::from(128));

        // 64 bit boundary (Transition from word[1] to word[0])
        assert_eq!(clz(U256::one() << 64), U256::from(191));
        assert_eq!(clz(U256::one() << 63), U256::from(192));

        // Small numbers and masks
        assert_eq!(clz(U256::from(0xFFFF)), U256::from(240));
        assert_eq!(clz(U256::from(0x100)), U256::from(247));
        assert_eq!(clz(U256::from(0xFF)), U256::from(248));

        // Low bit shifts
        assert_eq!(clz(U256::one() << 20), U256::from(235));
        assert_eq!(clz(U256::one() << 10), U256::from(245));

        // Very small numbers
        assert_eq!(clz(U256::from(16)), U256::from(251));
        assert_eq!(clz(U256::from(15)), U256::from(252));
        assert_eq!(clz(U256::from(8)), U256::from(252));
        assert_eq!(clz(U256::from(7)), U256::from(253));
        assert_eq!(clz(U256::from(4)), U256::from(253));
        assert_eq!(clz(U256::from(3)), U256::from(254));
        assert_eq!(clz(U256::from(2)), U256::from(254));
        assert_eq!(clz(U256::from(1)), U256::from(255));
    }
}
