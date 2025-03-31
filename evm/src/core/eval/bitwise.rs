use crate::core::utils::{Sign, I256};
use crate::utils::{U256_ONE, U256_ZERO};
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
    if op1 < 32.into() {
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
    if value == U256_ZERO || shift >= U256::from(256) {
        U256_ZERO
    } else {
        value << shift.as_usize()
    }
}

#[inline]
pub fn shr(shift: U256, value: U256) -> U256 {
    if value == U256_ZERO || shift >= U256::from(256) {
        U256_ZERO
    } else {
        value >> shift.as_usize()
    }
}

#[inline]
pub fn sar(shift: U256, value: U256) -> U256 {
    let value = I256::from(value);

    if value == I256::zero() || shift >= U256::from(256) {
        let I256(sign, _) = value;
        match sign {
            // value is 0 or >=1, pushing 0
            Sign::Plus | Sign::Zero => U256_ZERO,
            // value is <0, pushing -1
            Sign::Minus => I256(Sign::Minus, U256_ONE).into(),
        }
    } else {
        let shift: usize = shift.as_usize();

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
