use crate::core::utils::{Sign, I256};
use primitive_types::U256;

#[inline]
pub fn slt(op1: U256, op2: U256) -> U256 {
    let op1: I256 = op1.into();
    let op2: I256 = op2.into();

    if op1.lt(&op2) {
        U256::one()
    } else {
        U256::zero()
    }
}

#[inline]
pub fn sgt(op1: U256, op2: U256) -> U256 {
    let op1: I256 = op1.into();
    let op2: I256 = op2.into();

    if op1.gt(&op2) {
        U256::one()
    } else {
        U256::zero()
    }
}

#[inline]
pub fn iszero(op1: U256) -> U256 {
    if op1 == U256::zero() {
        U256::one()
    } else {
        U256::zero()
    }
}

#[inline]
pub fn not(op1: U256) -> U256 {
    !op1
}

#[inline]
pub fn byte(op1: U256, op2: U256) -> U256 {
    let mut ret = U256::zero();
    if op1 < 32.into() {
        let o = op1.as_usize();
        for i in 0..8 {
            let t = 255 - (7 - i + 8 * o);
            let value = (op2 >> t) & U256::one();
            ret = ret.overflowing_add(value << i).0;
        }
    }
    ret
}

#[inline]
pub fn shl(shift: U256, value: U256) -> U256 {
    if value == U256::zero() || shift >= U256::from(256) {
        U256::zero()
    } else {
        value << shift.as_usize()
    }
}

#[inline]
pub fn shr(shift: U256, value: U256) -> U256 {
    if value == U256::zero() || shift >= U256::from(256) {
        U256::zero()
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
            Sign::Plus | Sign::Zero => U256::zero(),
            // value is <0, pushing -1
            Sign::Minus => I256(Sign::Minus, U256::one()).into(),
        }
    } else {
        let shift: usize = shift.as_usize();

        match value.0 {
            Sign::Plus | Sign::Zero => value.1 >> shift,
            Sign::Minus => {
                let shifted = ((value.1.overflowing_sub(U256::one()).0) >> shift)
                    .overflowing_add(U256::one())
                    .0;
                I256(Sign::Minus, shifted).into()
            }
        }
    }
}
