use crate::core::utils::U256_ZERO;
use primitive_types::U256;

pub fn log2floor(value: U256) -> u64 {
    assert_ne!(value, U256_ZERO);
    let mut l: u64 = 256;
    for i in 0..4 {
        let i = 3 - i;
        if value.0[i] == 0u64 {
            l -= 64;
        } else {
            l -= u64::from(value.0[i].leading_zeros());
            if l == 0 {
                return l;
            }
            return l - 1;
        }
    }
    l
}
