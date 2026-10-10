use super::post_block_balance_increments;
use crate::spec::Spec;
use crate::withdrawal::Withdrawal;
use primitive_types::{H160, U256};

fn withdrawal(address: H160, amount: u64) -> Withdrawal {
    Withdrawal {
        index: 0,
        validator_index: 0,
        address,
        amount,
    }
}

#[test]
fn withdrawals_are_summed_per_recipient_in_wei_and_zero_sums_are_kept() {
    let a = H160::repeat_byte(0xa1);
    let b = H160::repeat_byte(0xb2);
    let increments = post_block_balance_increments(
        Spec::Prague,
        &[withdrawal(a, 2), withdrawal(b, 0), withdrawal(a, 3)],
    );
    let gwei = U256::from(1_000_000_000u64);
    assert_eq!(increments[&a], gwei * 5);
    assert_eq!(increments[&b], U256::zero());
    assert_eq!(increments.len(), 2);
}

#[test]
fn nothing_is_credited_before_shanghai() {
    let increments =
        post_block_balance_increments(Spec::London, &[withdrawal(H160::repeat_byte(0xa1), 5)]);
    assert!(increments.is_empty());
}
