//! Post-block state changes applied outside any transaction.

use crate::spec::Spec;
use crate::withdrawal::Withdrawal;
use primitive_types::{H160, U256};
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

/// Balance increments the block applies after its transactions: EIP-4895 withdrawals summed per
/// recipient (Shanghai+). A zero sum is kept, because the recipient is still touched.
#[must_use]
pub fn post_block_balance_increments(
    spec: Spec,
    withdrawals: &[Withdrawal],
) -> BTreeMap<H160, U256> {
    let mut increments = BTreeMap::new();
    if spec >= Spec::Shanghai {
        for withdrawal in withdrawals {
            let entry: &mut U256 = increments.entry(withdrawal.address).or_default();
            *entry = entry.saturating_add(withdrawal.amount_wei());
        }
    }
    increments
}
