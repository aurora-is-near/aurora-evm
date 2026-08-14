//! The block body: the lists a header commits to.
//!
//! [`BlockBody`] holds the block's transactions in their consensus form
//! ([`SignedTxEnvelope`]) and, from Shanghai on, its validator withdrawals. The header commits to
//! both through a root — `transactions_root` and `withdrawals_root` — so the body is the pre-image
//! those roots are re-derived from.
//!
//! Ommers are not modelled: this crate executes post-merge blocks only, where the list is always
//! empty and `ommers_hash` is therefore the constant
//! [`EMPTY_OMMERS_HASH`](crate::constants::EMPTY_OMMER_ROOT_HASH), checkable on the header alone.

use crate::transaction::SignedTxEnvelope;
use crate::withdrawal::Withdrawal;

/// The body of an Ethereum block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockBody {
    /// The block's transactions, in execution order.
    pub transactions: Vec<SignedTxEnvelope>,
    /// Validator withdrawals (EIP-4895); `None` before Shanghai.
    pub withdrawals: Option<Vec<Withdrawal>>,
}

impl BlockBody {
    /// Builds a body from its transactions and withdrawals.
    #[must_use]
    pub const fn new(
        transactions: Vec<SignedTxEnvelope>,
        withdrawals: Option<Vec<Withdrawal>>,
    ) -> Self {
        Self {
            transactions,
            withdrawals,
        }
    }

    /// The validator withdrawals, if the block carries any.
    #[must_use]
    pub fn withdrawals(&self) -> Option<&[Withdrawal]> {
        self.withdrawals.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::BlockBody;
    use crate::transaction::SignedTxEnvelope;
    use crate::withdrawal::Withdrawal;
    use hex_literal::hex;
    use primitive_types::H160;

    /// A real EIP-1559 transaction, decoded from its consensus bytes.
    fn transaction() -> SignedTxEnvelope {
        SignedTxEnvelope::decode_2718(&hex!("02f8b00142843b9aca008504a817c80082ad62946069a6c32cf691f5982febae4faf8a6f3ab2f0f680b844a22cb4650000000000000000000000005eee75727d804a2b13038928d36f8b188945a57a0000000000000000000000000000000000000000000000000000000000000000c080a0840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565a025e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1")).unwrap()
    }

    #[test]
    fn body_holds_transactions_and_withdrawals() {
        let withdrawal = Withdrawal {
            index: 1,
            validator_index: 2,
            address: H160::repeat_byte(0xab),
            amount: 32,
        };
        let body = BlockBody::new(vec![transaction()], Some(vec![withdrawal.clone()]));
        assert_eq!(body.transactions.len(), 1);
        assert_eq!(body.withdrawals(), Some(&[withdrawal][..]));
    }

    #[test]
    fn default_body_is_empty() {
        let body = BlockBody::default();
        assert!(body.transactions.is_empty());
        assert!(body.withdrawals().is_none());
    }
}
