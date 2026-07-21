//! [EIP-4895] validator withdrawals.
//!
//! From Shanghai onward a block body carries *withdrawals* — balance credits pushed by the
//! consensus layer (validator exits and balance skimming). They are not transactions: a
//! withdrawal is credited unconditionally, consumes no gas, runs no EVM code, cannot fail and
//! produces no receipt or logs.
//!
//! Each [`Withdrawal`] is `{index, validator_index, address, amount}` with `amount` denominated
//! in **Gwei**; the state credit uses [`Withdrawal::amount_wei`]. The block header commits to
//! the list with `withdrawals_root` — an
//! [`ordered_trie_root`](crate::trie::ordered_trie_root) over the RLP encoding (a four-item
//! list) of each withdrawal in body order.
//!
//! # Place in the execution pipeline
//!
//! Withdrawals arrive as block input in [`BlockEnv`](crate::block::BlockEnv) and are applied in
//! the **post-execution** stage, after the transaction loop: each `amount_wei` is credited to
//! `address`, and the computed `withdrawals_root` is compared against the header value (`Some`
//! from Shanghai onward) during post-execution validation.
//!
//! [EIP-4895]: https://eips.ethereum.org/EIPS/eip-4895

use primitive_types::{H160, U256};

/// Number of Wei in one Gwei.
const GWEI_TO_WEI: u64 = 1_000_000_000;

/// A consensus-layer validator withdrawal (EIP-4895). `amount` is denominated in **Gwei**.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Withdrawal {
    /// Monotonically increasing withdrawal index.
    pub index: u64,
    /// Index of the validator the withdrawal belongs to.
    pub validator_index: u64,
    /// Recipient address.
    pub address: H160,
    /// Amount in Gwei.
    pub amount: u64,
}

impl Withdrawal {
    /// Withdrawal amount converted from Gwei to Wei.
    #[must_use]
    pub fn amount_wei(&self) -> U256 {
        U256::from(self.amount) * U256::from(GWEI_TO_WEI)
    }
}

impl rlp::Encodable for Withdrawal {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(4);
        stream.append(&self.index);
        stream.append(&self.validator_index);
        stream.append(&self.address);
        stream.append(&self.amount);
    }
}

#[cfg(test)]
mod tests {
    use super::Withdrawal;
    use primitive_types::{H160, U256};

    #[test]
    fn amount_wei_conversion() {
        let w = Withdrawal {
            index: 0,
            validator_index: 0,
            address: H160::zero(),
            amount: 1,
        };
        assert_eq!(w.amount_wei(), U256::from(1_000_000_000u64));
    }

    #[test]
    fn rlp_is_four_item_list() {
        let w = Withdrawal {
            index: 1,
            validator_index: 2,
            address: H160::repeat_byte(0xab),
            amount: 32,
        };
        let encoded = rlp::encode(&w);
        let r = rlp::Rlp::new(&encoded);
        assert_eq!(r.item_count().unwrap(), 4);
    }

    #[test]
    fn rlp_exact_bytes() {
        // Known-answer vector: list[1, 2, 0xab*20, 32]
        //   payload = 0x01 | 0x02 | (0x94 + 20 bytes) | 0x20 = 24 bytes → header 0xd8.
        let w = Withdrawal {
            index: 1,
            validator_index: 2,
            address: H160::repeat_byte(0xab),
            amount: 32,
        };
        let mut expected = vec![0xd8, 0x01, 0x02, 0x94];
        expected.extend_from_slice(&[0xab; 20]);
        expected.push(0x20);
        assert_eq!(rlp::encode(&w).to_vec(), expected);
    }
}
