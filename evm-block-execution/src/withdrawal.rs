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
#[derive(Clone, Debug, Eq, PartialEq)]
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

impl rlp::Decodable for Withdrawal {
    fn decode(rlp: &rlp::Rlp<'_>) -> Result<Self, rlp::DecoderError> {
        if crate::rlp_strict::checked_len(rlp)? != 4 {
            return Err(rlp::DecoderError::RlpIncorrectListLen);
        }
        Ok(Self {
            index: rlp.val_at(0)?,
            validator_index: rlp.val_at(1)?,
            address: rlp.val_at(2)?,
            amount: rlp.val_at(3)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Withdrawal;
    use hex_literal::hex;
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
    fn rlp_roundtrip() {
        let withdrawal = Withdrawal {
            index: u64::MAX,
            validator_index: 1_234_567,
            address: H160::repeat_byte(0x42),
            amount: 32_000_000_000,
        };
        let encoded = rlp::encode(&withdrawal);
        assert_eq!(rlp::decode::<Withdrawal>(&encoded).unwrap(), withdrawal);
    }

    #[test]
    fn rlp_roundtrip_all_zero() {
        // Zero integers encode as the empty string 0x80; the address keeps its 20 zero bytes.
        let withdrawal = Withdrawal {
            index: 0,
            validator_index: 0,
            address: H160::zero(),
            amount: 0,
        };
        let encoded = rlp::encode(&withdrawal);
        assert_eq!(
            encoded.to_vec(),
            hex!("d8808094000000000000000000000000000000000000000080")
        );
        assert_eq!(rlp::decode::<Withdrawal>(&encoded).unwrap(), withdrawal);
    }

    #[test]
    fn rlp_rejects_wrong_item_count() {
        for count in [0usize, 3, 5] {
            let mut stream = rlp::RlpStream::new_list(count);
            for _ in 0..count {
                stream.append(&0u64);
            }
            assert!(
                rlp::decode::<Withdrawal>(&stream.out()).is_err(),
                "a {count}-item list must not decode as a withdrawal"
            );
        }
    }

    #[test]
    fn rlp_rejects_non_canonical_index() {
        // A leading zero byte in an integer is not canonical RLP.
        let mut stream = rlp::RlpStream::new_list(4);
        stream.append_raw(&[0x82, 0x00, 0x01], 1);
        stream.append(&0u64);
        stream.append(&H160::zero());
        stream.append(&0u64);
        assert!(rlp::decode::<Withdrawal>(&stream.out()).is_err());
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
