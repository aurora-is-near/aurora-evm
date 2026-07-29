//! A signed [EIP-7702] authorization tuple.
//!
//! This is the consensus form of an authorization: the six fields
//! `[chain_id, address, nonce, y_parity, r, s]` that are RLP-encoded inside a set-code
//! transaction's `authorization_list`, and therefore part of what that transaction's sender signs.
//!
//! It is distinct from [`Authorization`](aurora_evm::executor::stack::Authorization), the form the
//! executor consumes: that one holds the *recovered* `authority` and a validity flag, which are
//! products of checking a signed tuple, not inputs to it. Recovering the authority from this tuple
//! is a separate step and is not implemented here.
//!
//! [EIP-7702]: https://eips.ethereum.org/EIPS/eip-7702

use crate::transaction::signature::TxSignature;
use primitive_types::{H160, U256};

/// A signed EIP-7702 authorization: the delegation this signer authorizes, plus the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedAuthorization {
    /// Chain the authorization is valid on; zero means "any chain".
    pub chain_id: U256,
    /// Address whose code the authority delegates to.
    pub address: H160,
    /// Authority's account nonce this authorization is bound to.
    pub nonce: u64,
    /// Signature over the authorization tuple.
    pub signature: TxSignature,
}

impl rlp::Encodable for SignedAuthorization {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(6);
        stream.append(&self.chain_id);
        stream.append(&self.address);
        stream.append(&self.nonce);
        stream.append(&self.signature.y_parity);
        stream.append(&self.signature.r);
        stream.append(&self.signature.s);
    }
}

impl rlp::Decodable for SignedAuthorization {
    fn decode(rlp: &rlp::Rlp<'_>) -> Result<Self, rlp::DecoderError> {
        if rlp.item_count()? != 6 {
            return Err(rlp::DecoderError::RlpIncorrectListLen);
        }
        let y_parity: u8 = rlp.val_at(3)?;
        let y_parity = match y_parity {
            0 => false,
            1 => true,
            _ => {
                return Err(rlp::DecoderError::Custom(
                    "authorization y_parity is not 0 or 1",
                ));
            }
        };
        Ok(Self {
            chain_id: rlp.val_at(0)?,
            address: rlp.val_at(1)?,
            nonce: rlp.val_at(2)?,
            signature: TxSignature::new(y_parity, rlp.val_at(4)?, rlp.val_at(5)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SignedAuthorization;
    use crate::transaction::signature::TxSignature;
    use hex_literal::hex;
    use primitive_types::{H160, U256};

    /// The authorization carried by the EIP-7702 transaction used as a vector in `signed.rs`.
    fn vector() -> SignedAuthorization {
        SignedAuthorization {
            chain_id: U256::zero(),
            address: H160::zero(),
            nonce: 0,
            signature: TxSignature::new(
                false,
                U256::from_big_endian(&hex!(
                    "85044e88414585239b3b7b4f91c0bc6275ed817b925d973869370ca9b842925a"
                )),
                U256::from_big_endian(&hex!(
                    "2e021ec5210eb0cc051524a05e9049d6a57acdf0386e3feeae658df6d2a242a9"
                )),
            ),
        }
    }

    #[test]
    fn rlp_matches_the_consensus_bytes() {
        // Taken from the `authorization_list` of the set-code transaction vector: a six-item list
        // whose zero-valued chain_id, nonce and y_parity encode as `0x80`.
        let expected = hex!(
            "f85a8094000000000000000000000000000000000000000080"
            "80a085044e88414585239b3b7b4f91c0bc6275ed817b925d973869370ca9b842925a"
            "a02e021ec5210eb0cc051524a05e9049d6a57acdf0386e3feeae658df6d2a242a9"
        );
        assert_eq!(rlp::encode(&vector()).to_vec(), expected.to_vec());
    }

    #[test]
    fn rlp_roundtrips() {
        let encoded = rlp::encode(&vector());
        assert_eq!(
            rlp::decode::<SignedAuthorization>(&encoded).unwrap(),
            vector()
        );
    }

    #[test]
    fn decode_rejects_a_non_binary_y_parity() {
        let mut stream = rlp::RlpStream::new_list(6);
        stream.append(&U256::zero());
        stream.append(&H160::zero());
        stream.append(&0u64);
        stream.append(&2u8); // neither 0 nor 1
        stream.append(&U256::one());
        stream.append(&U256::one());
        assert!(rlp::decode::<SignedAuthorization>(&stream.out()).is_err());
    }

    #[test]
    fn decode_rejects_a_wrong_length_list() {
        let mut stream = rlp::RlpStream::new_list(5);
        for _ in 0..5 {
            stream.append(&U256::zero());
        }
        assert!(rlp::decode::<SignedAuthorization>(&stream.out()).is_err());
    }
}
