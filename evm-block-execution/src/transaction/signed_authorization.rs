//! Consensus representation of a signed [EIP-7702] authorization.
//!
//! The encoded tuple is `[chain_id, address, nonce, y_parity, r, s]`. It is distinct from the
//! executor's [`Authorization`], which contains a
//! recovered authority and a validity flag. Projection recovers that form from this signed input.
//!
//! EIP-7702 only requires `y_parity < 2**8`. Values other than 0 and 1 are validly encoded tuples
//! whose recovery fails and which execution skips; rejecting or normalizing them would change the
//! carrying transaction's signing preimage. [`SignedAuthorization::signature`] interprets the byte
//! at recovery time.
//!
//! [EIP-7702]: https://eips.ethereum.org/EIPS/eip-7702

use crate::crypto::keccak256;
use crate::transaction::signature::TxSignature;
use aurora_evm::executor::stack::Authorization;
use primitive_types::{H160, U256};

/// The `MAGIC` byte EIP-7702 prefixes an authorization's signing preimage with, so that an
/// authorization signature can never be mistaken for a transaction signature.
const MAGIC: u8 = 0x05;

/// A signed EIP-7702 authorization: the delegation this signer authorizes, plus the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedAuthorization {
    /// Chain the authorization is valid on; zero means "any chain".
    pub chain_id: U256,
    /// Address whose code the authority delegates to.
    pub address: H160,
    /// Authority's account nonce this authorization is bound to.
    pub nonce: u64,
    /// Parity of the y coordinate of the key that signed the tuple, as it appears on the wire.
    ///
    /// A [`u8`], not a `bool`: see the module docs. Use [`Self::signature`] for the recoverable form.
    pub y_parity: u8,
    /// Signature `r` component.
    pub r: U256,
    /// Signature `s` component.
    pub s: U256,
}

impl SignedAuthorization {
    /// The signature this tuple carries, or `None` when [`Self::y_parity`] is not a parity and no
    /// authority can therefore be recovered from it (EIP-7702 behaviour step 3).
    #[must_use]
    pub const fn signature(&self) -> Option<TxSignature> {
        match self.y_parity {
            0 => Some(TxSignature::new(false, self.r, self.s)),
            1 => Some(TxSignature::new(true, self.r, self.s)),
            _ => None,
        }
    }

    /// Recovers the executor representation of this authorization.
    ///
    /// Invalid tuples remain in the list as `is_valid: false`, because EIP-7702 charges intrinsic gas
    /// for every tuple. This checks only chain id, signature normalization and recovery; state-based
    /// nonce and delegation checks remain with the executor. `rlp_stream` is cleared and reused for
    /// the signing preimage.
    ///
    /// # Panics
    /// Panics if the internal three-field signing-preimage encoder does not finish its bounded RLP
    /// list. This signals a programming error, not an invalid authorization tuple.
    #[must_use]
    pub(crate) fn recover_authority(
        &self,
        tx_chain_id: u64,
        rlp_stream: &mut rlp::RlpStream,
    ) -> Authorization {
        let invalid = Authorization::new(H160::zero(), self.address, self.nonce, false);

        // `chain_id == 0` authorises on every chain; otherwise it must be this transaction's own.
        if !self.chain_id.is_zero() && self.chain_id != U256::from(tx_chain_id) {
            return invalid;
        }
        // `y_parity` outside `{0, 1}` yields no signature at all, which is a well-formed tuple that
        // simply authorises nobody.
        let Some(signature) = self.signature() else {
            return invalid;
        };
        if !signature.is_s_normalized() {
            return invalid;
        }

        rlp_stream.clear();
        // Not an RLP item: EIP-7702 hashes the raw magic byte followed by the encoded list.
        rlp_stream.append_raw(&[MAGIC], 0);
        rlp_stream.begin_list(3);
        rlp_stream.append(&self.chain_id);
        rlp_stream.append(&self.address);
        rlp_stream.append(&self.nonce);
        // `as_raw()` does not perform `RlpStream::out()`'s completion check; fail closed before a
        // malformed internal preimage can select the wrong authority.
        assert!(
            rlp_stream.is_finished(),
            "EIP-7702 authorization signing preimage left an open list"
        );
        let message = libsecp256k1::Message::parse(&keccak256(rlp_stream.as_raw()).0);
        let Ok(parsed) = libsecp256k1::Signature::parse_standard_slice(&signature.rs_bytes())
        else {
            return invalid;
        };
        let Ok(recovery_id) = libsecp256k1::RecoveryId::parse(u8::from(signature.y_parity)) else {
            return invalid;
        };
        let Ok(key) = libsecp256k1::recover(&message, &parsed, &recovery_id) else {
            return invalid;
        };
        // The address is the low 20 bytes of `keccak256` over the key without its `0x04` tag.
        let authority = H160::from_slice(&keccak256(&key.serialize()[1..]).as_bytes()[12..]);
        Authorization::new(authority, self.address, self.nonce, true)
    }
}

impl rlp::Encodable for SignedAuthorization {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(6);
        stream.append(&self.chain_id);
        stream.append(&self.address);
        stream.append(&self.nonce);
        stream.append(&self.y_parity);
        stream.append(&self.r);
        stream.append(&self.s);
    }
}

impl rlp::Decodable for SignedAuthorization {
    fn decode(rlp: &rlp::Rlp<'_>) -> Result<Self, rlp::DecoderError> {
        if crate::rlp_strict::checked_len(rlp)? != 6 {
            return Err(rlp::DecoderError::RlpIncorrectListLen);
        }
        Ok(Self {
            chain_id: rlp.val_at(0)?,
            address: rlp.val_at(1)?,
            nonce: rlp.val_at(2)?,
            // `val_at::<u8>` is EIP-7702's `assert auth.y_parity < 2**8` and accepts only the
            // canonical minimal encoding of the value; no further check belongs here.
            y_parity: rlp.val_at(3)?,
            r: rlp.val_at(4)?,
            s: rlp.val_at(5)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SignedAuthorization;
    use hex_literal::hex;
    use primitive_types::{H160, U256};

    /// The authorization carried by the EIP-7702 transaction used as a vector in
    /// [`types::eip7702`](crate::transaction::types::eip7702).
    fn vector() -> SignedAuthorization {
        SignedAuthorization {
            chain_id: U256::zero(),
            address: H160::zero(),
            nonce: 0,
            y_parity: 0,
            r: U256::from_big_endian(&hex!(
                "85044e88414585239b3b7b4f91c0bc6275ed817b925d973869370ca9b842925a"
            )),
            s: U256::from_big_endian(&hex!(
                "2e021ec5210eb0cc051524a05e9049d6a57acdf0386e3feeae658df6d2a242a9"
            )),
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

    /// A six-item tuple whose `y_parity` item is spliced in raw, so non-minimal forms can be built.
    fn tuple_with_parity(parity: &[u8]) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new_list(6);
        stream.append(&U256::zero());
        stream.append(&H160::zero());
        stream.append(&0u64);
        stream.append_raw(parity, 1);
        stream.append(&U256::one());
        stream.append(&U256::one());
        stream.out().to_vec()
    }

    #[test]
    fn every_y_parity_below_256_decodes_and_only_0_and_1_yield_a_signature() {
        for parity in 0u8..=255 {
            let encoded = tuple_with_parity(&rlp::encode(&parity));
            let decoded = rlp::decode::<SignedAuthorization>(&encoded)
                .unwrap_or_else(|err| panic!("y_parity {parity}: {err}"));
            assert_eq!(decoded.y_parity, parity);
            assert_eq!(
                decoded.signature().is_some(),
                parity < 2,
                "y_parity {parity}"
            );
            // Verbatim: the parity is inside the carrying transaction's signing preimage.
            assert_eq!(rlp::encode(&decoded).to_vec(), encoded, "y_parity {parity}");
        }
    }

    #[test]
    fn decode_rejects_a_y_parity_of_256_or_more() {
        // EIP-7702's `assert auth.y_parity < 2**8`. No fixture covers it, so it is synthetic.
        assert_eq!(
            rlp::decode::<SignedAuthorization>(&tuple_with_parity(&hex!("820100"))).unwrap_err(),
            rlp::DecoderError::RlpIsTooBig
        );
    }

    #[test]
    fn decode_rejects_a_non_minimal_y_parity() {
        // One value, one encoding: `0x80` is zero, `0x00` and `0x81 00` are not.
        for parity in [
            hex!("00").to_vec(),
            hex!("8100").to_vec(),
            hex!("8101").to_vec(),
        ] {
            assert!(
                rlp::decode::<SignedAuthorization>(&tuple_with_parity(&parity)).is_err(),
                "{parity:02x?}"
            );
        }
    }

    /// The preimage is `MAGIC ‖ rlp([chain_id, address, nonce])`, and every part of that is
    /// consensus-critical: the magic byte separates an authorization signature from a transaction
    /// signature, and the three fields are the ones EIP-7702 binds — the `y_parity, r, s` that follow
    /// them in the tuple are the signature *over* this, never part of it.
    ///
    /// Asserted on the bytes rather than only through the address they recover, so that a wrong magic
    /// byte or a reordered field is reported here, as the preimage it is, instead of surfacing as an
    /// unexplained sender three layers up.
    #[test]
    fn the_signing_preimage_is_the_magic_byte_and_three_fields() {
        let mut stream = rlp::RlpStream::new();
        let recovered = vector().recover_authority(1, &mut stream);

        // `d7` is a 23-byte list: `80` (chain_id 0), `94 ‖ 20 zero bytes` (address), `80` (nonce 0).
        assert_eq!(
            stream.as_raw(),
            hex!("05d78094000000000000000000000000000000000000000080"),
            "MAGIC ‖ rlp([chain_id, address, nonce])"
        );

        // The authority this preimage recovers. Also asserted where the carrying transaction is
        // decoded, which is what makes it a value and not just this function's own output.
        assert!(recovered.is_valid);
        assert_eq!(
            recovered.authority,
            H160(hex!("dde0a8f1c754bca49c7ad9017cbb242d3116d9a3"))
        );

        // A `chain_id` of zero authorises on every chain, so the preimage does not depend on the
        // transaction's — the tuple's own field is what is hashed.
        let mut other_chain = rlp::RlpStream::new();
        assert_eq!(
            vector().recover_authority(0xdead_beef, &mut other_chain),
            recovered
        );
        assert_eq!(other_chain.as_raw(), stream.as_raw());
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
