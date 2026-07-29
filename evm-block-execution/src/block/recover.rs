//! Establishing a block's senders from public keys supplied alongside it.
//!
//! Recovering a sender the usual way means `ecrecover`: solving for the public key that produced a
//! signature. Verifying one is cheaper — given the public key, only a single scalar multiplication
//! and a comparison are needed, with no point decompression. A stateless validator can therefore be
//! handed the public keys as part of its input and *check* them rather than recover them, which is
//! why [`recover_block_with_public_keys`] takes them as an argument.
//!
//! That makes the keys untrusted input, and harmless as such: a key that did not sign the
//! transaction fails verification, so the only thing a caller can do by supplying the wrong key is
//! having the block rejected. What the verified key gives is the sender address, which is just
//! `keccak256(key)[12..]`.
//!
//! Two rules are applied per transaction, in this order:
//!
//! 1. `s` must be in the lower half of the curve order ([EIP-2]). `verify` does not enforce this,
//!    and both `(r, s)` and `(r, n - s)` satisfy it, so without this check a transaction could be
//!    re-signed into a different hash while keeping its sender.
//! 2. the signature must verify against the supplied key over the transaction's
//!    [signature hash](SignedTransaction::signature_hash).
//!
//! [EIP-2]: https://eips.ethereum.org/EIPS/eip-2

use crate::block::Block;
use crate::block::recovered::RecoveredBlock;
use crate::crypto::keccak256;
use crate::transaction::{SignedTransaction, TxEncodeError};
use core::fmt;
use core::ops::Deref;
use primitive_types::H160;
use serde::{Deserialize, Serialize};
use serde_with::{Bytes, serde_as};

/// Length of an uncompressed SEC1 public key: the `0x04` tag followed by the two coordinates.
const UNCOMPRESSED_PUBLIC_KEY_LEN: usize = 65;

/// The SEC1 tag that introduces an uncompressed public key.
const UNCOMPRESSED_TAG: u8 = 0x04;

/// An uncompressed secp256k1 public key: `0x04 || x || y`.
#[serde_as]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UncompressedPublicKey(#[serde_as(as = "Bytes")] pub [u8; UNCOMPRESSED_PUBLIC_KEY_LEN]);

impl Deref for UncompressedPublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl UncompressedPublicKey {
    /// The account address this key controls: the low 20 bytes of `keccak256(x || y)`.
    ///
    /// # Errors
    /// [`SenderRecoveryError::InvalidPublicKey`] if the key does not carry the uncompressed tag.
    pub fn address(&self, index: usize) -> Result<H160, SenderRecoveryError> {
        if self.0[0] != UNCOMPRESSED_TAG {
            return Err(SenderRecoveryError::InvalidPublicKey { index });
        }
        // The tag is not part of the hashed key material.
        let hash = keccak256(&self.0[1..]);
        Ok(H160::from_slice(&hash[12..]))
    }
}

/// Why a block's senders cannot be established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderRecoveryError {
    /// There is not exactly one public key per transaction.
    KeyCountMismatch {
        /// Number of public keys supplied.
        keys: usize,
        /// Number of transactions in the block.
        transactions: usize,
    },
    /// A transaction's `s` is in the upper half of the curve order, which EIP-2 forbids.
    SignatureSNotNormalized {
        /// Index of the offending transaction.
        index: usize,
    },
    /// A transaction's fields cannot be encoded, so it has no signature hash.
    Encoding {
        /// Index of the offending transaction.
        index: usize,
        /// Why the encoding failed.
        source: TxEncodeError,
    },
    /// The supplied public key is not a valid uncompressed secp256k1 point.
    InvalidPublicKey {
        /// Index of the offending transaction.
        index: usize,
    },
    /// The signature's `r` or `s` is out of range.
    InvalidSignature {
        /// Index of the offending transaction.
        index: usize,
    },
    /// The signature does not verify against the supplied public key.
    VerificationFailed {
        /// Index of the offending transaction.
        index: usize,
    },
}

impl fmt::Display for SenderRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyCountMismatch { keys, transactions } => write!(
                f,
                "block has {transactions} transactions but {keys} public keys were supplied"
            ),
            Self::SignatureSNotNormalized { index } => write!(
                f,
                "transaction {index} has a non-normalized signature `s` (EIP-2)"
            ),
            Self::Encoding { index, source } => {
                write!(f, "transaction {index} cannot be encoded: {source}")
            }
            Self::InvalidPublicKey { index } => {
                write!(f, "public key for transaction {index} is not a valid point")
            }
            Self::InvalidSignature { index } => {
                write!(f, "signature of transaction {index} is out of range")
            }
            Self::VerificationFailed { index } => write!(
                f,
                "signature of transaction {index} does not match the supplied public key"
            ),
        }
    }
}

impl core::error::Error for SenderRecoveryError {}

/// Establishes the sender of every transaction in `block` by verifying its signature against the
/// matching public key, and returns the block paired with those senders.
///
/// The keys must be given in transaction order, one per transaction.
///
/// # Errors
/// [`SenderRecoveryError`] if the key count does not match the transaction count, or if any
/// transaction fails the EIP-2 `s` check, cannot be encoded, or does not verify against its key.
pub fn recover_block_with_public_keys(
    block: Block,
    public_keys: &[UncompressedPublicKey],
) -> Result<RecoveredBlock, SenderRecoveryError> {
    let transactions = block.transactions();
    if transactions.len() != public_keys.len() {
        return Err(SenderRecoveryError::KeyCountMismatch {
            keys: public_keys.len(),
            transactions: transactions.len(),
        });
    }

    // Verify each transaction signature against its corresponding public key
    let senders = public_keys
        .iter()
        .zip(transactions)
        .enumerate()
        .map(|(index, (key, transaction))| verify_and_compute_sender(key, transaction, index))
        .collect::<Result<Vec<_>, _>>()?;

    // Senders were just established one-per-transaction, so the checked constructor cannot fail;
    // the lazy hash keeps callers that never ask for it from paying for it.
    Ok(RecoveredBlock::new_unhashed(block, senders))
}

/// Verifies one transaction's signature against `key` and returns the address that key controls.
fn verify_and_compute_sender(
    pub_key: &UncompressedPublicKey,
    transaction: &SignedTransaction,
    index: usize,
) -> Result<H160, SenderRecoveryError> {
    // EIP-2 first: `verify` accepts both `s` and `n - s`, so a malleable signature would otherwise
    // pass and yield the same sender under a different transaction hash.
    if !transaction.signature.is_s_normalized() {
        return Err(SenderRecoveryError::SignatureSNotNormalized { index });
    }

    let tx_signature_hash = transaction
        .signature_hash()
        .map_err(|source| SenderRecoveryError::Encoding { index, source })?;

    let address = pub_key.address(index)?;
    let message = libsecp256k1::Message::parse(&tx_signature_hash.0);
    let public_key = libsecp256k1::PublicKey::parse(&pub_key.0)
        .map_err(|_| SenderRecoveryError::InvalidPublicKey { index })?;
    let signature =
        libsecp256k1::Signature::parse_standard_slice(&transaction.signature.rs_bytes())
            .map_err(|_| SenderRecoveryError::InvalidSignature { index })?;

    if libsecp256k1::verify(&message, &signature, &public_key) {
        Ok(address)
    } else {
        Err(SenderRecoveryError::VerificationFailed { index })
    }
}

#[cfg(test)]
mod tests {
    use super::{SenderRecoveryError, UncompressedPublicKey, recover_block_with_public_keys};
    use crate::block::{Block, BlockBody, Header};
    use crate::transaction::SignedTransaction;
    use hex_literal::hex;
    use primitive_types::{H160, U256};

    /// A transaction with the public key that signed it and the sender that key derives.
    ///
    /// All three come from Ethereum test fixtures: the raw bytes and `sender` are taken verbatim,
    /// and the key is the one that verifies against them.
    struct Vector {
        name: &'static str,
        raw: &'static [u8],
        public_key: [u8; 65],
        sender: [u8; 20],
    }

    fn vectors() -> Vec<Vector> {
        vec![
            Vector {
                name: "legacy, pre-EIP-155",
                raw: &hex!(
                    "f85f800182520894000000000000000000000000000b9331677e6ebf0a801ca098ff921201554726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4aa01887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a3"
                ),
                public_key: hex!(
                    "0420f7f2a19ed53bda096b6476524fde50c770560d13c4c26ab3aa46f065699644aeab7e91498d00094f24000b8f919cbd82a3f0318a38b7790d8b9ed068df0b30"
                ),
                sender: hex!("2fbffb0b9f709fd1fa4db9ff7342f2e6b3b2b7a6"),
            },
            Vector {
                name: "EIP-2930",
                raw: &hex!(
                    "01f89b01800a8301e974943068947c19dbbc5a170610a69c65e341f0a0b7458080f838f7940000000000000000000000000000000000000000e1a0000000000000000000000000000000000000000000000000000000000000000001a0712d63f4983ce033255f9adfe3b159f465766eac906591091e3ad03ffc06ad16a0078e21a3501b9fc9b9b9e223cc19768be044d5c7c6faf1fbc0f5aa4deb325fe9"
                ),
                public_key: hex!(
                    "048b8097fdae211681bc03116bf15894db78988484e8060ab53d5c04035b7c89b7b2bde3506bcc250a3332fa8bd09f4065e69b7a5aa52e645fb0d998d2613b7bab"
                ),
                sender: hex!("5482624482f9454fbb0dff7b7201a709ba5fb4c2"),
            },
            Vector {
                name: "EIP-1559",
                raw: &hex!(
                    "02f8b00142843b9aca008504a817c80082ad62946069a6c32cf691f5982febae4faf8a6f3ab2f0f680b844a22cb4650000000000000000000000005eee75727d804a2b13038928d36f8b188945a57a0000000000000000000000000000000000000000000000000000000000000000c080a0840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565a025e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1"
                ),
                public_key: hex!(
                    "047a48f1002b71017a05d369d5412aaeb7ed93f8789a09fe617056ba23c337502f2206cea7c7a7a90dc1d155e8d3b5a35ed3da3b3ce075be16c852e2c7e9df185c"
                ),
                sender: hex!("dd6b8b3dc6b7ad97db52f08a275ff4483e024cea"),
            },
            Vector {
                name: "EIP-4844",
                raw: &hex!(
                    "03f8a601808007830f424094000f3df6d732807ef1319fb7b8bb8522d0beac0280a0000000000000000000000000000000000000000000000000000000000000000cc001e1a0010000000000000000000000000000000000000000000000000000000000000001a08cdee4f529448c31aef67fb75346f7e0279e9545da3194191835349e19888b41a013e7d078013af8d334a2b09246dad964099443bb85b20d40bb3b08ea3c93229f"
                ),
                public_key: hex!(
                    "0420b83f49768edf425eba13de548b7ea233fdf49ca3088bf567aff6d98c6f93129e6a8f9a518aebfa7eeb1aacc1b5912ae32e2afb6f15f2a62cf08b2582a525ce"
                ),
                sender: hex!("cacd1a2f14e2c49f3631549a5752afe9812c2795"),
            },
            Vector {
                name: "EIP-7702",
                raw: &hex!(
                    "04f8e101808007830f424094000f3df6d732807ef1319fb7b8bb8522d0beac0280a0000000000000000000000000000000000000000000000000000000000000000cc0f85cf85a809400000000000000000000000000000000000000008080a085044e88414585239b3b7b4f91c0bc6275ed817b925d973869370ca9b842925aa02e021ec5210eb0cc051524a05e9049d6a57acdf0386e3feeae658df6d2a242a980a0f2e0c327202f18c44b074c628433f8d7ed09f7fbe180684f1ab6da84b8d94c4aa00c755520f565a678bac8959549dba76a7c2120025b53e1565b09845880a66dbf"
                ),
                public_key: hex!(
                    "04c1695f081302a3d90ee071f1fbfff4487bb0430dd928a5f1f321921e724954a82a6c93fa00710452553f20a59bf7adc2e3ced6d3a73379990644eb0431409723"
                ),
                sender: hex!("d7d82ecec412de189ae2257aa14437edf77bf89a"),
            },
        ]
    }

    fn block_of(transactions: Vec<SignedTransaction>) -> Block {
        Block::new(
            Header {
                number: 1,
                ..Header::default()
            },
            BlockBody::new(transactions, None),
        )
    }

    #[test]
    fn every_transaction_type_recovers_its_fixture_sender() {
        for vector in vectors() {
            let transaction = SignedTransaction::decode_2718(vector.raw).unwrap();
            let block = block_of(vec![transaction]);
            let keys = [UncompressedPublicKey(vector.public_key)];
            let recovered = recover_block_with_public_keys(block, &keys)
                .unwrap_or_else(|err| panic!("{}: {err}", vector.name));
            assert_eq!(
                recovered.senders(),
                [H160(vector.sender)],
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn a_block_of_several_transactions_recovers_every_sender() {
        let all = vectors();
        let transactions: Vec<_> = all
            .iter()
            .map(|vector| SignedTransaction::decode_2718(vector.raw).unwrap())
            .collect();
        let keys: Vec<_> = all
            .iter()
            .map(|vector| UncompressedPublicKey(vector.public_key))
            .collect();
        let expected: Vec<_> = all.iter().map(|vector| H160(vector.sender)).collect();

        let recovered = recover_block_with_public_keys(block_of(transactions), &keys).unwrap();
        assert_eq!(recovered.senders(), expected);
        // Senders line up with their transactions, in order.
        for ((sender, transaction), vector) in recovered.transactions_with_senders().zip(&all) {
            assert_eq!(*sender, H160(vector.sender), "{}", vector.name);
            assert_eq!(
                transaction.encode_2718().unwrap(),
                vector.raw.to_vec(),
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn an_empty_block_needs_no_keys() {
        let recovered = recover_block_with_public_keys(block_of(Vec::new()), &[]).unwrap();
        assert!(recovered.senders().is_empty());
    }

    #[test]
    fn the_key_count_must_match_the_transaction_count() {
        let transaction = SignedTransaction::decode_2718(vectors()[0].raw).unwrap();
        let error = recover_block_with_public_keys(block_of(vec![transaction]), &[]).unwrap_err();
        assert_eq!(
            error,
            SenderRecoveryError::KeyCountMismatch {
                keys: 0,
                transactions: 1
            }
        );
    }

    #[test]
    fn a_key_that_did_not_sign_is_rejected() {
        // Verification, not recovery: the wrong key cannot yield a sender, it fails outright.
        let vector = &vectors()[2];
        let transaction = SignedTransaction::decode_2718(vector.raw).unwrap();
        let other_key = UncompressedPublicKey(vectors()[3].public_key);
        let error =
            recover_block_with_public_keys(block_of(vec![transaction]), &[other_key]).unwrap_err();
        assert_eq!(error, SenderRecoveryError::VerificationFailed { index: 0 });
    }

    #[test]
    fn keys_in_the_wrong_order_are_rejected() {
        let all = vectors();
        let transactions: Vec<_> = all[..2]
            .iter()
            .map(|vector| SignedTransaction::decode_2718(vector.raw).unwrap())
            .collect();
        // Swapped: each key belongs to the other transaction.
        let keys = [
            UncompressedPublicKey(all[1].public_key),
            UncompressedPublicKey(all[0].public_key),
        ];
        let error = recover_block_with_public_keys(block_of(transactions), &keys).unwrap_err();
        assert_eq!(error, SenderRecoveryError::VerificationFailed { index: 0 });
    }

    #[test]
    fn a_non_normalized_s_is_rejected_before_verification() {
        // secp256k1n - s is an equally valid signature over the same message; EIP-2 forbids it, and
        // it must be rejected even though `verify` itself would accept it.
        let vector = &vectors()[2];
        let mut transaction = SignedTransaction::decode_2718(vector.raw).unwrap();
        let order = U256::from_big_endian(&hex!(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        ));
        transaction.signature.s = order - transaction.signature.s;
        transaction.signature.y_parity = !transaction.signature.y_parity;
        let keys = [UncompressedPublicKey(vector.public_key)];
        let error = recover_block_with_public_keys(block_of(vec![transaction]), &keys).unwrap_err();
        assert_eq!(
            error,
            SenderRecoveryError::SignatureSNotNormalized { index: 0 }
        );
    }

    #[test]
    fn a_key_without_the_uncompressed_tag_is_rejected() {
        let vector = &vectors()[2];
        let transaction = SignedTransaction::decode_2718(vector.raw).unwrap();
        let mut malformed = vector.public_key;
        malformed[0] = 0x02; // a compressed-key tag
        let error = recover_block_with_public_keys(
            block_of(vec![transaction]),
            &[UncompressedPublicKey(malformed)],
        )
        .unwrap_err();
        assert_eq!(error, SenderRecoveryError::InvalidPublicKey { index: 0 });
    }

    #[test]
    fn the_recovered_block_keeps_its_body() {
        let vector = &vectors()[2];
        let transaction = SignedTransaction::decode_2718(vector.raw).unwrap();
        let keys = [UncompressedPublicKey(vector.public_key)];
        let recovered = recover_block_with_public_keys(block_of(vec![transaction]), &keys).unwrap();
        assert_eq!(recovered.transactions().len(), 1);
        assert_eq!(recovered.number, 1);
        // The hash is the header's, computed lazily on first use.
        assert_eq!(recovered.hash(), recovered.header().hash_slow());
    }
}
