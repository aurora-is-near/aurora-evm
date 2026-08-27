//! Recovering each transaction's sender from its signature.
//!
//! [`recover_block`] derives the public key selected by the signature's parity and converts it to an
//! address. [`recover_block_with_public_keys`] additionally compares that recovered key with an
//! untrusted caller-supplied key; a mismatch can only reject the block.
//!
//! Recovery is required rather than verification against the supplied key because two candidate
//! keys can verify the same `(hash, r, s)`. Selecting the supplied key would let the caller choose the
//! sender without changing the transaction bytes. Each transaction also enforces the low-`s` rule
//! from [EIP-2] before recovery.
//!
//! [EIP-2]: https://eips.ethereum.org/EIPS/eip-2

use crate::block::Block;
use crate::block::recovered::RecoveredBlock;
use crate::crypto::keccak256;
use crate::transaction::SignedTxEnvelope;
use core::fmt;
use core::ops::Deref;
use primitive_types::H160;

/// Length of an uncompressed SEC1 public key: the `0x04` tag followed by the two coordinates.
const UNCOMPRESSED_PUBLIC_KEY_LEN: usize = 65;

/// The SEC1 tag that introduces an uncompressed public key.
const UNCOMPRESSED_TAG: u8 = 0x04;

/// Bytes in the uncompressed SEC1 form `0x04 || x || y`.
///
/// Construction does not validate that `(x, y)` is a secp256k1 point. The recovery APIs remain safe:
/// they compare supplied bytes with the canonical point recovered by `libsecp256k1` before deriving
/// the sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UncompressedPublicKey(pub [u8; UNCOMPRESSED_PUBLIC_KEY_LEN]);

impl Deref for UncompressedPublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl UncompressedPublicKey {
    /// The account address this key controls: the low 20 bytes of `keccak256(x || y)`.
    ///
    /// This checks the `0x04` tag, but not whether `(x, y)` lies on secp256k1. Use the block recovery
    /// APIs when the key must be authenticated as a transaction signer.
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

/// Establishes the sender of every transaction in `block` and returns the block paired with those
/// senders.
///
/// # Errors
/// [`SenderRecoveryError`] if any transaction fails the EIP-2 `s` check or
/// carries a signature no public key can be recovered from.
pub fn recover_block(block: Block) -> Result<RecoveredBlock, SenderRecoveryError> {
    // One RLP buffer for the whole block, reused for every transaction's signing encoding.
    let mut stream = rlp::RlpStream::new();
    let senders = block
        .transactions()
        .iter()
        .enumerate()
        .map(|(index, transaction)| {
            recover_public_key(transaction, index, &mut stream)?.address(index)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(pair_with_senders(block, senders))
}

/// Establishes the sender of every transaction in `block`, additionally requiring each to be the
/// account the matching supplied public key controls, and returns the block paired with those
/// senders.
///
/// The keys must be given in transaction order, one per transaction. They are a hint, not an input
/// to the result: the sender is recovered from the transaction either way, and a key that does not
/// match the recovered one can only get the block rejected.
///
/// # Errors
/// [`SenderRecoveryError`] if the key count does not match the transaction count, or if any
/// transaction fails the EIP-2 `s` check, carries a signature no public key can
/// be recovered from, or was not signed by the key supplied for it.
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

    // One RLP stream for the whole block: every transaction is encoded for signing and hashed
    // in the same backing storage, whose capacity is retained between transactions.
    let mut stream = rlp::RlpStream::new();
    let senders = public_keys
        .iter()
        .zip(transactions)
        .enumerate()
        .map(|(index, (key, transaction))| {
            recover_and_check_sender(key, transaction, index, &mut stream)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(pair_with_senders(block, senders))
}

/// Pairs a block with the senders just established for it.
///
/// `senders` was built by mapping over `transactions`, so there is exactly one per transaction and
/// the count check would be redundant; the lazy hash keeps callers that never ask for it from paying
/// for it.
fn pair_with_senders(block: Block, senders: Vec<H160>) -> RecoveredBlock {
    RecoveredBlock::new_unhashed_unchecked(block, senders)
}

/// The public key `ecrecover` yields for one transaction's signature.
///
/// Deliberately takes no candidate key: the recovered key — and therefore the sender — is a function
/// of the transaction's signature hash, `r`, `s` and `y_parity` alone, all of which are inside the
/// bytes the block hash commits to, so no caller-supplied value can steer it.
fn recover_public_key(
    transaction: &SignedTxEnvelope,
    index: usize,
    rlp_stream: &mut rlp::RlpStream,
) -> Result<UncompressedPublicKey, SenderRecoveryError> {
    // EIP-2 first: `(r, n - s)` at the opposite parity recovers the *same* key, so recovery alone
    // would accept a malleable signature and yield the same sender under a different hash.
    if !transaction.signature().is_s_normalized() {
        return Err(SenderRecoveryError::SignatureSNotNormalized { index });
    }

    let message = libsecp256k1::Message::parse(&transaction.signature_hash_in(rlp_stream).0);
    let signature =
        libsecp256k1::Signature::parse_standard_slice(&transaction.signature().rs_bytes())
            .map_err(|_| SenderRecoveryError::InvalidSignature { index })?;
    // `parse` accepts `0..=3`; `y_parity` is a `bool`, so the `r + n` wraparound that ids `2` and
    // `3` denote — which `verify` tolerates but `ecrecover` forbids — is unrepresentable here.
    let recovery_id = libsecp256k1::RecoveryId::parse(u8::from(transaction.signature().y_parity))
        .map_err(|_| SenderRecoveryError::InvalidSignature { index })?;
    let key = libsecp256k1::recover(&message, &signature, &recovery_id)
        .map_err(|_| SenderRecoveryError::InvalidSignature { index })?;
    // `serialize` normalizes the point and writes the `0x04` tag, so these 65 bytes are canonical
    // and comparable with a supplied key however that one was produced.
    Ok(UncompressedPublicKey(key.serialize()))
}

/// Recovers one transaction's signer, requires it to be `pub_key`, and returns its address.
fn recover_and_check_sender(
    pub_key: &UncompressedPublicKey,
    transaction: &SignedTxEnvelope,
    index: usize,
    rlp_stream: &mut rlp::RlpStream,
) -> Result<H160, SenderRecoveryError> {
    // The supplied key's own tag is checked first, so a malformed hint stays distinguishable from a
    // merely mismatching one.
    pub_key.address(index)?;
    let recovered = recover_public_key(transaction, index, rlp_stream)?;
    if recovered != *pub_key {
        return Err(SenderRecoveryError::VerificationFailed { index });
    }
    // The address of the *recovered* key: the supplied one decides only whether an address is
    // returned, never which one.
    recovered.address(index)
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
    /// The supplied bytes do not carry the required `0x04` uncompressed SEC1 tag.
    InvalidPublicKey {
        /// Index of the offending transaction.
        index: usize,
    },
    /// The signature's `r` or `s` is out of range, or `r` is not the x coordinate of a curve point
    /// at the signature's parity, so recovery yields no public key.
    InvalidSignature {
        /// Index of the offending transaction.
        index: usize,
    },
    /// The key recovery yields is not the key that was supplied.
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
            Self::InvalidPublicKey { index } => {
                write!(f, "public key for transaction {index} is not a valid point")
            }
            Self::InvalidSignature { index } => {
                write!(f, "signature of transaction {index} yields no public key")
            }
            Self::VerificationFailed { index } => write!(
                f,
                "signature of transaction {index} does not match the supplied public key"
            ),
        }
    }
}

impl core::error::Error for SenderRecoveryError {}

#[cfg(test)]
mod tests {
    use super::{
        SenderRecoveryError, UncompressedPublicKey, recover_block, recover_block_with_public_keys,
    };
    use crate::block::{Block, BlockBody, Header};
    use crate::transaction::SignedTxEnvelope;
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
        /// The *other* key `libsecp256k1::verify` accepts for this exact `(hash, r, s)`.
        ///
        /// `verify` compares only the x coordinate of the recomputed point, so the two keys that
        /// share one signature both pass it; only recovery at `y_parity` picks one of them.
        alt_public_key: [u8; 65],
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
                alt_public_key: hex!(
                    "041d80ec1b693b251e8ca8f4849c93d44e789f6bd878eb1ab0f36ed0f0dae414c23a39ab802ac054d04c114edb0e8d4991ed0447f147438b92a9c6c6e06633fdbc"
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
                alt_public_key: hex!(
                    "0402bf937650fbea90248aa737681c40cb3abcf87375149c45393434e139800e0c10a0593dc5eb961d0e62927a48681819e1233d0b05b4043e220ec74fcc8243cf"
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
                alt_public_key: hex!(
                    "04c624070728532cf7bddbdbe284a8483036ed3e985ff12389aa5ce5dd2f80e3b224affb7f746ba6445bf4f7d69659ffbdf0c00e8a03d003b22c719a2d7a7f5744"
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
                alt_public_key: hex!(
                    "045913baa87ad6b69d6aae943fe276caff7bec2f8de6c63eba81ca9aeb81864301ad21a293375fb47c44b0a47bbc827ae79b8cc0e515095df798233c591ff8fb2b"
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
                alt_public_key: hex!(
                    "049436df6cf3b8b73e65b44315bbff4fd81d65b8801f87bb2321cf4a6f2b8b2bdf9714feb1b583ebac45d3b30478a5ab7de8ae82bff2dc5f63f75ac560d843e839"
                ),
                sender: hex!("d7d82ecec412de189ae2257aa14437edf77bf89a"),
            },
        ]
    }

    fn block_of(transactions: Vec<SignedTxEnvelope>) -> Block {
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
            let transaction = SignedTxEnvelope::decode_2718(vector.raw).unwrap();
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
            .map(|vector| SignedTxEnvelope::decode_2718(vector.raw).unwrap())
            .collect();
        let keys: Vec<_> = all
            .iter()
            .map(|vector| UncompressedPublicKey(vector.public_key))
            .collect();
        let expected: Vec<_> = all.iter().map(|vector| H160(vector.sender)).collect();

        let recovered = recover_block_with_public_keys(block_of(transactions), &keys).unwrap();
        assert_eq!(recovered.senders(), expected);
        // Senders line up with their transactions, in order — asked of the pairing where it is spent,
        // because that is the only place the two lists are read against each other.
        for (tx_env, vector) in recovered.into_tx_envs().unwrap().iter().zip(&all) {
            assert_eq!(tx_env.caller, H160(vector.sender), "{}", vector.name);
        }
    }

    #[test]
    fn an_empty_block_needs_no_keys() {
        let recovered = recover_block_with_public_keys(block_of(Vec::new()), &[]).unwrap();
        assert!(recovered.senders().is_empty());
    }

    #[test]
    fn the_key_count_must_match_the_transaction_count() {
        let transaction = SignedTxEnvelope::decode_2718(vectors()[0].raw).unwrap();
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
        let transaction = SignedTxEnvelope::decode_2718(vector.raw).unwrap();
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
            .map(|vector| SignedTxEnvelope::decode_2718(vector.raw).unwrap())
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
        let mut transaction = SignedTxEnvelope::decode_2718(vector.raw).unwrap();
        let order = U256::from_big_endian(&hex!(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        ));
        transaction.signature_mut().s = order - transaction.signature().s;
        transaction.signature_mut().y_parity = !transaction.signature().y_parity;
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
        let transaction = SignedTxEnvelope::decode_2718(vector.raw).unwrap();
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
        let transaction = SignedTxEnvelope::decode_2718(vector.raw).unwrap();
        let keys = [UncompressedPublicKey(vector.public_key)];
        let recovered = recover_block_with_public_keys(block_of(vec![transaction]), &keys).unwrap();
        assert_eq!(recovered.transactions().len(), 1);
        assert_eq!(recovered.number, 1);
        // The hash is the header's, computed lazily on first use.
        assert_eq!(recovered.hash(), recovered.header().hash_slow());
    }
    #[test]
    fn the_other_candidate_key_for_the_same_signature_is_rejected() {
        // The hash-preserving attack: the block's bytes are untouched, only the *hint* changes.
        // `libsecp256k1::verify` accepts both keys, so the old code let the caller pick the sender.
        for vector in vectors() {
            let transaction = SignedTxEnvelope::decode_2718(vector.raw).unwrap();
            assert_eq!(
                transaction.encoded_2718(),
                vector.raw.to_vec(),
                "{}: the transaction bytes, and therefore the block hash, are unchanged",
                vector.name
            );
            let keys = [UncompressedPublicKey(vector.alt_public_key)];
            let error =
                recover_block_with_public_keys(block_of(vec![transaction]), &keys).unwrap_err();
            assert_eq!(
                error,
                SenderRecoveryError::VerificationFailed { index: 0 },
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn the_two_candidate_keys_name_different_senders() {
        // Keeps the test above non-vacuous: the choice the old code left open was a real one.
        for vector in vectors() {
            let genuine = UncompressedPublicKey(vector.public_key).address(0).unwrap();
            let alternate = UncompressedPublicKey(vector.alt_public_key)
                .address(0)
                .unwrap();
            assert_eq!(genuine, H160(vector.sender), "{}", vector.name);
            assert_ne!(genuine, alternate, "{}", vector.name);
        }
    }

    #[test]
    fn flipping_y_parity_is_rejected() {
        // `y_parity` is not part of the signature hash, which is why verification could not see this
        // change; recovery can, because the parity is what selects the point.
        for vector in vectors() {
            let mut transaction = SignedTxEnvelope::decode_2718(vector.raw).unwrap();
            let before = transaction.signature_hash();
            transaction.signature_mut().y_parity = !transaction.signature().y_parity;
            assert_eq!(
                transaction.signature_hash(),
                before,
                "{}: the signature hash does not cover `y_parity`",
                vector.name
            );
            let keys = [UncompressedPublicKey(vector.public_key)];
            let error =
                recover_block_with_public_keys(block_of(vec![transaction]), &keys).unwrap_err();
            assert_eq!(
                error,
                SenderRecoveryError::VerificationFailed { index: 0 },
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn an_off_curve_key_with_the_uncompressed_tag_is_rejected() {
        // Reported as a mismatch rather than as an invalid key: an off-curve point can never equal
        // the on-curve key recovery yields, so the outcome is the same rejection.
        let vector = &vectors()[2];
        let transaction = SignedTxEnvelope::decode_2718(vector.raw).unwrap();
        let mut off_curve = vector.public_key;
        off_curve[64] ^= 1;
        let error = recover_block_with_public_keys(
            block_of(vec![transaction]),
            &[UncompressedPublicKey(off_curve)],
        )
        .unwrap_err();
        assert_eq!(error, SenderRecoveryError::VerificationFailed { index: 0 });
    }

    #[test]
    fn recovery_needs_no_public_keys() {
        // The sender is a function of the transaction alone; the keys are a checked hint.
        for vector in vectors() {
            let transaction = SignedTxEnvelope::decode_2718(vector.raw).unwrap();
            let recovered = recover_block(block_of(vec![transaction]))
                .unwrap_or_else(|err| panic!("{}: {err}", vector.name));
            assert_eq!(
                recovered.senders(),
                [H160(vector.sender)],
                "{}",
                vector.name
            );
        }
    }
}
