//! The RLP codec for [`Block`] and [`BlockBody`] — the block's byte layout, in one place.
//!
//! # The canonical shape
//!
//! A block is **not** `[header, body]`: the body's items are flattened into the block's own list,
//! so a block is
//!
//! ```text
//! [header, transactions, ommers, withdrawals?]
//! ```
//!
//! and a standalone body is the same list without the header:
//!
//! ```text
//! [transactions, ommers, withdrawals?]
//! ```
//!
//! `withdrawals` is *trailing-optional*: present from Shanghai on, absent before it, and never
//! encoded as a placeholder. Absent and empty are therefore different encodings — `None` and
//! `Some(vec![])` must survive a round trip, or `withdrawals_root` would be derived from the
//! wrong pre-image.
//!
//! `ommers` has no counterpart in [`BlockBody`], which does not model ommers at all: this crate
//! executes post-merge blocks, where the list is always empty. The encoder writes the empty list,
//! and the decoder *requires* it — a pre-merge block is rejected rather than silently stripped of
//! its ommers, which would change the block hash.
//!
//! # Transactions are not encoded as they are hashed
//!
//! Inside the transaction list a legacy transaction is a bare RLP list, while a typed one is its
//! EIP-2718 envelope wrapped in an RLP **byte string** — otherwise a `0x02…` envelope would not be
//! a legal item of an RLP list. The bare envelope is what the transactions trie and the
//! transaction hash are built from, so the two forms must not be confused; the distinction lives in
//! [`SignedTxEnvelope::encode_block_item`] and its inverse.
//!
//! # `Encodable` yes, `Decodable` no
//!
//! [`Block`] and [`BlockBody`] implement `rlp::Encodable`, and that is the whole encoder.
//! Encoding a transaction is total: a [`SignedTxEnvelope`] holds exactly
//! the fields its own type has, so there is nothing that can contradict itself and nothing to fail on.
//!
//! Decoding cannot be a trait impl. `rlp::Decodable::decode` may only fail with
//! [`rlp::DecoderError`], whose `Custom(&'static str)` carries a fixed string — it cannot say *which*
//! transaction failed, how many ommers a pre-merge block brought, or by how much a buffer overran.
//! [`BlockDecodeError`] carries all three, so decoding stays a method and the asymmetry with the
//! encode side is deliberate.
//!
//! Two inputs are refused that a lenient decoder would let through: a legacy transaction carrying an
//! explicit `0x00` type byte, and a legacy transaction wrapped in an RLP byte string as though it were
//! typed. Both are alternative encodings of a block that already has a canonical one, and admitting
//! either would mean the same block has two encodings — which is what the strict decoding here exists
//! to prevent.
//!
//! The EIP-4844 *network* form, carrying blobs, commitments and proofs, is not modelled at all. It exists
//! for transaction gossip; a block carries only versioned hashes, so a validator never sees one.

use crate::block::{Block, BlockBody, Header};
use crate::rlp_strict;
use crate::transaction::{SignedTxEnvelope, TxDecodeError};
use crate::withdrawal::Withdrawal;
use core::cmp::Ordering;
use core::fmt;

const BODY_ITEM_COUNT_WITHOUT_WITHDRAWALS: usize = 2;
const BLOCK_ITEM_COUNT_WITHOUT_WITHDRAWALS: usize = BODY_ITEM_COUNT_WITHOUT_WITHDRAWALS + 1;

/// Number of items a body contributes to a list: two, plus `withdrawals` when present.
const fn body_item_count(body: &BlockBody) -> usize {
    if body.withdrawals.is_some() {
        BODY_ITEM_COUNT_WITHOUT_WITHDRAWALS + 1
    } else {
        BODY_ITEM_COUNT_WITHOUT_WITHDRAWALS
    }
}

/// Appends a body's items — transactions, the empty ommers list, and `withdrawals` when present —
/// to a list the caller has already opened.
fn append_body_items(body: &BlockBody, stream: &mut rlp::RlpStream) {
    stream.begin_list(body.transactions.len());
    // One lazily-created scratch buffer for all typed transactions. Empty and legacy-only lists never
    // allocate it; after the first typed transaction its capacity is retained for every following one.
    let mut tx_rlp_stream = None;
    for transaction in &body.transactions {
        transaction.append_block_item(stream, &mut tx_rlp_stream);
    }
    // Ommers: always empty, and the decoder requires it (see the module docs).
    stream.begin_list(0);
    if let Some(withdrawals) = &body.withdrawals {
        stream.append_list(withdrawals);
    }
}

/// Reads a body's items from `rlp` starting at `offset`.
fn decode_body_items(
    rlp: &rlp::Rlp<'_>,
    offset: usize,
    has_withdrawals: bool,
) -> Result<BlockBody, BlockDecodeError> {
    let list = rlp.at(offset)?;
    rlp_strict::checked_len(&list)?;
    // Validate up front, but do not preallocate from an untrusted RLP item count (with `Vec::with_capacity`).
    let mut transactions = Vec::new();
    for (index, item) in list.iter().enumerate() {
        transactions.push(
            SignedTxEnvelope::decode_block_item(&item)
                .map_err(|source| BlockDecodeError::Transaction { index, source })?,
        );
    }

    let ommers = rlp_strict::checked_len(&rlp.at(offset + 1)?)?;
    if ommers != 0 {
        return Err(BlockDecodeError::OmmersNotSupported { count: ommers });
    }

    let withdrawals = if has_withdrawals {
        Some(rlp_strict::checked_list_at::<Withdrawal>(rlp, offset + 2)?)
    } else {
        None
    };

    Ok(BlockBody::new(transactions, withdrawals))
}

/// Whether a block list of `count` items carries trailing withdrawals.
const fn has_withdrawals(count: usize) -> Result<bool, BlockDecodeError> {
    if count == BLOCK_ITEM_COUNT_WITHOUT_WITHDRAWALS {
        Ok(false)
    } else if count == BLOCK_ITEM_COUNT_WITHOUT_WITHDRAWALS + 1 {
        Ok(true)
    } else {
        Err(BlockDecodeError::Rlp(
            rlp::DecoderError::RlpIncorrectListLen,
        ))
    }
}

impl rlp::Encodable for BlockBody {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(body_item_count(self));
        append_body_items(self, stream);
    }
}

impl rlp::Encodable for Block {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(body_item_count(&self.body) + 1);
        stream.append(&self.header);
        append_body_items(&self.body, stream);
    }
}

impl Block {
    /// Decodes a block from the start of `bytes`, **ignoring anything after it**.
    ///
    /// Crate-internal, because that leniency is the hazard the strict path exists to remove: a block
    /// decoded this way can re-encode to different bytes than it arrived as. [`Self::decode_exact`] is
    /// the public form, and it is this one plus the check that the block covers its buffer.
    ///
    /// ## Errors
    /// [`BlockDecodeError`] if the list has the wrong length, the header or a transaction does not
    /// decode, or the ommers list is not empty.
    pub(crate) fn decode_rlp(bytes: &[u8]) -> Result<Self, BlockDecodeError> {
        let rlp = rlp::Rlp::new(bytes);
        let withdrawals = has_withdrawals(rlp_strict::checked_len(&rlp)?)?;
        let header: Header = rlp.val_at(0)?;
        let body = decode_body_items(&rlp, 1, withdrawals)?;
        Ok(Self::new(header, body))
    }

    /// Decodes a block that must occupy `bytes` **entirely**.
    ///
    /// The only way in from bytes, and strict on purpose: RLP is self-delimiting, so a lenient
    /// decoder would silently drop whatever follows the block and then re-encode to something the
    /// input never was.
    ///
    /// ## Errors
    /// [`BlockDecodeError::TrailingBytes`] if `bytes` holds more than the block;
    /// [`rlp::DecoderError::RlpIsTooShort`] if the block declares a payload `bytes` does not hold —
    /// the opposite fault, and named as such rather than folded into `TrailingBytes`;
    /// [`rlp::DecoderError::RlpInvalidLength`] if the declared length overflows a `usize`; and
    /// otherwise [`BlockDecodeError`] for a list of the wrong length, a header or transaction that
    /// does not decode, or a non-empty ommers list.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, BlockDecodeError> {
        let consumed = rlp_strict::declared_item_len(bytes)?;
        match consumed.cmp(&bytes.len()) {
            // The block declares a payload the buffer does not hold: too few bytes, not too many.
            Ordering::Greater => return Err(rlp::DecoderError::RlpIsTooShort.into()),
            // The buffer holds bytes past the end of the block.
            Ordering::Less => {
                return Err(BlockDecodeError::TrailingBytes {
                    consumed,
                    total: bytes.len(),
                });
            }
            Ordering::Equal => {}
        }
        Self::decode_rlp(bytes)
    }
}

/// Why a block or a block body could not be decoded from its RLP form.
#[derive(Debug)]
pub enum BlockDecodeError {
    /// The bytes are not well-formed RLP, or not the shape a block or body must have.
    Rlp(rlp::DecoderError),
    /// The transaction at `index` in the body's transaction list could not be decoded.
    Transaction {
        /// Position of the transaction in the body.
        index: usize,
        /// What was wrong with it.
        source: TxDecodeError,
    },
    /// The ommers list is not empty, so the block is pre-merge — which this crate does not execute.
    OmmersNotSupported {
        /// How many ommers the block carries.
        count: usize,
    },
    /// The buffer holds more than the one block that was decoded from its start.
    ///
    /// Only this direction: a block declaring *more* than the buffer holds is
    /// [`rlp::DecoderError::RlpIsTooShort`], so `consumed` is always below `total` here.
    TrailingBytes {
        /// Bytes the block itself occupies.
        consumed: usize,
        /// Bytes the buffer holds.
        total: usize,
    },
}

impl From<rlp::DecoderError> for BlockDecodeError {
    fn from(error: rlp::DecoderError) -> Self {
        Self::Rlp(error)
    }
}

impl fmt::Display for BlockDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rlp(error) => write!(f, "malformed block RLP: {error}"),
            Self::Transaction { index, source } => {
                write!(f, "transaction at index {index} is invalid: {source}")
            }
            Self::OmmersNotSupported { count } => write!(
                f,
                "block carries {count} ommer(s); only post-merge blocks are supported"
            ),
            Self::TrailingBytes { consumed, total } => write!(
                f,
                "block occupies {consumed} of {total} bytes, leaving {} trailing",
                total.saturating_sub(*consumed)
            ),
        }
    }
}

impl core::error::Error for BlockDecodeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Rlp(error) => Some(error),
            Self::Transaction { source, .. } => Some(source),
            Self::OmmersNotSupported { .. } | Self::TrailingBytes { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Block, BlockBody, BlockDecodeError, decode_body_items};
    use crate::rlp_strict;
    use crate::transaction::{SignedTxEnvelope, TxType};
    use crate::withdrawal::Withdrawal;
    use hex_literal::hex;
    use primitive_types::{H160, H256};

    /// Test-only helper for whether `count` items carry trailing withdrawals, given the count without.
    const fn has_withdrawals(count: usize, expected: usize) -> Result<bool, BlockDecodeError> {
        if count == expected {
            Ok(false)
        } else if count == expected + 1 {
            Ok(true)
        } else {
            Err(BlockDecodeError::Rlp(
                rlp::DecoderError::RlpIncorrectListLen,
            ))
        }
    }

    /// Test-only inverse of `BlockBody::rlp_append`; bytes after the first body item are ignored.
    fn decode_body_rlp_allowing_trailing_bytes(
        bytes: &[u8],
    ) -> Result<BlockBody, BlockDecodeError> {
        let rlp = rlp::Rlp::new(bytes);
        let withdrawals = has_withdrawals(rlp_strict::checked_len(&rlp)?, 2)?;
        decode_body_items(&rlp, 0, withdrawals)
    }

    /// A real block from the Ethereum execution-spec fixtures: its `rlp` field, the `blockHeader.hash`
    /// it must reproduce, and the body shape it must decode to.
    ///
    /// Between them the four vectors cover every branch of the codec: an empty body, a body mixing
    /// a legacy transaction with a typed (string-wrapped) one, a pre-Shanghai block whose
    /// `withdrawals` item is *absent*, and a block carrying an actual withdrawal.
    pub(super) struct Vector {
        name: &'static str,
        pub(super) rlp: &'static [u8],
        hash: [u8; 32],
        tx_types: &'static [TxType],
        withdrawals: Option<usize>,
    }

    pub(super) fn vectors() -> Vec<Vector> {
        vec![
            Vector {
                name: "Prague, empty body (eip7251_consolidations)",
                rlp: &hex!(
                    "f9025df90257a026cffefa95103a16b364b48edb6691de31922de6ff72d247fc6c999a2092e619a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa0ecf8f514461676ba71cbdff24a494804f9de02bd6f8e901503e526267447f004a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080028407270e00800280a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a08668bfe78b1cd122263f0b6c4ba13bcf1ae9a14524630fd41e19bef4c9b31f19c0c0c0"
                ),
                hash: hex!("e359e707caf12c4e0ef2c7cf55f318dacf56bce5348139d61b7381ccec90b0dc"),
                tx_types: &[],
                withdrawals: Some(0),
            },
            Vector {
                name: "Prague, legacy + EIP-7702 (eip7702_set_code_tx)",
                rlp: &hex!(
                    "f90389f9025aa0c58435c699d56b4cbf23b35e87eb8c302c415edc8a81b26279dbf5c69d8b9196a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa04712ec4ffb9c0cf156ffc4e3e1955050adca08b8239d56c3135d5247b2a835aaa0fee824f56752bb64c187277c55cfaedde287310e8ddd7af812221884245bbef9a0db89ad4f7ff93499b0a2590cb4eaef47cd0fbe6a7c02392cc5f3bf17e03edab9b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e00830105b80c80a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855f90127f85f800a8252089457a6154dc3d6111f3977629f8014b1dd1ba5387e018026a04eaa379ee08e2c6a7feb6c046d8a65af8e93c078c8e76481024f34662c705afea064e1a25a80a7e4fec459225217bfb0ab8205461d75e683db86b31ec9d3a608ccb8c404f8c1018080078307a1209457a6154dc3d6111f3977629f8014b1dd1ba5387e8080c0f85cf85a809400000000000000000000000000000000000000018080a0f4b418acc0844ea7065590653ce3bf8a40be1aeddbf2803d942837452a322fdda0519fd981273c530175386b9c6007074484f85be751a2ba003fc3676e4719fa1480a0f0d5656bf92ac12c6d8a4c726868f3a04e2b47864c577c3b2770fb36524db036a0413df564a6d0828edcb599b9fb1e6698b9c57049ffe98227adbf09fe4c3bba20c0c0"
                ),
                hash: hex!("5359a601b44a9ea3a024ccfa182a966ce1e119e24cb8deb30fcec2386e405cd7"),
                tx_types: &[TxType::Legacy, TxType::Eip7702],
                withdrawals: Some(0),
            },
            Vector {
                name: "Paris, pre-Shanghai — no withdrawals item at all",
                rlp: &hex!(
                    "f90250f901f7a0d975efca4d95caa032a6c36765cadc0df97ef7bfe036eb9645f2227c1580647ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa04bf5b536b80204668fbd51b904aae9ff4ba87a648370dddb026ce9290d8326a7a0f49609a5cf8fad9861dfc5d3ec18899d8ef2dde0ed8683ae5aee5de78fdf38caa0ea5b87d12423d7570eb418dcdbb9f547f8fcc0577bd026d2189fd8fb550b85cfb901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e0083030d408203e800a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007f853f851800a83030d4080808560006000fd26a05898cff8b1d72c0d9fef2a838dc271f3c976f9f217ba78006acf3e2751d3b0c8a014883eb435e1782c62e6f190ca3448164fe56e100b8294a5c6a261489ca1fd4ec0"
                ),
                hash: hex!("db55235740825afbebc5a0d8774a70418df30a377ebbb66ffd2dbfa7fbdd1032"),
                tx_types: &[TxType::Legacy],
                withdrawals: None,
            },
            Vector {
                name: "Shanghai, one withdrawal (eip4895_withdrawals)",
                rlp: &hex!(
                    "f90232f90213a02f9639757d1650c9fa1903da83a0c80ff6a0e490d6eb7b74c209295e69b8566da01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa07c37918e3f6db1995d488cfb4cf2b608726ac9f181568128a42120b608e1e243a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e00800c80a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a00bdc1d9181528e8631acb4c64834ccfb089abd95a84c8a12c78f40cca40c8b2ac0c0d9d8808094c62652e73a4cfef1bc27dff4556a047a246c34c801"
                ),
                hash: hex!("19e575e028bc63fb1951fc644ebb7fe98bdd1f52fb0b2e120efbd905ac17552c"),
                tx_types: &[],
                withdrawals: Some(1),
            },
        ]
    }

    /// The strongest check available: every vector must decode, reproduce the fixture's own block
    /// hash, and re-encode to the very bytes it came from.
    #[test]
    fn real_blocks_decode_reencode_and_hash() {
        for vector in vectors() {
            let block = Block::decode_exact(vector.rlp).unwrap_or_else(|error| {
                panic!("{} failed to decode: {error}", vector.name);
            });

            assert_eq!(
                block.header.hash_slow(),
                H256::from(vector.hash),
                "{} block hash",
                vector.name
            );
            assert_eq!(
                rlp::encode(&block).to_vec(),
                vector.rlp,
                "{} must re-encode byte-identically",
                vector.name
            );

            let types: Vec<TxType> = block
                .transactions()
                .iter()
                .map(SignedTxEnvelope::tx_type)
                .collect();
            assert_eq!(types, vector.tx_types, "{} transaction types", vector.name);
            assert_eq!(
                block.body.withdrawals().map(<[Withdrawal]>::len),
                vector.withdrawals,
                "{} withdrawals",
                vector.name
            );
        }
    }

    /// The body's items are flattened into the block's list, not nested under one: a block's payload
    /// is therefore the header item followed by exactly the payload of the standalone body encoding.
    #[test]
    fn block_encoding_flattens_the_body() {
        for vector in vectors() {
            let block = Block::decode_exact(vector.rlp).unwrap();
            let body = rlp::encode(&block.body).to_vec();

            let block_payload_start = rlp::PayloadInfo::from(vector.rlp).unwrap().header_len;
            let body_payload_start = rlp::PayloadInfo::from(&body).unwrap().header_len;
            let header_item_len = rlp::Rlp::new(vector.rlp).at(0).unwrap().as_raw().len();

            assert_eq!(
                &vector.rlp[block_payload_start + header_item_len..],
                &body[body_payload_start..],
                "{} body items must appear verbatim in the block",
                vector.name
            );
        }
    }

    #[test]
    fn body_roundtrips() {
        for vector in vectors() {
            let body = Block::decode_exact(vector.rlp).unwrap().body;
            let encoded = rlp::encode(&body).to_vec();
            assert_eq!(
                decode_body_rlp_allowing_trailing_bytes(&encoded).unwrap(),
                body,
                "{} body",
                vector.name
            );
        }
    }

    /// Absent and empty withdrawals are different encodings — one item shorter, not an empty list —
    /// and must not be conflated, since `withdrawals_root` differs between them.
    #[test]
    fn absent_and_empty_withdrawals_differ() {
        let absent = BlockBody::new(Vec::new(), None);
        let empty = BlockBody::new(Vec::new(), Some(Vec::new()));

        let absent_rlp = rlp::encode(&absent).to_vec();
        let empty_rlp = rlp::encode(&empty).to_vec();
        assert_eq!(absent_rlp, hex!("c2c0c0"));
        assert_eq!(empty_rlp, hex!("c3c0c0c0"));

        assert_eq!(
            decode_body_rlp_allowing_trailing_bytes(&absent_rlp).unwrap(),
            absent
        );
        assert_eq!(
            decode_body_rlp_allowing_trailing_bytes(&empty_rlp).unwrap(),
            empty
        );
    }

    #[test]
    fn decode_exact_rejects_trailing_bytes() {
        let vector = &vectors()[0];
        let mut padded = vector.rlp.to_vec();
        padded.push(0xff);

        assert!(matches!(
            Block::decode_exact(&padded),
            Err(BlockDecodeError::TrailingBytes { .. })
        ));
        // The lenient form stops at the end of the block's own list, by contract.
        assert_eq!(
            Block::decode_rlp(&padded).unwrap(),
            Block::decode_exact(vector.rlp).unwrap()
        );
    }

    /// The two ways a buffer can disagree with the block it declares are opposite faults.
    /// `TrailingBytes` is only ever the one it is named for, so `consumed < total` always holds in it.
    #[test]
    fn decode_exact_names_a_truncated_block_apart_from_a_padded_one() {
        let raw = vectors()[0].rlp;

        let mut padded = raw.to_vec();
        padded.push(0xff);
        match Block::decode_exact(&padded).unwrap_err() {
            BlockDecodeError::TrailingBytes { consumed, total } => {
                assert_eq!(consumed, raw.len());
                assert_eq!(total, padded.len());
                assert!(consumed < total);
            }
            other => panic!("padded: {other}"),
        }

        // The block declares a payload the buffer does not hold: too few bytes, not too many.
        assert!(matches!(
            Block::decode_exact(&raw[..raw.len() - 1]).unwrap_err(),
            BlockDecodeError::Rlp(rlp::DecoderError::RlpIsTooShort)
        ));

        // A declared length that overflows a `usize` is neither, and must not be summed: a header and
        // its length bytes would otherwise wrap or panic before any block was read.
        assert!(matches!(
            Block::decode_exact(&rlp_strict::overflowing_header(true)).unwrap_err(),
            BlockDecodeError::Rlp(rlp::DecoderError::RlpInvalidLength)
        ));
    }

    #[test]
    fn decode_rejects_non_empty_ommers() {
        let block = Block::decode_exact(vectors()[0].rlp).unwrap();

        let mut stream = rlp::RlpStream::new_list(4);
        stream.append(&block.header);
        stream.begin_list(0);
        stream.begin_list(1); // one ommer: a pre-merge block
        stream.append(&block.header);
        stream.begin_list(0);

        assert!(matches!(
            Block::decode_rlp(&stream.out()),
            Err(BlockDecodeError::OmmersNotSupported { count: 1 })
        ));
    }

    #[test]
    fn decode_rejects_ommers_that_are_not_a_list() {
        let block = Block::decode_exact(vectors()[0].rlp).unwrap();

        let mut stream = rlp::RlpStream::new_list(4);
        stream.append(&block.header);
        stream.begin_list(0);
        stream.append(&Vec::<u8>::new()); // a byte string where the ommers list belongs
        stream.begin_list(0);

        assert!(matches!(
            Block::decode_rlp(&stream.out()),
            Err(BlockDecodeError::Rlp(
                rlp::DecoderError::RlpExpectedToBeList
            ))
        ));
    }

    #[test]
    fn decode_rejects_wrong_item_count() {
        let block = Block::decode_exact(vectors()[0].rlp).unwrap();

        for count in [0usize, 1, 2, 5] {
            let mut stream = rlp::RlpStream::new_list(count);
            for index in 0..count {
                if index == 0 {
                    stream.append(&block.header);
                } else {
                    stream.begin_list(0);
                }
            }
            assert!(
                matches!(
                    Block::decode_rlp(&stream.out()),
                    Err(BlockDecodeError::Rlp(
                        rlp::DecoderError::RlpIncorrectListLen
                    ))
                ),
                "a {count}-item list must not decode as a block"
            );
        }

        for count in [0usize, 1, 4] {
            let mut stream = rlp::RlpStream::new_list(count);
            for _ in 0..count {
                stream.begin_list(0);
            }
            assert!(
                matches!(
                    decode_body_rlp_allowing_trailing_bytes(&stream.out()),
                    Err(BlockDecodeError::Rlp(
                        rlp::DecoderError::RlpIncorrectListLen
                    ))
                ),
                "a {count}-item list must not decode as a body"
            );
        }
    }

    /// A transaction failure names the position it happened at, which is what makes an invalid
    /// block diagnosable at all.
    #[test]
    fn transaction_errors_carry_their_index() {
        let good = Block::decode_exact(vectors()[1].rlp)
            .unwrap()
            .body
            .transactions[0]
            .encode_block_item();

        let mut stream = rlp::RlpStream::new_list(3);
        stream.begin_list(2);
        stream.append_raw(&good, 1);
        stream.append(&hex!("05aabb").to_vec()); // unknown transaction type 0x05
        stream.begin_list(0);
        stream.begin_list(0);

        match decode_body_rlp_allowing_trailing_bytes(&stream.out()) {
            Err(BlockDecodeError::Transaction { index, .. }) => assert_eq!(index, 1),
            other => panic!("expected a transaction error at index 1, got {other:?}"),
        }
    }

    #[test]
    fn body_with_withdrawals_roundtrips_through_a_block() {
        let block = Block::decode_exact(vectors()[3].rlp).unwrap();
        assert_eq!(
            block.body.withdrawals(),
            Some(
                &[Withdrawal {
                    index: 0,
                    validator_index: 0,
                    address: H160::from(hex!("c62652e73a4cfef1bc27dff4556a047a246c34c8")),
                    amount: 1,
                }][..]
            )
        );
    }

    #[test]
    fn empty_block_body_encodes_to_three_empty_lists() {
        let block = Block::new(
            Block::decode_exact(vectors()[0].rlp).unwrap().header,
            BlockBody::new(Vec::new(), Some(Vec::new())),
        );
        let encoded = rlp::encode(&block).to_vec();
        assert_eq!(&encoded[encoded.len() - 3..], &[0xc0, 0xc0, 0xc0]);
        assert_eq!(Block::decode_exact(&encoded).unwrap(), block);
    }

    /// Decoding is the inverse of `encode_block_item`, so a transaction list mixing the two forms
    /// survives a round trip through the body with each form preserved.
    #[test]
    fn mixed_transaction_forms_survive_the_body() {
        let block = Block::decode_exact(vectors()[1].rlp).unwrap();
        let transactions: &[SignedTxEnvelope] = block.transactions();
        assert_eq!(transactions.len(), 2);

        let list = rlp::Rlp::new(vectors()[1].rlp).at(1).unwrap();
        assert!(list.at(0).unwrap().is_list(), "legacy stays a bare list");
        assert!(
            list.at(1).unwrap().is_data(),
            "a typed transaction is a byte string"
        );
        assert_eq!(
            list.at(1).unwrap().data().unwrap(),
            transactions[1].encode_2718().as_slice()
        );
    }
    /// A long-string header claiming 65535 bytes with nothing behind it: `payload_info` fails on it,
    /// so `rlp`'s own list walk stops there and silently reports fewer items.
    const POISON: &[u8] = &hex!("b9ffff");

    /// The raw bytes of each item of the RLP list `raw`.
    fn items_of(raw: &[u8]) -> Vec<Vec<u8>> {
        rlp::Rlp::new(raw)
            .iter()
            .map(|item| item.as_raw().to_vec())
            .collect()
    }

    /// An RLP list over `items`, followed by `extra` bytes no item accounts for.
    ///
    /// The list header declares the longer payload, so the item still covers the whole input exactly
    /// and `Block::decode_exact`'s exactness check cannot see the difference — only `checked_len`'s
    /// tiling requirement can.
    fn list_of(items: &[Vec<u8>], extra: &[u8]) -> Vec<u8> {
        let mut payload: Vec<u8> = items.concat();
        payload.extend_from_slice(extra);
        let mut out = Vec::new();
        if payload.len() <= 55 {
            out.push(0xc0 + u8::try_from(payload.len()).unwrap());
        } else {
            let significant: Vec<u8> = payload
                .len()
                .to_be_bytes()
                .into_iter()
                .skip_while(|byte| *byte == 0)
                .collect();
            out.push(0xf7 + u8::try_from(significant.len()).unwrap());
            out.extend_from_slice(&significant);
        }
        out.extend_from_slice(&payload);
        out
    }

    /// `raw` re-tagged as an RLP byte string holding the same payload.
    fn as_byte_string(raw: &[u8]) -> Vec<u8> {
        let header_len = rlp::PayloadInfo::from(raw).unwrap().header_len;
        let end = rlp_strict::declared_item_len(raw).unwrap();
        let mut stream = rlp::RlpStream::new();
        stream.append(&raw[header_len..end].to_vec());
        stream.out().to_vec()
    }

    /// `raw` wrapped verbatim in an RLP byte string.
    fn wrapped(raw: &[u8]) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        stream.append(&raw.to_vec());
        stream.out().to_vec()
    }

    /// Vector `vector`'s block with top-level item `index` replaced by `replacement`.
    fn block_with_item(vector: usize, index: usize, replacement: Vec<u8>) -> Vec<u8> {
        let mut items = items_of(vectors()[vector].rlp);
        items[index] = replacement;
        list_of(&items, &[])
    }

    /// Asserts that `mutated` occupies its bytes exactly and is rejected as malformed RLP.
    fn assert_rejected(label: &str, mutated: &[u8]) {
        // The same call `decode_exact` makes, so the assertion tracks the production check rather
        // than a second opinion about it.
        assert_eq!(
            rlp_strict::declared_item_len(mutated).unwrap(),
            mutated.len(),
            "{label}: the mutation must be invisible to the exactness check"
        );
        let error = Block::decode_exact(mutated)
            .err()
            .unwrap_or_else(|| panic!("{label}: accepted"));
        assert!(
            matches!(
                error,
                BlockDecodeError::Rlp(_) | BlockDecodeError::Transaction { .. }
            ),
            "{label}: {error}"
        );
    }

    #[test]
    fn decode_rejects_a_byte_string_where_a_list_belongs() {
        // `rlp`'s own walk over a byte string yields nothing, so each of these used to decode as an
        // *empty* list while `hash_slow()` still returned the genuine block hash.
        let transactions = items_of(vectors()[1].rlp)[1].clone();
        for (label, item, replacement) in [
            (
                "transactions as a byte string",
                1,
                as_byte_string(&transactions),
            ),
            ("transactions as 0x80", 1, hex!("80").to_vec()),
            ("transactions as 0x83aabbcc", 1, hex!("83aabbcc").to_vec()),
        ] {
            assert_rejected(label, &block_with_item(1, item, replacement));
        }
        // Vector 3 is the one with a real withdrawal.
        let withdrawals = items_of(vectors()[3].rlp)[3].clone();
        for (label, replacement) in [
            ("withdrawals as a byte string", as_byte_string(&withdrawals)),
            ("withdrawals as 0x80", hex!("80").to_vec()),
        ] {
            assert_rejected(label, &block_with_item(3, 3, replacement));
        }
    }

    #[test]
    fn decode_rejects_bytes_that_no_item_accounts_for() {
        let top = items_of(vectors()[1].rlp);
        // An "empty" ommers list hiding three bytes: the `!= 0` count check waves it through.
        assert_rejected(
            "ommers = c3 b9ffff",
            &block_with_item(1, 2, hex!("c3b9ffff").to_vec()),
        );
        // Inside the transactions list.
        assert_rejected(
            "poison after the last transaction",
            &block_with_item(1, 1, list_of(&items_of(&top[1]), POISON)),
        );
        // Inside the header's own list.
        assert_rejected(
            "poison inside the header",
            &block_with_item(1, 0, list_of(&items_of(&top[0]), POISON)),
        );
        // Inside the block's own list payload: this is the contract `decode_exact` documents.
        assert_rejected("poison inside the block's payload", &list_of(&top, POISON));
        // Inside a withdrawal, and after the last withdrawal.
        let with_withdrawals = items_of(vectors()[3].rlp);
        let withdrawals = items_of(&with_withdrawals[3]);
        assert_rejected(
            "poison after the last withdrawal",
            &block_with_item(3, 3, list_of(&withdrawals, POISON)),
        );
        let mut poisoned = withdrawals.clone();
        poisoned[0] = list_of(&items_of(&withdrawals[0]), POISON);
        assert_rejected(
            "poison inside a withdrawal",
            &block_with_item(3, 3, list_of(&poisoned, POISON.get(..0).unwrap())),
        );
    }

    #[test]
    fn decode_rejects_a_legacy_transaction_wrapped_in_a_byte_string() {
        // Vector 1's first transaction is a bare legacy list. Wrapping it decodes to the same
        // transaction, so accepting both forms would give this block two valid encodings.
        let top = items_of(vectors()[1].rlp);
        let mut transactions = items_of(&top[1]);
        transactions[0] = wrapped(&transactions[0]);
        let mutated = block_with_item(1, 1, list_of(&transactions, &[]));
        let error = Block::decode_exact(&mutated).unwrap_err();
        assert!(
            matches!(error, BlockDecodeError::Transaction { index: 0, .. }),
            "{error}"
        );
        assert!(
            format!("{error}").contains("must not be wrapped"),
            "{error}"
        );
    }

    #[test]
    fn decoding_is_injective() {
        // The property the individual cases above are instances of: anything `decode_exact` accepts
        // re-encodes to exactly its input, so one block has exactly one encoding.
        let mut inputs: Vec<Vec<u8>> = vectors().iter().map(|v| v.rlp.to_vec()).collect();
        let top = items_of(vectors()[1].rlp);
        inputs.push(block_with_item(1, 1, hex!("80").to_vec()));
        inputs.push(block_with_item(1, 2, hex!("c3b9ffff").to_vec()));
        inputs.push(list_of(&top, POISON));
        inputs.push(block_with_item(1, 1, list_of(&items_of(&top[1]), POISON)));
        for input in inputs {
            if let Ok(block) = Block::decode_exact(&input) {
                assert_eq!(
                    rlp::encode(&block).to_vec(),
                    input,
                    "an accepted encoding must reproduce itself"
                );
            }
        }
    }
}
