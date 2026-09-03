//! RLP encoding and strict decoding for [`Block`] and [`BlockBody`].
//!
//! The body is flattened into the block rather than nested:
//!
//! ```text
//! block = [header, transactions, ommers, withdrawals?]
//! body  = [transactions, ommers, withdrawals?]
//! ```
//!
//! Withdrawals are trailing-optional, preserving the distinction between absence and an empty list.
//! Only post-merge blocks are supported, so ommers must be empty.
//!
//! A legacy body item is a bare RLP list; a typed transaction is a string-wrapped EIP-2718 envelope.
//! Trie values and transaction hashes use the bare envelope instead.
//!
//! Manually assembled headers should use [`Header::encode_rlp`] to reject optional-tail gaps. The
//! EIP-4844 network wrapper is not a valid block-body transaction item.

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
    /// Decodes one block from the start of `bytes`, ignoring trailing bytes.
    ///
    /// Crate-internal because public byte input must use [`Self::decode_exact`].
    ///
    /// # Errors
    /// [`BlockDecodeError`] if the list has the wrong length, the header or a transaction does not
    /// decode, or the ommers list is not empty.
    pub(crate) fn decode_rlp(bytes: &[u8]) -> Result<Self, BlockDecodeError> {
        let rlp = rlp::Rlp::new(bytes);
        let withdrawals = has_withdrawals(rlp_strict::checked_len(&rlp)?)?;
        let header: Header = rlp.val_at(0)?;
        let body = decode_body_items(&rlp, 1, withdrawals)?;
        Ok(Self::new(header, body))
    }

    /// Decodes exactly one block occupying all of `bytes`.
    ///
    /// # Errors
    /// [`BlockDecodeError::TrailingBytes`] for bytes after the block,
    /// [`rlp::DecoderError::RlpIsTooShort`] for a truncated item, or another [`BlockDecodeError`] for
    /// malformed contents, unsupported ommers or an overflowing declared length.
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
pub(super) mod tests {
    use super::{Block, BlockBody, BlockDecodeError, decode_body_items};
    use crate::rlp_strict;
    use crate::transaction::{SignedTxEnvelope, TxType};
    use crate::trie::ordered_trie_root;
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

    fn encode_block_item(tx: &SignedTxEnvelope) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        let mut scratch = None;
        tx.append_block_item(&mut stream, &mut scratch);
        stream.out().to_vec()
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
    /// Together the vectors cover every transaction type, nested access and authorization lists,
    /// empty and mixed bodies, and both absent and present withdrawals.
    pub(in crate::block) struct Vector {
        name: &'static str,
        pub(in crate::block) rlp: &'static [u8],
        hash: [u8; 32],
        tx_types: &'static [TxType],
        withdrawals: Option<usize>,
    }

    pub(in crate::block) fn vectors() -> Vec<Vector> {
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
                name: "Prague, EIP-2930 with repeated access-list entries",
                rlp: &hex!(
                    "f9033bf9025ca0ca3ae77044b619cb2b299418ce3fd8a207f521d6da65c71e9820c218c885dcf0a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa0f8199b49791a7ad9b3793e70c6ae1c4808d51d7e707329f887bac682b67e06f8a06bc3b7e2af708bffdf8395b47c0a65ac8bed13010b693bd10d458e3726c7cee8a034e69c07529f60bc157d3f9bfe310b8bdcfbaea80dedb9b66cadb01d5c5531e4b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e00830110e48203e800a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855f8d8b8d601f8d301800a8307a120948cdf9cd5727230f7cf60842520379509cfa508258080f870f7948cdf9cd5727230f7cf60842520379509cfa50825e1a00000000000000000000000000000000000000000000000000000000000000000f7948cdf9cd5727230f7cf60842520379509cfa50825e1a0000000000000000000000000000000000000000000000000000000000000000180a0a8d412d7ef346948f2541965a0d16a5cf3e38385f3bfa41ca9e45ff9d2075195a04305f95428e06fc531341fffc20f96e444717c3d3a15e6d4e40d2bcd332cbeacc0c0"
                ),
                hash: hex!("f94ad38f0d7f8ebf9a6acaab5f90df534e6df3d5541b4398dfc7cc980121e1b0"),
                tx_types: &[TxType::Eip2930],
                withdrawals: Some(0),
            },
            Vector {
                name: "Cancun, EIP-4844 + EIP-1559 (blobhash_multiple_txs_in_block)",
                rlp: &hex!(
                    "f9041ff9023ca012b0d4adf590f23c4c014f233f14bad0430b2ddb4e92cd554924eacb0ae15cc6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa05e69418e4413143c6dedb27e54ea2df6ebcf5968861c0e7da9fa3fe0e6fbe371a0d284c6c90a6579f509f6f07dd3263fccf8e84d0a79030a34398160509c1d2089a0f44b62ca500455002c17e676410100f1a6df14862de0691766cb2a9ed3c59dc8b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e008302f8a80c80a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421830c000080a00000000000000000000000000000000000000000000000000000000000000000f901dbb9015003f9014c018080078307a120948fc0e9c3c2239d0fca8631f4e272257cf8af952e80a00000000000000000000000000000000000000000000000000000000000000000c00af8c6a001b8c5b09810b5fc07355d3da42e2c3a3e200c1d9a678491b7e8e256fc50cc4fa0015b4c8cc4f86aa2d2cf9e9ce97fca704a11a6c20f6b1d6c00a6e15f6d60a6dfa001878f80eaf10be1a6f618e6f8c071b10a6c14d9b89a3bf2a3f3cf2db6c5681da0014eb72b108d562c639faeb6f8c6f366a28b0381c7d30431117ec8c7bb89f834a001a9b2a6c3f3f0675b768d49b5f5dc5b5d988f88d55766247ba9e40b125f16bba001a4d4cde4aa01e57fb2c880d1d9c778c33bdf85e48ef4c4d4b4de51abccf4ed80a0ab24aec8d2287e8f5f853cb5fdf8de14fe8b8fe4486940bba3ff466c23b7a4c0a07a105021f4d892469dd5a5fa763fa06f23663c7f29939e8dfb7cd32d0775548eb88602f883010180078307a120948fc0e9c3c2239d0fca8631f4e272257cf8af952e80a00000000000000000000000000000000000000000000000000000000000000000c080a0e4cf8e34c5772818f55502c9e4a730f4569b2227b763eccd61ca83b6a8458e20a0649a45b84c873f851d4425282f9cd85b468c68e2fc9002cc0783727a4da8e7d3c0c0"
                ),
                hash: hex!("1d8d14f7914fdc34c7aa3e37c613d5c51bc9ea804dd88d35a2c3cfc61b42fd7f"),
                tx_types: &[TxType::Eip4844, TxType::Eip1559],
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

    fn vector_named(name: &str) -> Vector {
        vectors()
            .into_iter()
            .find(|vector| vector.name.contains(name))
            .unwrap_or_else(|| panic!("missing block vector matching {name:?}"))
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

            let transactions_root = ordered_trie_root(
                block
                    .transactions()
                    .iter()
                    .map(SignedTxEnvelope::encoded_2718),
            );
            assert_eq!(
                transactions_root, block.header.transactions_root,
                "{} transactions root",
                vector.name
            );

            let withdrawals_root = block.body.withdrawals().map(|withdrawals| {
                ordered_trie_root(withdrawals.iter().map(|item| rlp::encode(item).to_vec()))
            });
            assert_eq!(
                withdrawals_root, block.header.withdrawals_root,
                "{} withdrawals root",
                vector.name
            );
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
        let vector = vector_named("empty body");
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
        let raw = vector_named("empty body").rlp;

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
        let block = Block::decode_exact(vector_named("empty body").rlp).unwrap();

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
        let block = Block::decode_exact(vector_named("empty body").rlp).unwrap();

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
        let block = Block::decode_exact(vector_named("empty body").rlp).unwrap();

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
        let good = encode_block_item(
            &Block::decode_exact(vector_named("legacy + EIP-7702").rlp)
                .unwrap()
                .body
                .transactions[0],
        );

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
        let block = Block::decode_exact(vector_named("one withdrawal").rlp).unwrap();
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
            Block::decode_exact(vector_named("empty body").rlp)
                .unwrap()
                .header,
            BlockBody::new(Vec::new(), Some(Vec::new())),
        );
        let encoded = rlp::encode(&block).to_vec();
        assert_eq!(&encoded[encoded.len() - 3..], &[0xc0, 0xc0, 0xc0]);
        assert_eq!(Block::decode_exact(&encoded).unwrap(), block);
    }

    /// The block encoder and decoder agree on both transaction-item forms, so a mixed list survives
    /// a round trip with each form preserved.
    #[test]
    fn mixed_transaction_forms_survive_the_body() {
        let vector = vector_named("legacy + EIP-7702");
        let block = Block::decode_exact(vector.rlp).unwrap();
        let transactions: &[SignedTxEnvelope] = block.transactions();
        assert_eq!(transactions.len(), 2);

        let list = rlp::Rlp::new(vector.rlp).at(1).unwrap();
        assert!(list.at(0).unwrap().is_list(), "legacy stays a bare list");
        assert!(
            list.at(1).unwrap().is_data(),
            "a typed transaction is a byte string"
        );
        assert_eq!(
            list.at(1).unwrap().data().unwrap(),
            transactions[1].encoded_2718().as_slice()
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

    /// Named vector with top-level item `index` replaced by `replacement`.
    fn block_with_item(vector: &str, index: usize, replacement: Vec<u8>) -> Vec<u8> {
        let mut items = items_of(vector_named(vector).rlp);
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
        let transactions = items_of(vector_named("legacy + EIP-7702").rlp)[1].clone();
        for (label, item, replacement) in [
            (
                "transactions as a byte string",
                1,
                as_byte_string(&transactions),
            ),
            ("transactions as 0x80", 1, hex!("80").to_vec()),
            ("transactions as 0x83aabbcc", 1, hex!("83aabbcc").to_vec()),
        ] {
            assert_rejected(
                label,
                &block_with_item("legacy + EIP-7702", item, replacement),
            );
        }
        let withdrawals = items_of(vector_named("one withdrawal").rlp)[3].clone();
        for (label, replacement) in [
            ("withdrawals as a byte string", as_byte_string(&withdrawals)),
            ("withdrawals as 0x80", hex!("80").to_vec()),
        ] {
            assert_rejected(label, &block_with_item("one withdrawal", 3, replacement));
        }
    }

    #[test]
    fn decode_rejects_bytes_that_no_item_accounts_for() {
        let top = items_of(vector_named("legacy + EIP-7702").rlp);
        // An "empty" ommers list hiding three bytes: the `!= 0` count check waves it through.
        assert_rejected(
            "ommers = c3 b9ffff",
            &block_with_item("legacy + EIP-7702", 2, hex!("c3b9ffff").to_vec()),
        );
        // Inside the transactions list.
        assert_rejected(
            "poison after the last transaction",
            &block_with_item("legacy + EIP-7702", 1, list_of(&items_of(&top[1]), POISON)),
        );
        // Inside the header's own list.
        assert_rejected(
            "poison inside the header",
            &block_with_item("legacy + EIP-7702", 0, list_of(&items_of(&top[0]), POISON)),
        );
        // Inside the block's own list payload: this is the contract `decode_exact` documents.
        assert_rejected("poison inside the block's payload", &list_of(&top, POISON));
        // Inside a withdrawal, and after the last withdrawal.
        let with_withdrawals = items_of(vector_named("one withdrawal").rlp);
        let withdrawals = items_of(&with_withdrawals[3]);
        assert_rejected(
            "poison after the last withdrawal",
            &block_with_item("one withdrawal", 3, list_of(&withdrawals, POISON)),
        );
        let mut poisoned = withdrawals.clone();
        poisoned[0] = list_of(&items_of(&withdrawals[0]), POISON);
        assert_rejected(
            "poison inside a withdrawal",
            &block_with_item(
                "one withdrawal",
                3,
                list_of(&poisoned, POISON.get(..0).unwrap()),
            ),
        );
    }

    #[test]
    fn decode_rejects_a_legacy_transaction_wrapped_in_a_byte_string() {
        // Wrapping a bare legacy list would give the same block two encodings.
        let top = items_of(vector_named("legacy + EIP-7702").rlp);
        let mut transactions = items_of(&top[1]);
        transactions[0] = wrapped(&transactions[0]);
        let mutated = block_with_item("legacy + EIP-7702", 1, list_of(&transactions, &[]));
        let error = Block::decode_exact(&mutated).unwrap_err();
        assert!(
            matches!(error, BlockDecodeError::Transaction { index: 0, .. }),
            "{error}"
        );
        assert!(
            format!("{error}").contains("starts with a legacy RLP list"),
            "{error}"
        );
    }

    #[test]
    fn decoding_is_injective() {
        // The property the individual cases above are instances of: anything `decode_exact` accepts
        // re-encodes to exactly its input, so one block has exactly one encoding.
        let mut inputs: Vec<Vec<u8>> = vectors().iter().map(|v| v.rlp.to_vec()).collect();
        let top = items_of(vector_named("legacy + EIP-7702").rlp);
        inputs.push(block_with_item("legacy + EIP-7702", 1, hex!("80").to_vec()));
        inputs.push(block_with_item(
            "legacy + EIP-7702",
            2,
            hex!("c3b9ffff").to_vec(),
        ));
        inputs.push(list_of(&top, POISON));
        inputs.push(block_with_item(
            "legacy + EIP-7702",
            1,
            list_of(&items_of(&top[1]), POISON),
        ));
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
