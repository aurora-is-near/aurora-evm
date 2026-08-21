//! Block types and their progression toward execution:
//!
//! 1. [`Header`] — the canonical header; its RLP encoding defines the block hash.
//! 2. [`BlockBody`] — the transactions and withdrawals the header commits to.
//! 3. [`Block`] — header + body.
//! 4. [`SealedBlock`] — a block with a lazily cached hash.
//! 5. [`RecoveredBlock`] — a sealed block paired with each transaction's recovered sender.
//!
//! [`SignedTxEnvelope`] contains a signature but no sender. [`recover_block`] derives senders from
//! those signatures; [`recover_block_with_public_keys`] additionally checks caller-supplied keys.
//! The resulting pairing is later consumed into [`TxEnv`](crate::transaction::TxEnv) values.
//!
//! Only post-merge blocks are modelled, so ommers are absent from [`BlockBody`] entirely: the list
//! is empty and `ommers_hash` must be
//! [`EMPTY_OMMER_ROOT_HASH`](crate::constants::EMPTY_OMMER_ROOT_HASH).

mod body;
mod codec;
mod env;
mod header;
mod recover;
mod recovered;
mod sealed;

use crate::transaction::SignedTxEnvelope;
pub use body::BlockBody;
pub use codec::BlockDecodeError;
pub use env::{BlobExcessGasAndPrice, BlockEnv};
pub use header::Header;
use primitive_types::H256;
pub use recover::{
    SenderRecoveryError, UncompressedPublicKey, recover_block, recover_block_with_public_keys,
};
pub use recovered::{BlockRecoveryError, RecoveredBlock};
pub use sealed::{SealedBlock, SealedHeader};
use std::ops::Deref;

/// An Ethereum block: its [`Header`] and the [`BlockBody`] that header commits to.
///
/// Dereferences to the header, so header fields can be read straight off the block
/// (`block.state_root`). Sealing it ([`Block::seal_slow`]) caches the block hash; pairing it with
/// its senders — which [`recover_block_with_public_keys`]
/// establishes — yields a [`RecoveredBlock`], the form execution consumes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Block {
    /// The block header.
    pub header: Header,
    /// The block body.
    pub body: BlockBody,
}

impl Block {
    /// Builds a block from a header and a body.
    #[must_use]
    pub const fn new(header: Header, body: BlockBody) -> Self {
        Self { header, body }
    }

    /// The block header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// The block body.
    #[must_use]
    pub const fn body(&self) -> &BlockBody {
        &self.body
    }

    /// The block's transactions.
    #[must_use]
    pub fn transactions(&self) -> &[SignedTxEnvelope] {
        &self.body.transactions
    }

    /// Splits the block back into its header and body.
    #[must_use]
    pub fn split(self) -> (Header, BlockBody) {
        (self.header, self.body)
    }

    /// Seals the block, computing and caching its hash.
    #[must_use]
    pub fn seal_slow(self) -> SealedBlock {
        SealedBlock::seal_slow(self)
    }

    /// Seals the block with a hash the caller already knows, without recomputing it.
    #[must_use]
    pub fn seal_unchecked(self, hash: H256) -> SealedBlock {
        SealedBlock::new_unchecked(self, hash)
    }

    /// Seals the block lazily: the hash is computed on first use.
    #[must_use]
    pub fn seal_unhashed(self) -> SealedBlock {
        SealedBlock::new_unhashed(self)
    }
}

impl Deref for Block {
    type Target = Header;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::Block;
    use crate::block::{BlockBody, Header};
    use primitive_types::{H256, U256};

    fn block() -> Block {
        Block::new(
            Header {
                number: 7,
                gas_limit: 30_000_000,
                difficulty: U256::zero(),
                ..Header::default()
            },
            BlockBody::default(),
        )
    }

    #[test]
    fn derefs_to_the_header() {
        let block = block();
        assert_eq!(block.number, 7);
        assert_eq!(block.gas_limit, 30_000_000);
        assert_eq!(block.header().number, block.number);
    }

    #[test]
    fn split_returns_the_parts() {
        let (header, body) = block().split();
        assert_eq!(header.number, 7);
        assert!(body.transactions.is_empty());
    }

    #[test]
    fn seal_unchecked_keeps_the_supplied_hash() {
        let hash = H256::repeat_byte(0xaa);
        let sealed = block().seal_unchecked(hash);
        assert_eq!(sealed.hash(), hash);
    }

    #[test]
    fn seal_slow_computes_the_header_hash() {
        let block = block();
        let expected = block.header.hash_slow();
        assert_eq!(block.seal_slow().hash(), expected);
    }
}
