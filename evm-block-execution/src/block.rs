//! Block types: the header, the body, and the sealed / recovered forms execution consumes.
//!
//! The chain of types mirrors how a block is progressively refined on its way into execution:
//!
//! 1. [`Header`] — the canonical header; its RLP encoding defines the block hash.
//! 2. [`BlockBody`] — the transactions and withdrawals the header commits to.
//! 3. [`Block`] — header + body.
//! 4. [`SealedBlock`] — a block whose hash is cached ([`SealedHeader`] does the caching, lazily).
//! 5. [`RecoveredBlock`] — a sealed block paired with the sender of every transaction, which
//!    [`recover_block_with_public_keys`] establishes.
//!
//! Each type dereferences to the one it wraps, so a `RecoveredBlock` reads its header fields
//! directly (`block.state_root`) and its hash through [`SealedBlock::hash`].
//!
//! Alongside them live the execution *environment* types: [`BlockEnv`], the input the transaction
//! loop reads, and [`ExpectedHeader`], the output values a valid block must reproduce. Nothing here
//! converts between the two representations yet — the transaction loop is still entered with a
//! [`BlockEnv`] and a transaction list.
//!
//! # Senders
//!
//! A block body carries transactions in their consensus form
//! ([`SignedTransaction`](crate::transaction::SignedTransaction)): a signature, and no sender. The
//! sender is established by [`recover_block_with_public_keys`], which verifies each signature
//! against a public key supplied with the block — cheaper than recovering it, and the reason the
//! keys are an input. The result is a [`RecoveredBlock`]; the executor's transaction form,
//! [`Transaction`](crate::transaction::Transaction), is that pairing of payload and sender.
//!
//! Only post-merge blocks are modelled, so ommers are absent from [`BlockBody`] entirely: the list
//! is always empty and `ommers_hash` is the constant
//! [`EMPTY_OMMERS_HASH`](crate::constants::EMPTY_OMMERS_HASH), which is checkable on the header
//! alone.

mod body;
mod codec;
mod env;
mod header;
mod recover;
mod recovered;
mod sealed;

use crate::transaction::SignedTransaction;
pub use body::BlockBody;
pub use codec::BlockDecodeError;
pub use env::{BlockEnv, ExpectedHeader};
pub use header::Header;
use primitive_types::H256;
pub use recover::{SenderRecoveryError, UncompressedPublicKey, recover_block_with_public_keys};
pub use recovered::{BlockRecoveryError, RecoveredBlock};
pub use sealed::{SealedBlock, SealedHeader};
use std::ops::Deref;

/// An Ethereum block: its [`Header`] and the [`BlockBody`] that header commits to.
///
/// Dereferences to the header, so header fields can be read straight off the block
/// (`block.state_root`). Sealing it ([`Block::seal_slow`]) caches the block hash; pairing it with
/// its senders — which [`recover_block_with_public_keys`](super::recover_block_with_public_keys)
/// establishes — yields a [`RecoveredBlock`](super::RecoveredBlock), the form execution consumes.
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
    pub fn transactions(&self) -> &[SignedTransaction] {
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
