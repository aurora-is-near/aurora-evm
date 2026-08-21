//! Sealed header and block: a block paired with its cached hash.
//!
//! A block hash is `keccak256(rlp(header))`, so sealing caches a derived value rather than adding
//! consensus data. [`SealedHeader::new_unhashed`] computes it lazily; `new_unchecked` constructors
//! adopt a hash already established by the caller.

use crate::block::Block;
use crate::block::body::BlockBody;
use crate::block::header::Header;
use crate::transaction::SignedTxEnvelope;
use core::ops::Deref;
use primitive_types::H256;
use std::sync::OnceLock;

/// A [`Header`] with its block hash cached.
///
/// Dereferences to the header. Two sealed headers are equal when their headers are equal: the hash
/// is derived from the header, so comparing headers is equivalent and never forces a hash.
#[derive(Clone, Debug, Default, Eq)]
pub struct SealedHeader {
    /// The block hash, computed on first use unless it was supplied up front.
    hash: OnceLock<H256>,
    /// The sealed header.
    header: Header,
}

impl SealedHeader {
    /// Seals a header with a hash the caller already knows.
    #[must_use]
    pub fn new_unchecked(header: Header, hash: H256) -> Self {
        let cell = OnceLock::new();
        // The cell was just created, so this cannot fail.
        let _ = cell.set(hash);
        Self { hash: cell, header }
    }

    /// Seals a header without hashing it; the hash is computed on first use.
    #[must_use]
    pub const fn new_unhashed(header: Header) -> Self {
        Self {
            hash: OnceLock::new(),
            header,
        }
    }

    /// Seals a header, computing its hash now.
    #[must_use]
    pub fn seal_slow(header: Header) -> Self {
        let hash = header.hash_slow();
        Self::new_unchecked(header, hash)
    }

    /// The block hash, computing and caching it if it is not known yet.
    #[must_use]
    pub fn hash(&self) -> H256 {
        *self.hash.get_or_init(|| self.header.hash_slow())
    }

    /// The sealed header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Discards the cached hash and returns the header.
    #[must_use]
    pub fn unseal(self) -> Header {
        self.header
    }

    /// Splits into the header and its hash, computing the hash if it is not known yet.
    #[must_use]
    pub fn split(self) -> (Header, H256) {
        let hash = self.hash();
        (self.header, hash)
    }
}

impl PartialEq for SealedHeader {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
    }
}

impl Deref for SealedHeader {
    type Target = Header;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl From<Header> for SealedHeader {
    fn from(header: Header) -> Self {
        Self::new_unhashed(header)
    }
}

/// A [`Block`] whose header is sealed with its hash.
///
/// Dereferences to the [`SealedHeader`], and through it to the [`Header`], so `sealed.hash()` and
/// `sealed.state_root` both read naturally.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SealedBlock {
    /// The sealed header.
    header: SealedHeader,
    /// The block body.
    body: BlockBody,
}

impl SealedBlock {
    /// Seals a block with a hash the caller already knows.
    #[must_use]
    pub fn new_unchecked(block: Block, hash: H256) -> Self {
        let (header, body) = block.split();
        Self {
            header: SealedHeader::new_unchecked(header, hash),
            body,
        }
    }

    /// Seals a block without hashing it; the hash is computed on first use.
    #[must_use]
    pub fn new_unhashed(block: Block) -> Self {
        let (header, body) = block.split();
        Self {
            header: SealedHeader::new_unhashed(header),
            body,
        }
    }

    /// Seals a block, computing its hash now.
    #[must_use]
    pub fn seal_slow(block: Block) -> Self {
        let (header, body) = block.split();
        Self {
            header: SealedHeader::seal_slow(header),
            body,
        }
    }

    /// Assembles a sealed block from an already sealed header and a body.
    #[must_use]
    pub const fn from_parts(header: SealedHeader, body: BlockBody) -> Self {
        Self { header, body }
    }

    /// The block hash, computing and caching it if it is not known yet.
    #[must_use]
    pub fn hash(&self) -> H256 {
        self.header.hash()
    }

    /// The sealed header.
    #[must_use]
    pub const fn sealed_header(&self) -> &SealedHeader {
        &self.header
    }

    /// The block header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        self.header.header()
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

    /// Unseals the block, discarding the cached hash.
    #[must_use]
    pub fn into_block(self) -> Block {
        Block::new(self.header.unseal(), self.body)
    }

    /// Splits into the sealed header and the body.
    #[must_use]
    pub fn split(self) -> (SealedHeader, BlockBody) {
        (self.header, self.body)
    }
}

impl Deref for SealedBlock {
    type Target = SealedHeader;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl From<Block> for SealedBlock {
    fn from(block: Block) -> Self {
        Self::new_unhashed(block)
    }
}

#[cfg(test)]
mod tests {
    use super::{SealedBlock, SealedHeader};
    use crate::block::{Block, BlockBody, Header};
    use primitive_types::H256;

    fn header() -> Header {
        Header {
            number: 11,
            gas_limit: 30_000_000,
            ..Header::default()
        }
    }

    #[test]
    fn lazy_hash_matches_eager_hash() {
        let expected = header().hash_slow();
        // Sealed lazily: nothing is hashed until `hash()` is called.
        assert_eq!(SealedHeader::new_unhashed(header()).hash(), expected);
        // Sealed eagerly: same value.
        assert_eq!(SealedHeader::seal_slow(header()).hash(), expected);
    }

    #[test]
    fn cached_hash_is_returned_verbatim() {
        // `new` adopts the caller's hash without recomputing it, so a stale hash is returned as is.
        let stale = H256::repeat_byte(0xff);
        let sealed = SealedHeader::new_unchecked(header(), stale);
        assert_eq!(sealed.hash(), stale);
        assert_ne!(sealed.hash(), sealed.header().hash_slow());
    }

    #[test]
    fn hash_is_computed_once_and_reused() {
        let sealed = SealedHeader::new_unhashed(header());
        assert_eq!(sealed.hash(), sealed.hash());
    }

    #[test]
    fn equality_ignores_the_cached_hash() {
        // Equality is over the header: an unhashed and an eagerly sealed header are equal.
        assert_eq!(
            SealedHeader::new_unhashed(header()),
            SealedHeader::seal_slow(header())
        );
        let mut other = header();
        other.number = 12;
        assert_ne!(
            SealedHeader::new_unhashed(header()),
            SealedHeader::new_unhashed(other)
        );
    }

    #[test]
    fn sealed_header_derefs_and_splits() {
        let sealed = SealedHeader::seal_slow(header());
        assert_eq!(sealed.gas_limit, 30_000_000);
        let (unsealed, hash) = sealed.split();
        assert_eq!(hash, unsealed.hash_slow());
        assert_eq!(unsealed.number, 11);
    }

    #[test]
    fn sealed_block_derefs_through_to_the_header() {
        let block = Block::new(header(), BlockBody::default());
        let expected = block.header.hash_slow();
        let sealed = SealedBlock::seal_slow(block);
        // Through `SealedHeader` to `Header`.
        assert_eq!(sealed.number, 11);
        assert_eq!(sealed.hash(), expected);
        assert!(sealed.transactions().is_empty());
    }

    #[test]
    fn sealed_block_roundtrips_through_block() {
        let block = Block::new(header(), BlockBody::default());
        let sealed = SealedBlock::seal_slow(block.clone());
        assert_eq!(sealed.into_block(), block);
    }
}
