//! A sealed block paired with the sender of every transaction.
//!
//! [`RecoveredBlock`] is the form block execution consumes. A block body carries transactions in
//! their consensus form, which holds a signature but no sender; the sender is the *product* of
//! checking that signature, so it is established once per block and carried alongside it rather
//! than re-derived per use. That check is
//! [`recover_block_with_public_keys`](super::recover_block_with_public_keys), which is the intended
//! way to build this type.
//!
//! The constructors here do not verify anything: they pair a block with senders a caller has
//! already established. [`RecoveredBlock::try_new`] checks only that the two lists line up, which
//! is all that can be checked without the signatures — matching what the reference implementation
//! guarantees at this boundary.

use crate::block::Block;
use crate::block::body::BlockBody;
use crate::block::header::Header;
use crate::block::sealed::{SealedBlock, SealedHeader};
use crate::transaction::SignedTransaction;
use core::fmt;
use core::ops::Deref;
use primitive_types::{H160, H256};

/// Why a block and a senders list cannot be paired.
///
/// A construction-time error: it reports an inconsistent *input*, not a failed block validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRecoveryError {
    /// The senders list and the transaction list have different lengths.
    SenderCountMismatch {
        /// Number of senders supplied.
        senders: usize,
        /// Number of transactions in the block.
        transactions: usize,
    },
}

impl fmt::Display for BlockRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SenderCountMismatch {
                senders,
                transactions,
            } => write!(
                f,
                "block has {transactions} transactions but {senders} senders were supplied"
            ),
        }
    }
}

impl core::error::Error for BlockRecoveryError {}

/// A [`SealedBlock`] with the sender of every transaction alongside it.
///
/// Dereferences to the sealed block, and through it to the header, so `recovered.hash()` and
/// `recovered.state_root` both read naturally.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveredBlock {
    /// The sealed block.
    block: SealedBlock,
    /// Sender of each transaction, in transaction order.
    senders: Vec<H160>,
}

impl RecoveredBlock {
    /// Pairs a block and its senders, adopting a hash the caller already knows. Unchecked.
    #[must_use]
    pub fn new(block: Block, senders: Vec<H160>, hash: H256) -> Self {
        Self::new_sealed(SealedBlock::new_unchecked(block, hash), senders)
    }

    /// Pairs a block and its senders without hashing it; the hash is computed on first use.
    /// Unchecked.
    #[must_use]
    pub fn new_unhashed(block: Block, senders: Vec<H160>) -> Self {
        Self::new_sealed(SealedBlock::new_unhashed(block), senders)
    }

    /// Pairs an already sealed block and its senders. Unchecked.
    #[must_use]
    pub const fn new_sealed(block: SealedBlock, senders: Vec<H160>) -> Self {
        Self { block, senders }
    }

    /// Pairs a block and its senders, adopting a known hash, after checking that the two lists line
    /// up.
    ///
    /// # Errors
    /// [`BlockRecoveryError`] if there is not exactly one sender per transaction.
    pub fn try_new(
        block: Block,
        senders: Vec<H160>,
        hash: H256,
    ) -> Result<Self, BlockRecoveryError> {
        check_sender_count(&block.body.transactions, &senders)?;
        Ok(Self::new(block, senders, hash))
    }

    /// Pairs a block and its senders lazily, after checking that the two lists line up.
    ///
    /// # Errors
    /// [`BlockRecoveryError`] if there is not exactly one sender per transaction.
    pub fn try_new_unhashed(block: Block, senders: Vec<H160>) -> Result<Self, BlockRecoveryError> {
        check_sender_count(&block.body.transactions, &senders)?;
        Ok(Self::new_unhashed(block, senders))
    }

    /// Pairs an already sealed block and its senders, after checking that the two lists line up.
    ///
    /// # Errors
    /// [`BlockRecoveryError`] if there is not exactly one sender per transaction.
    pub fn try_new_sealed(
        block: SealedBlock,
        senders: Vec<H160>,
    ) -> Result<Self, BlockRecoveryError> {
        check_sender_count(block.transactions(), &senders)?;
        Ok(Self::new_sealed(block, senders))
    }

    /// The sender of each transaction, in transaction order.
    #[must_use]
    pub fn senders(&self) -> &[H160] {
        &self.senders
    }

    /// Iterates over the senders.
    pub fn senders_iter(&self) -> impl Iterator<Item = H160> + '_ {
        self.senders.iter().copied()
    }

    /// Iterates over the transactions paired with their senders.
    pub fn transactions_with_senders(&self) -> impl Iterator<Item = (&H160, &SignedTransaction)> {
        self.senders.iter().zip(self.transactions())
    }

    /// The block hash, computing and caching it if it is not known yet.
    #[must_use]
    pub fn hash(&self) -> H256 {
        self.block.hash()
    }

    /// The block header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        self.block.header()
    }

    /// The sealed header.
    #[must_use]
    pub const fn sealed_header(&self) -> &SealedHeader {
        self.block.sealed_header()
    }

    /// The block body.
    #[must_use]
    pub const fn body(&self) -> &BlockBody {
        self.block.body()
    }

    /// The block's transactions.
    #[must_use]
    pub fn transactions(&self) -> &[SignedTransaction] {
        self.block.transactions()
    }

    /// The underlying sealed block.
    #[must_use]
    pub const fn sealed_block(&self) -> &SealedBlock {
        &self.block
    }

    /// Discards the senders and the cached hash, returning the block.
    #[must_use]
    pub fn into_block(self) -> Block {
        self.block.into_block()
    }

    /// Splits into the sealed block and the senders.
    #[must_use]
    pub fn split(self) -> (SealedBlock, Vec<H160>) {
        (self.block, self.senders)
    }
}

impl Deref for RecoveredBlock {
    type Target = SealedBlock;

    fn deref(&self) -> &Self::Target {
        &self.block
    }
}

/// Checks that there is exactly one sender per transaction.
const fn check_sender_count(
    transactions: &[SignedTransaction],
    senders: &[H160],
) -> Result<(), BlockRecoveryError> {
    if transactions.len() == senders.len() {
        Ok(())
    } else {
        Err(BlockRecoveryError::SenderCountMismatch {
            senders: senders.len(),
            transactions: transactions.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockRecoveryError, RecoveredBlock};
    use crate::block::{Block, BlockBody, Header};
    use crate::transaction::SignedTransaction;
    use hex_literal::hex;
    use primitive_types::{H160, H256};

    /// A real EIP-1559 transaction, decoded from its consensus bytes.
    fn transaction() -> SignedTransaction {
        SignedTransaction::decode_2718(&hex!("02f8b00142843b9aca008504a817c80082ad62946069a6c32cf691f5982febae4faf8a6f3ab2f0f680b844a22cb4650000000000000000000000005eee75727d804a2b13038928d36f8b188945a57a0000000000000000000000000000000000000000000000000000000000000000c080a0840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565a025e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1")).unwrap()
    }

    fn block(transactions: usize) -> Block {
        Block::new(
            Header {
                number: 3,
                ..Header::default()
            },
            BlockBody::new(vec![transaction(); transactions], None),
        )
    }

    #[test]
    fn try_new_accepts_one_sender_per_transaction() {
        let senders = vec![H160::repeat_byte(0xaa), H160::repeat_byte(0xbb)];
        let recovered = RecoveredBlock::try_new_unhashed(block(2), senders.clone()).unwrap();
        assert_eq!(recovered.senders(), senders);
        assert_eq!(recovered.transactions().len(), 2);
        assert_eq!(recovered.senders_iter().count(), 2);
        for (sender, transaction) in recovered.transactions_with_senders() {
            assert!(senders.contains(sender));
            assert_eq!(transaction.payload.chain_id, Some(1));
        }
    }

    #[test]
    fn try_new_rejects_a_sender_count_mismatch() {
        let error =
            RecoveredBlock::try_new_unhashed(block(2), vec![H160::repeat_byte(0xaa)]).unwrap_err();
        assert_eq!(
            error,
            BlockRecoveryError::SenderCountMismatch {
                senders: 1,
                transactions: 2
            }
        );
    }

    #[test]
    fn unchecked_construction_trusts_the_caller() {
        // `new_unhashed` performs no check at all, not even on the count.
        let recovered = RecoveredBlock::new_unhashed(block(1), Vec::new());
        assert!(recovered.senders().is_empty());
        assert_eq!(recovered.transactions().len(), 1);
    }

    #[test]
    fn derefs_through_to_the_header_and_keeps_the_hash() {
        let hash = H256::repeat_byte(0x11);
        let recovered = RecoveredBlock::new(block(0), Vec::new(), hash);
        assert_eq!(recovered.hash(), hash);
        // Through `SealedBlock` and `SealedHeader` to `Header`.
        assert_eq!(recovered.number, 3);
        assert_eq!(recovered.header().number, 3);
    }

    #[test]
    fn splits_back_into_block_and_senders() {
        let senders = vec![H160::repeat_byte(0xaa)];
        let source = block(1);
        let recovered = RecoveredBlock::try_new_unhashed(source.clone(), senders.clone()).unwrap();
        let (sealed, split_senders) = recovered.split();
        assert_eq!(split_senders, senders);
        assert_eq!(sealed.into_block(), source);
    }
}
