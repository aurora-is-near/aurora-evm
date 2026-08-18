//! A sealed block paired with the sender of every transaction.
//!
//! [`RecoveredBlock`] is the form block execution consumes. A block body carries transactions in
//! their consensus form, which holds a signature but no sender; the sender is the *product* of
//! recovering from that signature, so it is established once per block and carried alongside it
//! rather than re-derived per use. That recovery is [`recover_block`](super::recover_block), which is
//! the intended way to build this type.
//!
//! The public constructors here pair a block with senders a caller has already established:
//! [`RecoveredBlock::try_new`] and its siblings check that the two lists line up, which is all that
//! can be checked without re-doing the recovery. The unchecked forms they wrap are crate-internal,
//! because a mismatched senders list is a crate bug rather than bad input.
//!
//! [`RecoveredBlock::into_tx_envs`] is where the pairing is spent: it consumes the block and yields
//! one [`TxEnv`] per transaction, which is what the executor reads.
//!
//! What the type does *not* prove: [`RecoveredBlock::try_new`] and its siblings compare only the
//! two lengths, so a caller can pair a block with senders of its own choosing. The type is a
//! *pairing*, not evidence that recovery was performed — only [`recover_block`] and
//! [`recover_block_with_public_keys`] produce senders derived from the signatures.
//!
//! [`recover_block`]: crate::block::recover_block
//! [`recover_block_with_public_keys`]: crate::block::recover_block_with_public_keys

use crate::block::Block;
use crate::block::body::BlockBody;
use crate::block::header::Header;
use crate::block::sealed::{SealedBlock, SealedHeader};
use crate::transaction::{SignedTxEnvelope, TxEnv};
use core::fmt;
use core::ops::Deref;
use primitive_types::{H160, H256};

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
    /// Pairs a block and its senders, leaving the hash to be computed on first use, **without**
    /// checking that there is one sender per transaction.
    ///
    /// Crate-internal: the public entry point is [`Self::try_new`].
    #[must_use]
    pub(super) fn new_unhashed_unchecked(block: Block, senders: Vec<H160>) -> Self {
        Self::new_sealed_unchecked(SealedBlock::new_unhashed(block), senders)
    }

    /// Pairs a block and its senders, adopting a hash the caller already knows, **without** checking
    /// that there is one sender per transaction.
    ///
    /// Crate-internal: the public entry point is [`Self::try_new`].
    #[must_use]
    pub(super) fn new_unchecked(block: Block, senders: Vec<H160>, hash: H256) -> Self {
        Self::new_sealed_unchecked(SealedBlock::new_unchecked(block, hash), senders)
    }

    /// Pairs an already sealed block and its senders **without** checking that there is one sender
    /// per transaction.
    ///
    /// Crate-internal: the public entry point is [`Self::try_new_sealed`].
    #[must_use]
    pub(super) const fn new_sealed_unchecked(block: SealedBlock, senders: Vec<H160>) -> Self {
        Self { block, senders }
    }

    /// Pairs a block and its senders, adopting a known hash, after checking that the two lists line
    /// up.
    ///
    /// The hash is adopted as given: this checks the sender count, not the hash.
    ///
    /// ## Errors
    /// [`BlockRecoveryError`] if there is not exactly one sender per transaction.
    pub fn try_new(
        block: Block,
        senders: Vec<H160>,
        hash: H256,
    ) -> Result<Self, BlockRecoveryError> {
        check_sender_count(&block.body.transactions, &senders)?;
        Ok(Self::new_unchecked(block, senders, hash))
    }

    /// Pairs a block and its senders lazily, after checking that the two lists line up.
    ///
    /// ## Errors
    /// [`BlockRecoveryError`] if there is not exactly one sender per transaction.
    pub fn try_new_unhashed(block: Block, senders: Vec<H160>) -> Result<Self, BlockRecoveryError> {
        check_sender_count(&block.body.transactions, &senders)?;
        Ok(Self::new_unhashed_unchecked(block, senders))
    }

    /// Pairs an already sealed block and its senders, after checking that the two lists line up.
    ///
    /// ## Errors
    /// [`BlockRecoveryError`] if there is not exactly one sender per transaction.
    pub fn try_new_sealed(
        block: SealedBlock,
        senders: Vec<H160>,
    ) -> Result<Self, BlockRecoveryError> {
        check_sender_count(block.transactions(), &senders)?;
        Ok(Self::new_sealed_unchecked(block, senders))
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
    pub fn transactions(&self) -> &[SignedTxEnvelope] {
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

    /// Projects the whole block into the executor's transaction form, **consuming** it.
    ///
    /// The bridge from the consensus shape to the execution shape, and the reason both halves of the
    /// pairing are owned: [`SignedTxEnvelope::into_tx_env`] takes its transaction by value, so the call
    /// data, the access list and the authorization tuples *move* into the result. Borrowing the
    /// transactions here would force a copy of each that the executor immediately takes ownership of
    /// anyway. Nothing reads the block after this point, which is what makes that safe.
    ///
    /// Order is preserved: entry `i` is transaction `i` paired with its own sender.
    ///
    /// ## Errors
    /// [`BlockRecoveryError::SenderCountMismatch`] if the two lists do not line up. Unreachable for
    /// any value built through the public constructors, which all check it, or by
    /// [`recover_block`](super::recover_block), which derives one sender per transaction from the
    /// transactions themselves — but it is checked rather than assumed, because the alternative is a
    /// `zip` that pairs the shorter of the two and yields a *prefix* of the block. Executing part of a
    /// block and reporting success is the worst outcome available here. The cost is one length
    /// comparison per block.
    pub fn into_tx_envs(self) -> Result<Vec<TxEnv>, BlockRecoveryError> {
        check_sender_count(self.transactions(), &self.senders)?;
        let (block, senders) = self.split();
        let transactions = block.into_block().body.transactions;
        Ok(core::iter::zip(senders, transactions)
            .map(|(sender, transaction)| transaction.into_tx_env(sender))
            .collect())
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
    transactions: &[SignedTxEnvelope],
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

#[cfg(test)]
mod tests {
    use super::{BlockRecoveryError, RecoveredBlock};
    use crate::block::{Block, BlockBody, Header};
    use crate::transaction::{SignedTxEnvelope, TxType};
    use hex_literal::hex;
    use primitive_types::{H160, H256};

    /// A real EIP-1559 transaction, decoded from its consensus bytes.
    fn transaction() -> SignedTxEnvelope {
        SignedTxEnvelope::decode_2718(&hex!("02f8b00142843b9aca008504a817c80082ad62946069a6c32cf691f5982febae4faf8a6f3ab2f0f680b844a22cb4650000000000000000000000005eee75727d804a2b13038928d36f8b188945a57a0000000000000000000000000000000000000000000000000000000000000000c080a0840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565a025e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1")).unwrap()
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
        // The unchecked constructor performs no check at all, not even on the count.
        let recovered = RecoveredBlock::new_unhashed_unchecked(block(1), Vec::new());
        assert!(recovered.senders().is_empty());
        assert_eq!(recovered.transactions().len(), 1);
    }

    #[test]
    fn derefs_through_to_the_header_and_keeps_the_hash() {
        let hash = H256::repeat_byte(0x11);
        let recovered = RecoveredBlock::new_unchecked(block(0), Vec::new(), hash);
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
    /// The projection is the only place the pairing is spent, so it is where order has to be proven:
    /// entry `i` must carry sender `i`, not merely some sender from the list.
    #[test]
    fn into_tx_envs_pairs_each_transaction_with_its_own_sender() {
        let senders = vec![H160::repeat_byte(0xaa), H160::repeat_byte(0xbb)];
        let recovered = RecoveredBlock::try_new_unhashed(block(2), senders.clone()).unwrap();

        let tx_envs = recovered.into_tx_envs().unwrap();
        assert_eq!(tx_envs.len(), 2);
        for (index, tx_env) in tx_envs.iter().enumerate() {
            assert_eq!(tx_env.caller, senders[index], "transaction {index}");
            assert_eq!(tx_env.tx_type, TxType::Eip1559, "transaction {index}");
        }
    }

    /// The fields the consuming projection moves rather than copies must arrive intact, or the
    /// executor would run a transaction that is not the one the block carried.
    #[test]
    fn into_tx_envs_carries_the_transactions_own_fields() {
        let sender = H160::repeat_byte(0xaa);
        let source = transaction();
        let tx_envs = RecoveredBlock::try_new_unhashed(block(1), vec![sender])
            .unwrap()
            .into_tx_envs()
            .unwrap();

        let SignedTxEnvelope::Eip1559(expected) = source else {
            panic!("the vector is an EIP-1559 transaction")
        };
        assert_eq!(tx_envs[0].data, expected.tx.data);
        assert_eq!(tx_envs[0].nonce, expected.tx.nonce);
        assert_eq!(tx_envs[0].gas_limit, expected.tx.gas_limit);
        assert_eq!(tx_envs[0].chain_id, Some(expected.tx.chain_id));
    }

    #[test]
    fn into_tx_envs_on_an_empty_block_yields_nothing() {
        let recovered = RecoveredBlock::try_new_unhashed(block(0), Vec::new()).unwrap();
        assert!(recovered.into_tx_envs().unwrap().is_empty());
    }

    /// A mismatched pairing is refused rather than zipped down to a prefix: executing part of a block
    /// and reporting success is worse than refusing it. Only the crate-internal unchecked
    /// constructors can build one, which is why this reaches for one.
    #[test]
    fn into_tx_envs_refuses_a_mismatched_pairing_instead_of_truncating() {
        let recovered = RecoveredBlock::new_unhashed_unchecked(block(2), Vec::new());
        assert_eq!(
            recovered.into_tx_envs().unwrap_err(),
            BlockRecoveryError::SenderCountMismatch {
                senders: 0,
                transactions: 2
            }
        );

        // The other direction too: `zip` truncates whichever list is longer.
        let recovered = RecoveredBlock::new_unhashed_unchecked(
            block(1),
            vec![H160::repeat_byte(0xaa), H160::repeat_byte(0xbb)],
        );
        assert_eq!(
            recovered.into_tx_envs().unwrap_err(),
            BlockRecoveryError::SenderCountMismatch {
                senders: 2,
                transactions: 1
            }
        );
    }

    #[test]
    fn try_new_sealed_rejects_more_senders_than_transactions() {
        // The untested direction: `zip` truncates both ways, so both must be rejected.
        let sealed = block(1).seal_slow();
        let senders = vec![H160::repeat_byte(0xaa), H160::repeat_byte(0xbb)];
        assert_eq!(
            RecoveredBlock::try_new_sealed(sealed, senders).unwrap_err(),
            BlockRecoveryError::SenderCountMismatch {
                senders: 2,
                transactions: 1
            }
        );
    }
}
