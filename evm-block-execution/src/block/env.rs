use crate::blob::{BlobExcessGasAndPrice, BlobParams, BlobSchedule};
use crate::bloom::Bloom;
use crate::errors::BlockExecutionError;
use crate::spec::Spec;
use crate::withdrawal::Withdrawal;
use primitive_types::{H160, H256, U256};

/// Execution **input** environment for a block.
///
/// Holds everything the transaction loop reads (block context, BLOCKHASH window, blob fee) plus
/// the inputs consumed by the pre/post-execution system steps (`parent_hash`,
/// `parent_beacon_block_root`, `withdrawals`). The *expected* header values a valid block must
/// reproduce live separately in [`ExpectedHeader`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEnv {
    /// Environmental block hashes (recent ancestors, for the `BLOCKHASH` opcode window).
    pub block_hashes: Vec<H256>,
    /// Environmental block number.
    pub block_number: U256,
    /// Environmental coinbase.
    pub block_coinbase: H160,
    /// Environmental block timestamp.
    pub block_timestamp: U256,
    /// Environmental block difficulty.
    pub block_difficulty: U256,
    /// Environmental block gas limit. Mandatory: a block always carries `gasLimit`, and the
    /// transaction loop enforces `SUM tx.gas_limit <= block_gas_limit` against it. Making it a plain
    /// `u64` (not `Option`) rules out a fail-open where an absent limit silently disables the check.
    pub block_gas_limit: u64,
    /// Environmental base fee per gas.
    pub block_base_fee_per_gas: U256,
    /// Environmental randomness.
    ///
    /// In Ethereum, this is the randomness beacon provided by the beacon
    /// chain and is only enabled post Merge.
    pub block_randomness: Option<H256>,
    /// EIP-4844
    pub blob_excess_gas_and_price: Option<BlobExcessGasAndPrice>,
    /// EIP-4844
    pub blob_hashes: Vec<U256>,
    /// Active blob-gas parameters for this block, resolved from the chain's `BlobSchedule` by
    /// timestamp (EIP-7840 / EIP-7892). `None` before Cancun. Set by `Evm::new`.
    pub blob_params: Option<BlobParams>,
    /// Hash of the parent block.
    ///
    /// Consumed by the EIP-2935 pre-execution system call (writes the parent hash into the
    /// history-storage contract on Prague+).
    pub parent_hash: H256,
    /// Parent beacon block root (EIP-4788).
    ///
    /// `Some` from Cancun onward; consumed by the beacon-root pre-execution system call.
    /// `None` before Cancun (and on the genesis block, where the call is skipped).
    pub parent_beacon_block_root: Option<H256>,
    /// Validator withdrawals credited after the transaction loop (EIP-4895, Shanghai+).
    pub withdrawals: Vec<Withdrawal>,
}

impl BlockEnv {
    /// Resolve this block's blob parameters. They are a block-level property gated purely by
    /// hardfork — required from Cancun on, absent before it. `Spec` is authoritative for the
    /// fork, so a pre-Cancun block ignores the schedule entirely: a stray active entry cannot
    /// turn it into a "blob block". The schedule was already validated by `BlobSchedule::try_new`
    /// (once, at config-construction time), so any resolved params are known well-formed here.
    ///
    /// ## Errors
    /// Resolve blob params errors
    pub fn resolve_blob_params(
        &mut self,
        spec: &Spec,
        blob_schedule: &BlobSchedule,
    ) -> Result<(), BlockExecutionError> {
        let timestamp = u64::try_from(self.block_timestamp)
            .map_err(|_| BlockExecutionError::InvalidBlockTimestamp)?;

        self.blob_params = if spec >= &Spec::Cancun {
            Some(
                blob_schedule
                    .blob_params_for_timestamp(timestamp)
                    .ok_or(BlockExecutionError::MissingBlobParams)?,
            )
        } else {
            None
        };
        Ok(())
    }
}

/// Expected header values used to **validate** a block after execution.
///
/// Deliberately kept separate from [`BlockEnv`] (the execution *input*): these are the *outputs*
/// a valid block must reproduce. Post-execution validation compares the computed roots and sums
/// against these fields.
///
/// `Option` fields are `None` before the hardfork that introduced them, so a single struct
/// describes blocks from any supported fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedHeader {
    /// Total gas used by the block (`header.gasUsed`).
    pub gas_used: u64,
    /// Post-execution world state root (`header.stateRoot`).
    pub state_root: H256,
    /// Receipts trie root (`header.receiptsRoot`).
    pub receipts_root: H256,
    /// Block logs bloom (`header.logsBloom`).
    pub logs_bloom: Bloom,
    /// EIP-7685 requests hash (`header.requestsHash`); `Some` from Prague onward.
    pub requests_hash: Option<H256>,
    /// Total blob gas used (`header.blobGasUsed`); `Some` from Cancun onward.
    pub blob_gas_used: Option<u64>,
    /// Withdrawals trie root (`header.withdrawalsRoot`); `Some` from Shanghai onward.
    pub withdrawals_root: Option<H256>,
    /// Transactions trie root (`header.transactionsRoot`).
    pub transactions_root: H256,
}

#[cfg(test)]
mod tests {
    use super::ExpectedHeader;
    use crate::bloom::Bloom;
    use primitive_types::H256;

    fn sample_expected_header() -> ExpectedHeader {
        ExpectedHeader {
            gas_used: 21_000,
            state_root: H256::repeat_byte(0x11),
            receipts_root: H256::repeat_byte(0x22),
            logs_bloom: Bloom::zero(),
            requests_hash: Some(H256::repeat_byte(0x33)),
            blob_gas_used: Some(0),
            withdrawals_root: Some(H256::repeat_byte(0x44)),
            transactions_root: H256::repeat_byte(0x55),
        }
    }

    #[test]
    fn expected_header_eq_detects_field_changes() {
        let header = sample_expected_header();
        let same = sample_expected_header();
        assert_eq!(header, same);

        let mut different_gas = sample_expected_header();
        different_gas.gas_used = 21_001;
        assert_ne!(header, different_gas);

        // A difference anywhere in the 256-byte logs bloom must be detected.
        let mut bloom = Bloom::zero();
        bloom.accrue(b"topic");
        let mut different_bloom = sample_expected_header();
        different_bloom.logs_bloom = bloom;
        assert_ne!(header, different_bloom);
    }

    #[test]
    fn expected_header_optional_fields_reflect_forks() {
        // A pre-Shanghai header carries none of the later optional roots/sums.
        let pre = ExpectedHeader {
            gas_used: 0,
            state_root: H256::zero(),
            receipts_root: H256::zero(),
            logs_bloom: Bloom::zero(),
            requests_hash: None,
            blob_gas_used: None,
            withdrawals_root: None,
            transactions_root: H256::zero(),
        };
        assert!(pre.requests_hash.is_none());
        assert!(pre.blob_gas_used.is_none());
        assert!(pre.withdrawals_root.is_none());

        // A Prague header carries all of them.
        let prague = sample_expected_header();
        assert!(prague.requests_hash.is_some());
        assert!(prague.blob_gas_used.is_some());
        assert!(prague.withdrawals_root.is_some());
    }
}
