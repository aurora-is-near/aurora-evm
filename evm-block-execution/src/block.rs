use crate::blob::{BlobExcessGasAndPrice, BlobParams};
use crate::bloom::Bloom;
use crate::withdrawal::Withdrawal;
use primitive_types::{H160, H256, U256};

/// Execution **input** environment for a block.
///
/// Holds everything the transaction loop reads (block context, BLOCKHASH window, blob fee) plus
/// the inputs consumed by the pre/post-execution system steps (`parent_hash`,
/// `parent_beacon_block_root`, `withdrawals`). The *expected* header values a valid block must
/// reproduce live separately in [`ExpectedHeader`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// Expected header values used to **validate** a block after execution.
///
/// Deliberately kept separate from [`BlockEnv`] (the execution *input*): these are the *outputs*
/// a valid block must reproduce. Post-execution validation compares the computed roots and sums
/// against these fields.
///
/// `Option` fields are `None` before the hardfork that introduced them, so a single struct
/// describes blocks from any supported fork.
///
/// Note: this type intentionally does not derive `serde`. Its `logs_bloom` is a 256-byte
/// [`Bloom`], and serde has no built-in impl for arrays larger than 32 (that needs
/// `serde-big-array`). Header values are assembled field-by-field by the caller, so serde on the
/// whole struct is not required here.
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
    use super::{BlockEnv, ExpectedHeader};
    use crate::bloom::Bloom;
    use crate::withdrawal::Withdrawal;
    use primitive_types::{H160, H256, U256};

    fn sample_block_env() -> BlockEnv {
        BlockEnv {
            block_hashes: vec![H256::repeat_byte(0x01)],
            block_number: U256::from(42u64),
            block_coinbase: H160::repeat_byte(0xcc),
            block_timestamp: U256::from(1_000u64),
            block_difficulty: U256::zero(),
            block_gas_limit: 30_000_000,
            block_base_fee_per_gas: U256::from(7u64),
            block_randomness: Some(H256::repeat_byte(0x02)),
            blob_excess_gas_and_price: None,
            blob_hashes: vec![],
            blob_params: None,
            parent_hash: H256::repeat_byte(0x03),
            parent_beacon_block_root: Some(H256::repeat_byte(0x04)),
            withdrawals: vec![Withdrawal {
                index: 1,
                validator_index: 2,
                address: H160::repeat_byte(0xab),
                amount: 32,
            }],
        }
    }

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
    fn block_env_serde_roundtrip_with_new_fields() {
        let env = sample_block_env();
        let json = serde_json::to_string(&env).unwrap();
        let back: BlockEnv = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
        // The new fields survive the round-trip.
        assert_eq!(back.parent_hash, H256::repeat_byte(0x03));
        assert_eq!(back.parent_beacon_block_root, Some(H256::repeat_byte(0x04)));
        assert_eq!(back.withdrawals.len(), 1);
        assert_eq!(back.withdrawals[0].amount, 32);
    }

    #[test]
    fn block_env_pre_cancun_serde_roundtrip() {
        // A pre-Cancun block has no beacon root / blob fee and (pre-Shanghai) no withdrawals.
        let mut env = sample_block_env();
        env.parent_beacon_block_root = None;
        env.blob_excess_gas_and_price = None;
        env.withdrawals = vec![];
        let json = serde_json::to_string(&env).unwrap();
        // An absent optional field serializes as JSON `null` (not skipped).
        assert!(json.contains("\"parent_beacon_block_root\":null"));
        let back: BlockEnv = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
        assert!(back.parent_beacon_block_root.is_none());
        assert!(back.withdrawals.is_empty());
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
