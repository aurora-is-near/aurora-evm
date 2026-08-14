use crate::withdrawal::Withdrawal;
use primitive_types::{H160, H256, U256};

/// A block's `excess_blob_gas` together with the blob gas price it implies.
///
/// Not an EIP-defined type — the EIP defines the two quantities and the function between them; this
/// is the execution environment's convenience of carrying the input and the derived price as one
/// value, so the price is computed once per block rather than at every blob transaction.
#[derive(Copy, Clone, Debug, Default, Ord, PartialOrd, PartialEq, Eq)]
pub struct BlobExcessGasAndPrice {
    /// The block's `excess_blob_gas` header field.
    pub excess_blob_gas: u64,
    /// The blob gas price derived from it, per
    /// [`BlobParams::calc_blob_fee`](crate::eips::eip7840::BlobParams::calc_blob_fee).
    pub blob_gas_price: u128,
}

/// Execution **input** environment for a block.
///
/// Blob versioned hashes are deliberately absent: they are a per-*transaction* consensus field
/// ([`TxEnv::blob_versioned_hashes`](crate::transaction::TxEnv)), no block header commits to
/// a block-level list of them, and a field here could only shadow the per-transaction one.
///
/// The active [`BlobParams`](crate::eips::eip7840::BlobParams) are absent for a different reason: they are a
/// property of the *chain*, resolved once from its schedule
/// ([`ChainSpec`](crate::chain_spec::ChainSpec)), and holding them here would leave a `BlockEnv` that
/// looks complete while still waiting for a schedule to be applied to it.
///
/// Holds everything the transaction loop reads (block context, BLOCKHASH window, blob fee) plus
/// the inputs consumed by the pre/post-execution system steps (`parent_hash`,
/// `parent_beacon_block_root`, `withdrawals`). The *expected* header values a valid block must
/// reproduce are compared against the header itself after execution, not mirrored here.
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
