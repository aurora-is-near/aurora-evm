//! Execution inputs derived from a block header, body and ancestor chain.
//!
//! [`BlockEnv`] contains block-wide values read by transactions and system steps. Chain-scheduled
//! parameters remain in the chain configuration, while transaction-specific values remain in
//! [`crate::transaction::TxEnv`].

use crate::withdrawal::Withdrawal;
use primitive_types::{H160, H256, U256};

/// A block's `excess_blob_gas` together with the blob gas price it implies.
///
/// An execution convenience, not an EIP-defined type: the derived price is computed once per block.
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
/// Includes transaction-loop context and inputs consumed by pre/post-execution system steps. Blob
/// versioned hashes stay on [`TxEnv`](crate::transaction::TxEnv), and scheduled
/// [`BlobParams`](crate::eips::eip7840::BlobParams) stay in
/// [`ChainSpec`](crate::chain_spec::ChainSpec). Expected post-execution values are read directly from
/// the header rather than duplicated here.
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
    /// Block gas limit, mandatory so an absent value cannot disable the transaction-loop check.
    pub block_gas_limit: u64,
    /// Environmental base fee per gas.
    pub block_base_fee_per_gas: U256,
    /// Post-merge beacon-chain randomness.
    pub block_randomness: Option<H256>,
    /// Resolved excess blob gas and price while the EIP-4844 blob market is active.
    pub blob_excess_gas_and_price: Option<BlobExcessGasAndPrice>,
    /// Parent hash consumed by the EIP-2935 history-storage system call.
    pub parent_hash: H256,
    /// EIP-4788 parent beacon root; present from Cancun except where the system call is skipped.
    pub parent_beacon_block_root: Option<H256>,
    /// Validator withdrawals credited after the transaction loop (EIP-4895, Shanghai+).
    pub withdrawals: Vec<Withdrawal>,
}
