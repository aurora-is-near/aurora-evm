use crate::blob::BlobExcessGasAndPrice;
use primitive_types::{H160, H256, U256};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockEnv {
    /// Environmental block hashes.
    pub block_hashes: Vec<H256>,
    /// Environmental block number.
    pub block_number: U256,
    /// Environmental coinbase.
    pub block_coinbase: H160,
    /// Environmental block timestamp.
    pub block_timestamp: U256,
    /// Environmental block difficulty.
    pub block_difficulty: U256,
    /// Environmental block gas limit.
    pub block_gas_limit: Option<u64>,
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
}
