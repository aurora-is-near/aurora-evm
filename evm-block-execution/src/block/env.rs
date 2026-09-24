//! Block-wide execution inputs; transaction fields live in [`crate::transaction::TxEnv`].
//! The witness backend serves `BLOCKHASH` from verified ancestors.

use crate::block::header::Header;
use crate::chain_spec::ActiveSpec;
use crate::errors::{BlockExecutionError, InvalidHeader};
use crate::evm_context::InvalidEvmContext;
use crate::withdrawal::Withdrawal;
use aurora_evm::backend::MemoryVicinity;
use primitive_types::{H160, H256, U256};

/// Excess blob gas and its price, derived once per block.
#[derive(Copy, Clone, Debug, Default, Ord, PartialOrd, PartialEq, Eq)]
pub struct BlobExcessGasAndPrice {
    /// The block's `excess_blob_gas` header field.
    pub excess_blob_gas: u64,
    /// The blob gas price derived from it, per
    /// [`BlobParams::calc_blob_fee`](crate::eips::eip7840::BlobParams::calc_blob_fee).
    pub blob_gas_price: u128,
}

/// Inputs for transactions, system calls, and withdrawals.
/// Fork parameters remain in [`ChainSpec`](crate::chain_spec::ChainSpec);
/// expected execution results remain in the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEnv {
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

impl BlockEnv {
    /// Derives inputs from a validated header using the active blob fee parameters.
    ///
    /// # Errors
    /// [`BlockExecutionError`] if the base fee is missing or the blob gas price overflows.
    pub fn from_block(
        header: &Header,
        withdrawals: Option<Vec<Withdrawal>>,
        active_spec: ActiveSpec,
    ) -> Result<Self, BlockExecutionError> {
        let base_fee = header
            .base_fee_per_gas
            .ok_or(BlockExecutionError::InvalidContext(
                InvalidEvmContext::InvalidHeader(InvalidHeader::BaseFeeNotSet),
            ))?;
        let blob_excess_gas_and_price = header
            .excess_blob_gas
            .map(|excess_blob_gas| {
                active_spec
                    .blob_params()
                    .calc_blob_fee(excess_blob_gas)
                    .map(|blob_gas_price| BlobExcessGasAndPrice {
                        excess_blob_gas,
                        blob_gas_price,
                    })
                    .ok_or(BlockExecutionError::BlobGasPriceOverflow { excess_blob_gas })
            })
            .transpose()?;
        Ok(Self {
            block_number: U256::from(header.number),
            block_coinbase: header.beneficiary,
            block_timestamp: U256::from(header.timestamp),
            block_difficulty: header.difficulty,
            block_gas_limit: header.gas_limit,
            block_base_fee_per_gas: U256::from(base_fee),
            block_randomness: Some(header.mix_hash),
            blob_excess_gas_and_price,
            parent_hash: header.parent_hash,
            parent_beacon_block_root: header.parent_beacon_block_root,
            withdrawals: withdrawals.unwrap_or_default(),
        })
    }

    /// Builds the block environment for `chain_id`.
    /// The executor sets transaction fields before use; `block_hashes` stays empty.
    #[must_use]
    pub fn vicinity(&self, chain_id: u64) -> MemoryVicinity {
        MemoryVicinity {
            gas_price: U256::zero(),
            effective_gas_price: U256::zero(),
            origin: H160::zero(),
            block_hashes: Vec::new(),
            block_number: self.block_number,
            block_coinbase: self.block_coinbase,
            block_timestamp: self.block_timestamp,
            block_difficulty: self.block_difficulty,
            block_gas_limit: U256::from(self.block_gas_limit),
            chain_id: U256::from(chain_id),
            block_base_fee_per_gas: self.block_base_fee_per_gas,
            block_randomness: self.block_randomness,
            blob_gas_price: self
                .blob_excess_gas_and_price
                .map(|blob| blob.blob_gas_price),
            blob_hashes: Vec::new(),
        }
    }
}
