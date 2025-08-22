use self::account_state::AccountsState;
use self::transaction::Transaction;
use crate::types::blob::BlobExcessGasAndPrice;
use crate::types::json_utils::{
    deserialize_bytes_from_str, deserialize_bytes_from_str_opt, deserialize_h160_from_str,
    deserialize_h256_from_u256_str, deserialize_h256_from_u256_str_opt, deserialize_u256_from_str,
    deserialize_u64_from_str_opt,
};
use aurora_evm::backend::MemoryVicinity;
use primitive_types::{H160, H256, U256};
use serde::Deserialize;
use std::collections::BTreeMap;

pub mod account_state;
pub mod blob;
mod ecrecover;
pub mod eip_4844;
pub mod eip_7623;
pub mod eip_7702;
mod info;
mod json_utils;
pub mod spec;
pub mod transaction;
mod vm;

pub use spec::Spec;
pub use vm::VmTestCase;

/// Represents a test case for the Ethereum state transitions.
/// It includes the environment setup, pre-state, transaction details,
/// expected post-state results for different forks, configuration, and metadata.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
pub struct StateTestCase {
    /// The environment parameters for the state test execution.
    /// This includes block-specific information like coinbase address, difficulty, gas limit, etc.
    pub env: StateEnv,

    /// The initial state of accounts before the transaction is executed.
    #[serde(rename = "pre")]
    pub pre_state: PreState,

    /// The expected state of accounts after the transaction execution for various forks.
    /// Maps fork specifications to a list of possible outcomes (results).
    ///
    /// NOTE: field `config` skipped as it is not used in the current context.
    #[serde(rename = "post")]
    pub post_states: BTreeMap<Spec, Vec<PostState>>,

    /// The transaction(s) to be executed in the test case.
    /// Can represent different transaction types across forks.
    pub transaction: Transaction,

    #[serde(default, deserialize_with = "deserialize_bytes_from_str_opt")]
    pub out: Option<Vec<u8>>,

    /// Additional information or metadata about the state test.
    #[serde(rename = "_info")]
    pub info: info::Info,
}

impl StateTestCase {
    /// Get the memory vicinity for the transaction, which includesState test data.
    ///
    /// # Errors
    /// Invalid transaction error status.
    pub fn get_memory_vicinity(
        &self,
        spec: &Spec,
        blob_gas_price: Option<BlobExcessGasAndPrice>,
    ) -> Result<MemoryVicinity, InvalidTxReason> {
        let block_base_fee_per_gas = self.env.block_base_fee_per_gas;
        let tx = &self.transaction;
        // Validation for EIP-1559 that was introduced in London hard fork
        let gas_price = if *spec >= Spec::London {
            tx.gas_price.or(tx.max_fee_per_gas).unwrap_or_default()
        } else {
            if tx.max_fee_per_gas.is_some() {
                return Err(InvalidTxReason::GasPriseEip1559);
            }
            tx.gas_price.expect("expect gas price")
        };

        // EIP-1559: priority fee must be lower than gas_price
        if let Some(max_priority_fee_per_gas) = tx.max_priority_fee_per_gas {
            if max_priority_fee_per_gas > gas_price {
                return Err(InvalidTxReason::PriorityFeeTooLarge);
            }
        }

        let effective_gas_price = self.transaction.max_priority_fee_per_gas.map_or(
            gas_price,
            |max_priority_fee_per_gas| {
                gas_price.min(max_priority_fee_per_gas + block_base_fee_per_gas)
            },
        );

        // gas price cannot be lower than base fee
        if gas_price < block_base_fee_per_gas {
            return Err(InvalidTxReason::GasPriceLessThenBlockBaseFee);
        }

        let blob_hashes = tx.blob_versioned_hashes.clone();

        Ok(MemoryVicinity {
            gas_price,
            effective_gas_price,
            origin: self.transaction.get_caller_from_secret_key(),
            block_hashes: Vec::new(),
            block_number: self.env.block_number,
            block_coinbase: self.env.block_coinbase,
            block_timestamp: self.env.block_timestamp,
            block_difficulty: self.env.block_difficulty,
            block_gas_limit: self.env.block_gas_limit,
            chain_id: U256::one(),
            block_base_fee_per_gas,
            block_randomness: self.env.random,
            blob_gas_price: blob_gas_price.map(|bgp| bgp.blob_gas_price),
            blob_hashes,
        })
    }
}

/// Represents the environment parameters under which a state test is executed.
/// These parameters typically correspond to the fields of a block header.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateEnv {
    /// The difficulty of the current block.
    #[serde(
        rename = "currentDifficulty",
        deserialize_with = "deserialize_u256_from_str"
    )]
    pub block_difficulty: U256,
    /// The address of the beneficiary account (miner) to whom the block rewards are transferred.
    #[serde(
        rename = "currentCoinbase",
        deserialize_with = "deserialize_h160_from_str"
    )]
    pub block_coinbase: H160,
    /// The gas limit for the current block, setting the maximum amount of gas that can be
    /// consumed by transactions in the block.
    #[serde(
        rename = "currentGasLimit",
        deserialize_with = "deserialize_u256_from_str"
    )]
    pub block_gas_limit: U256,
    /// The number of the current block in the blockchain.
    #[serde(
        rename = "currentNumber",
        deserialize_with = "deserialize_u256_from_str"
    )]
    pub block_number: U256,
    /// The timestamp of the current block, typically representing the time when the block was mined.
    #[serde(
        rename = "currentTimestamp",
        deserialize_with = "deserialize_u256_from_str"
    )]
    pub block_timestamp: U256,
    /// The base fee per gas for the current block, as introduced in EIP-1559.
    /// This value adjusts based on network congestion.
    #[serde(
        default,
        rename = "currentBaseFee",
        deserialize_with = "deserialize_u256_from_str"
    )]
    pub block_base_fee_per_gas: U256,
    /// A pre-seeded random value (mix hash) used for testing purposes, particularly relevant
    /// before the Merge (transition to Proof-of-Stake).
    #[serde(
        default,
        rename = "currentRandom",
        deserialize_with = "deserialize_h256_from_u256_str_opt"
    )]
    pub random: Option<H256>,

    /// The amount of blob gas used by the parent block. Relevant for EIP-4844.
    #[serde(default, deserialize_with = "deserialize_u64_from_str_opt")]
    pub parent_blob_gas_used: Option<u64>,
    /// The excess blob gas of the parent block. Relevant for EIP-4844.
    #[serde(default, deserialize_with = "deserialize_u64_from_str_opt")]
    pub parent_excess_blob_gas: Option<u64>,
    /// The excess blob gas for the current block being processed. Relevant for EIP-4844.
    #[serde(default, deserialize_with = "deserialize_u64_from_str_opt")]
    pub current_excess_blob_gas: Option<u64>,
}

impl From<StateEnv> for MemoryVicinity {
    fn from(env: StateEnv) -> Self {
        Self {
            gas_price: U256::zero(),           // Gas price is not used in state tests
            effective_gas_price: U256::zero(), // Effective gas price is not used in state tests
            origin: H160::default(),           // Origin is not used in state tests
            block_hashes: Vec::new(),          // Block hashes are not used in state tests
            block_number: env.block_number,
            block_coinbase: env.block_coinbase,
            block_timestamp: env.block_timestamp,
            block_difficulty: env.block_difficulty,
            block_gas_limit: env.block_gas_limit,
            chain_id: U256::zero(), // Chain ID is not used in state tests
            block_base_fee_per_gas: env.block_base_fee_per_gas,
            block_randomness: env.random,
            blob_gas_price: None,    // Blob gas price is not used in state tests
            blob_hashes: Vec::new(), // Blob hashes are not used in state tests
        }
    }
}

/// `PreState` represents a sorted mapping from Ethereum account addresses (`H160`) to their
/// corresponding state (`StateAccount`).
/// Represents vis `AccountsState`.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
pub struct PreState(AccountsState);

impl AsRef<AccountsState> for PreState {
    fn as_ref(&self) -> &AccountsState {
        &self.0
    }
}

#[derive(Debug, Eq, Ord, PartialOrd, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostState {
    /// Post state hash
    #[serde(deserialize_with = "deserialize_h256_from_u256_str")]
    pub hash: H256,
    /// Post state logs
    #[serde(deserialize_with = "deserialize_h256_from_u256_str")]
    pub logs: H256,
    /// Indexes
    pub indexes: PostStateIndexes,
    /// Expected error if the test is meant to fail
    #[serde(default)]
    pub expect_exception: Option<String>,
    /// Transaction bytes
    #[serde(rename = "txbytes", deserialize_with = "deserialize_bytes_from_str")]
    pub tx_bytes: Vec<u8>,
    /// Output Accounts state
    #[serde(default)]
    pub state: Option<AccountsState>,
    /// Post Accounts state
    #[serde(default)]
    pub post_state: Option<AccountsState>,
}

/// Post State indexes.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
pub struct PostStateIndexes {
    /// Index into transaction data set.
    pub data: usize,
    /// Index into transaction gas limit set.
    pub gas: usize,
    /// Index into transaction value set.
    pub value: usize,
}

#[derive(Debug)]
pub enum InvalidTxReason {
    IntrinsicGas,
    OutOfFund,
    GasLimitReached,
    PriorityFeeTooLarge,
    GasPriceLessThenBlockBaseFee,
    BlobCreateTransaction,
    BlobVersionNotSupported,
    TooManyBlobs,
    EmptyBlobs,
    BlobGasPriceGreaterThanMax,
    BlobVersionedHashesNotSupported,
    MaxFeePerBlobGasNotSupported,
    GasPriseEip1559,
    AuthorizationListNotExist,
    AuthorizationListNotSupported,
    InvalidAuthorizationChain,
    InvalidAuthorizationSignature,
    CreateTransaction,
    GasFloorMoreThanGasLimit,
}
