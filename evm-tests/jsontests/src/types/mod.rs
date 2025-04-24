use crate::types::json_utils::{
    deserialize_h160_from_str, deserialize_h256_from_u256_str_opt, deserialize_u256_from_str,
    deserialize_u64_from_str_opt,
};
use primitive_types::{H160, H256, U256};
use serde::{Deserialize, Deserializer};

mod json_utils;

/// Represents a test case for the Ethereum state transitions.
/// It includes the environment setup, pre-state, transaction details,
/// expected post-state results for different forks, configuration, and metadata.

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct StateTestCase {
    /// The environment parameters for the state test execution.
    /// This includes block-specific information like coinbase address, difficulty, gas limit, etc.
    pub env: StateEnv,
    /*
        /// The initial state of accounts before the transaction is executed.
        #[serde(rename = "pre")]
        pub pre_state: AccountState,
        /// The expected state of accounts after the transaction execution for various forks.
        /// Maps fork specifications to a list of possible outcomes (results).
        #[serde(rename = "post")]
        pub post_states: BTreeMap<ForkSpec, Vec<PostStateResult>>,
        /// The transaction(s) to be executed in the test case.
        /// Can represent different transaction types across forks.
        pub transaction: MultiTransaction,
        /// Configuration settings specific to this state test.
        pub config: StateTestConfig,
        /// Additional information or metadata about the state test.
        #[serde(rename = "_info")]
        pub info: StateTestInfo,
    */
}

/// Represents the environment parameters under which a state test is executed.
/// These parameters typically correspond to the fields of a block header.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateEnv {
    /// The address of the beneficiary account (miner) to whom the block rewards are transferred.
    #[serde(
        rename = "currentCoinbase",
        deserialize_with = "deserialize_h160_from_str"
    )]
    pub block_coinbase: H160,
    /// The difficulty of the current block.
    #[serde(
        rename = "currentDifficulty",
        deserialize_with = "deserialize_u256_from_str"
    )]
    pub block_difficulty: U256,
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
        rename = "currentBaseFee",
        default,
        deserialize_with = "deserialize_u256_from_str"
    )]
    pub block_base_fee_per_gas: U256,
    /// A pre-seeded random value (mix hash) used for testing purposes, particularly relevant
    /// before the Merge (transition to Proof-of-Stake).
    #[serde(
        rename = "currentRandom",
        default,
        deserialize_with = "deserialize_h256_from_u256_str_opt"
    )]
    pub random: Option<H256>,

    /// The amount of blob gas used by the parent block. Relevant for EIP-4844.
    #[serde(deserialize_with = "deserialize_u64_from_str_opt")]
    pub parent_blob_gas_used: Option<u64>,
    /// The excess blob gas of the parent block. Relevant for EIP-4844.
    #[serde(deserialize_with = "deserialize_u64_from_str_opt")]
    pub parent_excess_blob_gas: Option<u64>,
    /// The excess blob gas for the current block being processed. Relevant for EIP-4844.
    #[serde(deserialize_with = "deserialize_u64_from_str_opt")]
    pub current_excess_blob_gas: Option<u64>,
}
