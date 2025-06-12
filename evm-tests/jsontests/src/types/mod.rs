use crate::types::json_utils::{
    deserialize_btree_u256_u256_from_str_opt, deserialize_bytes_from_str,
    deserialize_bytes_from_str_opt, deserialize_h160_from_str, deserialize_h160_from_str_opt,
    deserialize_h256_from_u256_str, deserialize_h256_from_u256_str_opt, deserialize_u256_from_str,
    deserialize_u256_from_str_opt, deserialize_u64_from_str_opt, deserialize_u8_from_str_opt,
    deserialize_vec_h256_from_str, deserialize_vec_of_hex, deserialize_vec_u256_from_str,
    h160_from_str, strip_0x_prefix,
};
use primitive_types::{H160, H256, U256};
use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;

mod info;
mod json_utils;
pub mod spec;
mod vm;

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
    pub post_states: BTreeMap<spec::Spec, Vec<PostState>>,

    /// The transaction(s) to be executed in the test case.
    /// Can represent different transaction types across forks.
    pub transaction: Transaction,

    #[serde(default)]
    #[serde(deserialize_with = "deserialize_bytes_from_str_opt")]
    pub out: Option<Vec<u8>>,

    /// Additional information or metadata about the state test.
    #[serde(rename = "_info")]
    pub info: info::Info,
}

/// Represents the environment parameters under which a state test is executed.
/// These parameters typically correspond to the fields of a block header.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

/// `PreState` represents a sorted mapping from Ethereum account addresses (`H160`) to their
/// corresponding state (`StateAccount`).
/// Represents vis `AccountsState`.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
pub struct PreState(AccountsState);

/// `AccountsState` represents a sorted mapping from Ethereum account addresses (`H160`) to their
/// corresponding state (`StateAccount`).
/// It uses a `BTreeMap` to ensure a consistent order for serialization.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct AccountsState(BTreeMap<H160, StateAccount>);

impl<'de> Deserialize<'de> for AccountsState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map: BTreeMap<String, StateAccount> = Deserialize::deserialize(deserializer)?;
        let mut inner = BTreeMap::new();
        for (k, v) in map {
            let address = h160_from_str::<D>(strip_0x_prefix(&k))?;
            inner.insert(address, v);
        }
        Ok(Self(inner))
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

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateAccount {
    /// Account Nonce.
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub nonce: U256,
    /// Account Balance.
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub balance: U256,
    /// Account Code.
    #[serde(default, deserialize_with = "deserialize_bytes_from_str_opt")]
    pub code: Option<Vec<u8>>,
    /// Account Storage.
    #[serde(default, deserialize_with = "deserialize_btree_u256_u256_from_str_opt")]
    pub storage: Option<BTreeMap<U256, U256>>,
}

/// Post State indexes.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
pub struct PostStateIndexes {
    /// Index into transaction data set.
    pub data: u64,
    /// Index into transaction gas limit set.
    pub gas: u64,
    /// Index into transaction value set.
    pub value: u64,
}

/// Transaction data.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    #[serde(
        default,
        rename = "type",
        deserialize_with = "deserialize_u8_from_str_opt"
    )]
    pub tx_type: Option<u8>,
    #[serde(deserialize_with = "deserialize_vec_of_hex")]
    pub data: Vec<Vec<u8>>,
    #[serde(deserialize_with = "deserialize_vec_u256_from_str")]
    pub gas_limit: Vec<U256>,
    #[serde(default, deserialize_with = "deserialize_u256_from_str_opt")]
    pub gas_price: Option<U256>,
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub nonce: U256,
    #[serde(default, deserialize_with = "deserialize_h256_from_u256_str_opt")]
    pub secret_key: Option<H256>,
    #[serde(default, deserialize_with = "deserialize_h160_from_str_opt")]
    pub sender: Option<H160>,
    #[serde(default, deserialize_with = "deserialize_h160_from_str_opt")]
    pub to: Option<H160>,
    #[serde(deserialize_with = "deserialize_vec_u256_from_str")]
    pub value: Vec<U256>,
    /// for details on `maxFeePerGas` see EIP-1559
    #[serde(default, deserialize_with = "deserialize_u256_from_str_opt")]
    pub max_fee_per_gas: Option<U256>,
    /// for details on `maxPriorityFeePerGas` see EIP-1559
    #[serde(default, deserialize_with = "deserialize_u256_from_str_opt")]
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(
        default,
        rename = "initcodes",
        deserialize_with = "deserialize_bytes_from_str_opt"
    )]
    pub init_codes: Option<Vec<u8>>,

    /// EIP-2930
    #[serde(default)]
    pub access_lists: Vec<Option<AccessList>>,

    /// EIP-4844
    #[serde(default, deserialize_with = "deserialize_vec_h256_from_str")]
    pub blob_versioned_hashes: Vec<H256>,
    /// EIP-4844
    #[serde(default, deserialize_with = "deserialize_u256_from_str_opt")]
    pub max_fee_per_blob_gas: Option<U256>,
    /// EIP-7702
    #[serde(default)]
    pub authorization_list: Option<AuthorizationList>,
}

/// Type alias for access lists (see EIP-2930)
pub type AccessList = Vec<AccessListTuple>;

/// Access list tuple (see <https://eips.ethereum.org/EIPS/eip-2930>).
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListTuple {
    /// Address to access
    #[serde(deserialize_with = "deserialize_h160_from_str")]
    pub address: H160,
    /// Keys (slots) to access at that address
    pub storage_keys: Vec<H256>,
}

/// EIP-7702 Authorization List
pub type AuthorizationList = Vec<AuthorizationItem>;
/// EIP-7702 Authorization item
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationItem {
    /// Chain ID
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub chain_id: U256,
    /// Address to access
    #[serde(deserialize_with = "deserialize_h160_from_str")]
    pub address: H160,
    /// Keys (slots) to access at that address
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub nonce: U256,
    /// r signature
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub r: U256,
    /// s signature
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub s: U256,
    /// Parity
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub v: U256,
    /// Signer address
    #[serde(default, deserialize_with = "deserialize_h160_from_str_opt")]
    pub signer: Option<H160>,
}
