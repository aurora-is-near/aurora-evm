use super::{AccountsState, StateEnv};
use crate::types::json_utils::{
    deserialize_bytes_from_str, deserialize_bytes_from_str_opt, deserialize_h160_from_str,
    deserialize_h160_from_str_opt, deserialize_h256_from_u256_str_opt, deserialize_u256_from_str,
    deserialize_u256_from_str_opt,
};
use aurora_evm::backend::{MemoryAccount, MemoryVicinity};
use primitive_types::{H160, H256, U256};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Represents vm execution environment before and after execution of transaction.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
pub struct VmTestCase {
    /// Contract calls made internally by executed transaction.
    #[serde(rename = "callcreates")]
    pub calls: Option<Vec<Call>>,
    /// Env info.
    pub env: StateEnv,
    /// Executed transaction
    #[serde(rename = "exec")]
    pub transaction: ExecutionTransaction,
    /// Gas left after transaction execution.
    #[serde(
        rename = "gas",
        default,
        deserialize_with = "deserialize_u256_from_str_opt"
    )]
    pub gas_left: Option<U256>,
    /// Hash of logs created during execution of the transaction.
    #[serde(default, deserialize_with = "deserialize_h256_from_u256_str_opt")]
    pub logs: Option<H256>,
    /// Transaction output.
    #[serde(
        default,
        rename = "out",
        deserialize_with = "deserialize_bytes_from_str_opt"
    )]
    pub output: Option<Vec<u8>>,
    /// Post execution vm state.
    #[serde(rename = "post")]
    pub post_state: Option<AccountsState>,
    /// Pre execution vm state.
    #[serde(rename = "pre")]
    pub pre_state: AccountsState,
}

impl VmTestCase {
    #[must_use]
    pub fn get_output(&self) -> Vec<u8> {
        self.output.clone().unwrap()
    }

    #[must_use]
    pub fn get_gas_left(&self) -> u64 {
        self.gas_left.unwrap().as_u64()
    }

    #[must_use]
    pub fn get_gas_limit(&self) -> u64 {
        self.transaction.gas.as_u64()
    }

    #[must_use]
    pub fn validate_state(&self, state: &BTreeMap<H160, MemoryAccount>) -> bool {
        &self
            .post_state
            .clone()
            .unwrap()
            .to_memory_accounts_state()
            .0
            == state
    }

    #[must_use]
    pub const fn get_memory_vicinity(&self) -> MemoryVicinity {
        MemoryVicinity {
            gas_price: self.transaction.gas_price,
            effective_gas_price: self.transaction.gas_price,
            origin: self.transaction.origin,
            block_hashes: Vec::new(),
            block_number: self.env.block_number,
            block_coinbase: self.env.block_coinbase,
            block_timestamp: self.env.block_timestamp,
            block_difficulty: self.env.block_difficulty,
            block_gas_limit: self.env.block_gas_limit,
            chain_id: U256::zero(),
            block_base_fee_per_gas: self.transaction.gas_price,
            block_randomness: self.env.random,
            blob_gas_price: None,
            blob_hashes: Vec::new(),
        }
    }
}

/// Call deserialization.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Call {
    /// Call data.
    #[serde(deserialize_with = "deserialize_bytes_from_str")]
    pub data: Vec<u8>,
    /// Call destination.
    #[serde(default, deserialize_with = "deserialize_h160_from_str_opt")]
    pub destination: Option<H160>,
    /// Gas limit.
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub gas_limit: U256,
    /// Call value.
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub value: U256,
}

/// Executed transaction.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionTransaction {
    /// Contract address.
    #[serde(deserialize_with = "deserialize_h160_from_str")]
    pub address: H160,
    /// Transaction sender.
    #[serde(rename = "caller", deserialize_with = "deserialize_h160_from_str")]
    pub sender: H160,
    /// Contract code.
    #[serde(deserialize_with = "deserialize_bytes_from_str")]
    pub code: Vec<u8>,
    /// Input data.
    #[serde(deserialize_with = "deserialize_bytes_from_str")]
    pub data: Vec<u8>,
    /// Gas.
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub gas: U256,
    /// Gas price.
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub gas_price: U256,
    /// Transaction origin.
    #[serde(deserialize_with = "deserialize_h160_from_str")]
    pub origin: H160,
    /// Sent value.
    #[serde(deserialize_with = "deserialize_u256_from_str")]
    pub value: U256,
    /// Contract code version.
    #[serde(default, deserialize_with = "deserialize_u256_from_str")]
    pub code_version: U256,
}

impl ExecutionTransaction {
    #[must_use]
    pub const fn get_context(&self) -> aurora_evm::Context {
        aurora_evm::Context {
            address: self.address,
            caller: self.sender,
            apparent_value: self.value,
        }
    }
}
