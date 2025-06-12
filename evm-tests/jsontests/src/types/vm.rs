use super::StateEnv;
use primitive_types::{H160, H256, U256};

use ethjson::maybe::MaybeEmpty;
use ethjson::spec::State;
use ethjson::uint::Uint;
use serde::Deserialize;

/// Represents vm execution environment before and after execution of transaction.
#[derive(Debug, PartialEq, Deserialize)]
pub struct Vm {
    /// Contract calls made internaly by executed transaction.
    #[serde(rename = "callcreates")]
    pub calls: Option<Vec<Call>>,
    /// Env info.
    pub env: StateEnv,
    /// Executed transaction
    #[serde(rename = "exec")]
    pub transaction: ExecutionTransaction,
    /// Gas left after transaction execution.
    #[serde(rename = "gas")]
    pub gas_left: Option<U256>,
    /// Hash of logs created during execution of transaction.
    pub logs: Option<H256>,
    /// Transaction output.
    #[serde(rename = "out")]
    pub output: Option<Vec<u8>>,
    /// Post execution vm state.
    #[serde(rename = "post")]
    pub post_state: Option<State>,
    /// Pre execution vm state.
    #[serde(rename = "pre")]
    pub pre_state: State,
}

/// Call deserialization.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Call {
    /// Call data.
    pub data: Vec<u8>,
    /// Call destination.
    pub destination: MaybeEmpty<Address>,
    /// Gas limit.
    pub gas_limit: U256,
    /// Call value.
    pub value: U256,
}

/// Executed transaction.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionTransaction {
    /// Contract address.
    pub address: H160,
    /// Transaction sender.
    #[serde(rename = "caller")]
    pub sender: H160,
    /// Contract code.
    pub code: Vec<u8>,
    /// Input data.
    pub data: Vec<u8>,
    /// Gas.
    pub gas: U256,
    /// Gas price.
    pub gas_price: U256,
    /// Transaction origin.
    pub origin: H160,
    /// Sent value.
    pub value: U256,
    /// Contract code version.
    #[serde(default)]
    pub code_version: U256,
}
