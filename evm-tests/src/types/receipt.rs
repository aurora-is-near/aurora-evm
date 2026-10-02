use super::json_utils::{
    IgnoredField, deserialize_bytes_from_str, deserialize_h160_from_str, deserialize_u64_from_str,
    deserialize_vec_h256_from_str,
};
use primitive_types::{H160, H256};
use serde::Deserialize;

/// `post[].receipt`: the receipt of the executed transaction (EEST fixtures from `tests@v20`).
#[derive(Debug, Eq, Ord, PartialOrd, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    /// `true` when the transaction succeeded (EIP-658, from Byzantium on)
    #[serde(default)]
    pub status: Option<bool>,
    /// Intermediate state root of pre-Byzantium receipts, replaced by `status` since EIP-658;
    /// those forks are not executed by the runner
    #[serde(default)]
    pub post_state: Option<IgnoredField>,
    /// Gas used by the transaction (a state test contains a single transaction)
    #[serde(deserialize_with = "deserialize_u64_from_str")]
    pub cumulative_gas_used: u64,
    /// Emitted logs, reported when the `post[].logs` hash does not match
    pub logs: Vec<ReceiptLog>,
    /// Derived from the fields above, not verified
    pub bloom: IgnoredField,
    /// Receipt RLP, derived from the fields above, not verified
    pub rlp: IgnoredField,
    /// Hash of the transaction in `txbytes`, not verified
    pub transaction_hash: IgnoredField,
    /// Transaction type, already derived from `txbytes` by the runner
    #[serde(rename = "type")]
    pub tx_type: IgnoredField,
}

/// A log entry of a receipt.
#[derive(Debug, Eq, Ord, PartialOrd, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptLog {
    /// Emitting contract
    #[serde(deserialize_with = "deserialize_h160_from_str")]
    pub address: H160,
    /// Log topics
    #[serde(deserialize_with = "deserialize_vec_h256_from_str")]
    pub topics: Vec<H256>,
    /// Log data
    #[serde(deserialize_with = "deserialize_bytes_from_str")]
    pub data: Vec<u8>,
}
