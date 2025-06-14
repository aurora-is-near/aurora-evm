use crate::types::json_utils::{
    deserialize_bytes_from_str_opt, deserialize_h160_from_str, deserialize_h160_from_str_opt,
    deserialize_h256_from_u256_str_opt, deserialize_u256_from_str, deserialize_u256_from_str_opt,
    deserialize_u8_from_str_opt, deserialize_vec_h256_from_str, deserialize_vec_of_hex,
    deserialize_vec_u256_from_str,
};

use primitive_types::{H160, H256, U256};
use serde::Deserialize;

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
