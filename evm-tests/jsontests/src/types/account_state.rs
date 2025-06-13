use super::json_utils::{
    btree_h256_h256_from_str, deserialize_bytes_from_str_opt, deserialize_u256_from_str,
    h160_from_str, strip_0x_prefix,
};
use aurora_evm::backend::MemoryAccount;
use primitive_types::{H160, H256, U256};
use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    #[serde(default, deserialize_with = "btree_h256_h256_from_str")]
    pub storage: BTreeMap<H256, H256>,
}

impl From<StateAccount> for MemoryAccount {
    fn from(account: StateAccount) -> Self {
        Self {
            nonce: account.nonce,
            balance: account.balance,
            storage: account.storage,
            code: account.code.unwrap_or_default(),
        }
    }
}

/// `AccountsState` represents a sorted mapping from Ethereum account addresses (`H160`) to their
/// corresponding state (`StateAccount`).
/// It uses a `BTreeMap` to ensure a consistent order for serialization.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct AccountsState(BTreeMap<H160, StateAccount>);

impl AccountsState {
    /// Converts the `AccountsState` into a `BTreeMap` of `H160` addresses to `MemoryAccount`.   
    pub fn to_memory_accounts(&self) -> BTreeMap<H160, MemoryAccount> {
        self.0
            .iter()
            .map(|(&address, state_account)| (address, MemoryAccount::from(state_account.clone())))
            .collect()
    }
}

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
