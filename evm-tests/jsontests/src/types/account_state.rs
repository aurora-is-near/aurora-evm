use super::json_utils::{btree_h256_h256_from_str, h160_from_str, strip_0x_prefix, u256_from_str};
use aurora_evm::backend::MemoryAccount;
use primitive_types::{H160, H256, U256};
use serde::{de, Deserialize, Deserializer};
use std::collections::BTreeMap;

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct StateAccount {
    /// Account Nonce.
    pub nonce: U256,
    /// Account Balance.
    pub balance: U256,
    /// Account Code.
    pub code: Option<Vec<u8>>,
    /// Account Storage.
    pub storage: Option<BTreeMap<H256, H256>>,
}

impl From<StateAccount> for MemoryAccount {
    fn from(account: StateAccount) -> Self {
        Self {
            nonce: account.nonce,
            balance: account.balance,
            storage: account.storage.unwrap_or_default(),
            code: account.code.unwrap_or_default(),
        }
    }
}

impl<'de> Deserialize<'de> for StateAccount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct StateAccountHelper {
            nonce: String,
            balance: String,
            #[serde(default)]
            code: Option<String>,
            #[serde(default)]
            storage: Option<BTreeMap<String, String>>,
        }

        let helper = StateAccountHelper::deserialize(deserializer)?;

        let nonce = u256_from_str::<D>(strip_0x_prefix(&helper.nonce))?;
        let balance = u256_from_str::<D>(strip_0x_prefix(&helper.balance))?;
        let code = helper
            .code
            .map(|c| hex::decode(strip_0x_prefix(&c)).map_err(|e| de::Error::custom(e.to_string())))
            .transpose()?;
        let storage = helper
            .storage
            .map(btree_h256_h256_from_str::<D>)
            .transpose()?;

        Ok(Self {
            nonce,
            balance,
            code,
            storage,
        })
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
