use primitive_types::{H160, H256};
use serde::{Deserialize, Serialize};
use std::ops::Deref;

/// A list of addresses and storage keys that the transaction plans to access.
/// Accesses outside the list are possible, but become more expensive.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccessListItem {
    /// Account addresses that would be loaded at the start of execution
    pub address: H160,
    /// Keys of storage that would be loaded at the start of execution
    pub storage_keys: Vec<H256>,
}

/// `AccessList` as defined in EIP-2930
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccessList(pub Vec<AccessListItem>);

impl From<Vec<AccessListItem>> for AccessList {
    fn from(list: Vec<AccessListItem>) -> Self {
        Self(list)
    }
}

impl From<AccessList> for Vec<AccessListItem> {
    fn from(this: AccessList) -> Self {
        this.0
    }
}

impl Deref for AccessList {
    type Target = Vec<AccessListItem>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AccessList {
    /// Converts the list into a Vec tuple
    #[must_use]
    pub fn flattened(&self) -> Vec<(H160, Vec<H256>)> {
        self.flatten().collect()
    }

    /// Consumes the type and converts the list into a vec
    #[must_use]
    pub fn into_flattened(self) -> Vec<(H160, Vec<H256>)> {
        self.into_flatten().collect()
    }

    /// Consumes the type and returns an iterator over the list's addresses and storage keys.
    pub fn into_flatten(self) -> impl Iterator<Item = (H160, Vec<H256>)> {
        self.0
            .into_iter()
            .map(|item| (item.address, item.storage_keys.into_iter().collect()))
    }

    /// Returns an iterator over the list's addresses and storage keys.
    pub fn flatten(&self) -> impl Iterator<Item = (H160, Vec<H256>)> + '_ {
        self.0
            .iter()
            .map(|item| (item.address, item.storage_keys.clone()))
    }
}
