//! EIP-2930 access-list types and execution projection.

use core::ops::Deref;
use primitive_types::{H160, H256};

/// An account and its storage keys to warm before execution.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AccessListItem {
    /// Account address to warm.
    pub address: H160,
    /// Storage keys to warm for the account.
    pub storage_keys: Vec<H256>,
}

/// An EIP-2930 access list.
#[derive(Debug, Clone, Eq, PartialEq)]
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
    /// Returns an iterator over the list's addresses and storage keys.
    pub fn flatten(&self) -> impl Iterator<Item = (H160, Vec<H256>)> + '_ {
        self.0
            .iter()
            .map(|item| (item.address, item.storage_keys.clone()))
    }

    /// Consumes the type and returns an iterator over the list's addresses and storage keys.
    pub fn into_flatten(self) -> impl Iterator<Item = (H160, Vec<H256>)> {
        self.0
            .into_iter()
            .map(|item| (item.address, item.storage_keys.into_iter().collect()))
    }

    /// Clones the list into the tuple form expected by Aurora EVM.
    #[must_use]
    pub fn flattened(&self) -> Vec<(H160, Vec<H256>)> {
        self.flatten().collect()
    }

    /// Converts the list into the tuple form expected by Aurora EVM.
    #[must_use]
    pub fn into_flattened(self) -> Vec<(H160, Vec<H256>)> {
        self.into_flatten().collect()
    }
}
