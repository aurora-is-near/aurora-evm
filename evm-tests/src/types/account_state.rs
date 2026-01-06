use super::json_utils::{
    btree_h256_h256_from_str, deserialize_bytes_from_str_opt, deserialize_u256_from_str,
    h160_from_hex_str, strip_0x_prefix,
};
use aurora_evm::backend::MemoryAccount;
use aurora_evm::executor::stack::Authorization;
use primitive_types::{H160, H256, U256};
use serde::{Deserialize, Deserializer};
use sha3::{Digest, Keccak256};
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
            storage: account
                .storage
                .iter()
                .filter_map(|(k, v)| {
                    if v.is_zero() {
                        // If value is zero then the key is not really there
                        None
                    } else {
                        Some((*k, *v))
                    }
                })
                .collect(),
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
    #[must_use]
    pub fn to_memory_accounts_state(&self) -> MemoryAccountsState {
        MemoryAccountsState(
            self.0
                .iter()
                .map(|(&address, state_account)| {
                    (address, MemoryAccount::from(state_account.clone()))
                })
                .collect(),
        )
    }
}

impl<'de> Deserialize<'de> for AccountsState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map: BTreeMap<String, StateAccount> = Deserialize::deserialize(deserializer)?;
        let mut inner = BTreeMap::new();
        for (k, v) in map {
            let address = h160_from_hex_str::<D>(strip_0x_prefix(&k))?;
            inner.insert(address, v);
        }
        Ok(Self(inner))
    }
}

/// Basic account type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieAccount {
    /// Nonce of the account.
    pub nonce: U256,
    /// Balance of the account.
    pub balance: U256,
    /// Storage root of the account.
    pub storage_root: H256,
    /// Code hash of the account.
    pub code_hash: H256,
    /// Code version of the account.
    pub code_version: U256,
}

impl rlp::Encodable for TrieAccount {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        let use_short_version = self.code_version == U256::zero();

        if use_short_version {
            stream.begin_list(4);
        } else {
            stream.begin_list(5);
        }

        stream.append(&self.nonce);
        stream.append(&self.balance);
        stream.append(&self.storage_root);
        stream.append(&self.code_hash);

        if !use_short_version {
            stream.append(&self.code_version);
        }
    }
}

impl rlp::Decodable for TrieAccount {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let use_short_version = match rlp.item_count()? {
            4 => true,
            5 => false,
            _ => return Err(rlp::DecoderError::RlpIncorrectListLen),
        };

        Ok(Self {
            nonce: rlp.val_at(0)?,
            balance: rlp.val_at(1)?,
            storage_root: rlp.val_at(2)?,
            code_hash: rlp.val_at(3)?,
            code_version: if use_short_version {
                U256::zero()
            } else {
                rlp.val_at(4)?
            },
        })
    }
}

#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct MemoryAccountsState(pub BTreeMap<H160, MemoryAccount>);

impl MemoryAccountsState {
    #[must_use]
    pub fn check_valid_hash(&self, h: &H256) -> (bool, H256) {
        let tree = self
            .0
            .iter()
            .map(|(address, account)| {
                let storage_root = H256(
                    ethereum::util::sec_trie_root(
                        account
                            .storage
                            .iter()
                            .map(|(k, v)| (k, rlp::encode(&U256::from_big_endian(&v[..])))),
                    )
                    .0,
                );
                let code_hash =
                    H256::from_slice(<[u8; 32]>::from(Keccak256::digest(&account.code)).as_slice());

                let account = TrieAccount {
                    nonce: account.nonce,
                    balance: account.balance,
                    storage_root,
                    code_hash,
                    code_version: U256::zero(),
                };
                (address, rlp::encode(&account))
            })
            .collect::<Vec<_>>();

        let root = H256(ethereum::util::sec_trie_root(tree).0);
        let expect = h;
        (root == *expect, root)
    }

    pub fn caller_balance(&self, caller: H160) -> U256 {
        self.0
            .get(&caller)
            .map_or_else(U256::zero, |acc| acc.balance)
    }

    pub fn caller_code(&self, caller: H160) -> Vec<u8> {
        self.0
            .get(&caller)
            .map_or_else(Vec::new, |acc| acc.code.clone())
    }

    #[must_use]
    pub fn is_delegated(&self, caller: H160) -> bool {
        self.0
            .get(&caller)
            .is_some_and(|c| Authorization::is_delegated(&c.code))
    }
}
