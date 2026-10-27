use super::{code_hash_of, Apply, ApplyBackend, Backend, Basic, Log, KECCAK_EMPTY};
use crate::core::utils::{U256_ONE, U256_ZERO};
use crate::prelude::*;
use primitive_types::{H160, H256, U256};

/// Vicinity value of a memory backend.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "with-codec",
    derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemoryVicinity {
    /// Gas price.
    pub gas_price: U256,
    /// Effective gas price.
    pub effective_gas_price: U256,
    /// Origin.
    pub origin: H160,
    /// Chain ID.
    pub chain_id: U256,
    /// Environmental block hashes.
    pub block_hashes: Vec<H256>,
    /// Environmental block number.
    pub block_number: U256,
    /// Environmental coinbase.
    pub block_coinbase: H160,
    /// Environmental block timestamp.
    pub block_timestamp: U256,
    /// Environmental block difficulty.
    pub block_difficulty: U256,
    /// Environmental block gas limit.
    pub block_gas_limit: U256,
    /// Environmental base fee per gas.
    ///
    pub block_base_fee_per_gas: U256,
    /// Environmental randomness.
    ///
    /// In Ethereum, this is the randomness beacon provided by the beacon
    /// chain and is only enabled post Merge.
    pub block_randomness: Option<H256>,
    /// EIP-4844
    pub blob_gas_price: Option<u128>,
    /// EIP-4844
    pub blob_hashes: Vec<U256>,
}

/// Account information of a memory backend.
#[derive(Default, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "with-codec",
    derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemoryAccount {
    /// Account nonce.
    pub nonce: U256,
    /// Account balance.
    pub balance: U256,
    /// Full account storage.
    pub storage: BTreeMap<H256, H256>,
    /// Account code.
    pub code: Vec<u8>,
}

/// Memory backend, storing all state values in a `BTreeMap` in memory.
#[derive(Clone, Debug)]
pub struct MemoryBackend<'vicinity> {
    vicinity: &'vicinity MemoryVicinity,
    state: BTreeMap<H160, MemoryAccount>,
    logs: Vec<Log>,
}

impl<'vicinity> MemoryBackend<'vicinity> {
    /// Create a new memory backend.
    #[must_use]
    pub const fn new(
        vicinity: &'vicinity MemoryVicinity,
        state: BTreeMap<H160, MemoryAccount>,
    ) -> Self {
        Self {
            vicinity,
            state,
            logs: Vec::new(),
        }
    }

    /// Get the underlying `BTreeMap` storing the state.
    #[must_use]
    pub const fn state(&self) -> &BTreeMap<H160, MemoryAccount> {
        &self.state
    }

    /// Get a mutable reference to the underlying `BTreeMap` storing the state.
    pub const fn state_mut(&mut self) -> &mut BTreeMap<H160, MemoryAccount> {
        &mut self.state
    }
}

impl Backend for MemoryBackend<'_> {
    #[allow(clippy::misnamed_getters)]
    fn gas_price(&self) -> U256 {
        self.vicinity.effective_gas_price
    }
    fn origin(&self) -> H160 {
        self.vicinity.origin
    }
    fn block_hash(&self, number: U256) -> H256 {
        if number >= self.vicinity.block_number
            || self.vicinity.block_number - number - U256_ONE
                >= U256::from(self.vicinity.block_hashes.len())
        {
            H256::default()
        } else {
            let index = (self.vicinity.block_number - number - U256_ONE).as_usize();
            self.vicinity.block_hashes[index]
        }
    }
    fn block_number(&self) -> U256 {
        self.vicinity.block_number
    }
    fn block_coinbase(&self) -> H160 {
        self.vicinity.block_coinbase
    }
    fn block_timestamp(&self) -> U256 {
        self.vicinity.block_timestamp
    }
    fn block_difficulty(&self) -> U256 {
        self.vicinity.block_difficulty
    }
    fn block_randomness(&self) -> Option<H256> {
        self.vicinity.block_randomness
    }
    fn block_gas_limit(&self) -> U256 {
        self.vicinity.block_gas_limit
    }
    fn block_base_fee_per_gas(&self) -> U256 {
        self.vicinity.block_base_fee_per_gas
    }

    fn chain_id(&self) -> U256 {
        self.vicinity.chain_id
    }

    fn exists(&self, address: H160) -> bool {
        self.state.contains_key(&address)
    }

    fn basic(&self, address: H160) -> Basic {
        self.state
            .get(&address)
            .map(|a| Basic {
                balance: a.balance,
                nonce: a.nonce,
            })
            .unwrap_or_default()
    }

    fn code(&self, address: H160) -> Vec<u8> {
        self.state
            .get(&address)
            .map(|v| v.code.clone())
            .unwrap_or_default()
    }

    fn code_hash(&self, address: H160) -> H256 {
        self.state
            .get(&address)
            .map_or(KECCAK_EMPTY, |v| code_hash_of(&v.code))
    }

    fn has_code(&self, address: H160) -> bool {
        self.state.get(&address).is_some_and(|v| !v.code.is_empty())
    }

    fn storage(&self, address: H160, index: H256) -> H256 {
        self.state
            .get(&address)
            .map(|v| v.storage.get(&index).copied().unwrap_or_default())
            .unwrap_or_default()
    }

    fn is_empty_storage(&self, address: H160) -> bool {
        self.state
            .get(&address)
            .is_none_or(|v| v.storage.is_empty())
    }

    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
        Some(self.storage(address, index))
    }
    fn blob_gas_price(&self) -> Option<u128> {
        self.vicinity.blob_gas_price
    }
    fn get_blob_hash(&self, index: usize) -> Option<U256> {
        self.vicinity.blob_hashes.get(index).copied()
    }
}

impl ApplyBackend for MemoryBackend<'_> {
    fn apply<A, I, L>(&mut self, values: A, logs: L, delete_empty: bool)
    where
        A: IntoIterator<Item = Apply<I>>,
        I: IntoIterator<Item = (H256, H256)>,
        L: IntoIterator<Item = Log>,
    {
        for apply in values {
            match apply {
                Apply::Modify {
                    address,
                    basic,
                    code,
                    storage,
                    reset_storage,
                } => {
                    let is_empty = {
                        let account = self.state.entry(address).or_default();
                        account.balance = basic.balance;
                        account.nonce = basic.nonce;
                        if let Some(code) = code {
                            account.code = code;
                        }

                        if reset_storage {
                            account.storage = BTreeMap::new();
                        }

                        let zeros = account
                            .storage
                            .iter()
                            .filter(|(_, v)| v == &&H256::default())
                            .map(|(k, _)| *k)
                            .collect::<Vec<H256>>();

                        for zero in zeros {
                            account.storage.remove(&zero);
                        }

                        for (index, value) in storage {
                            if value == H256::default() {
                                account.storage.remove(&index);
                            } else {
                                account.storage.insert(index, value);
                            }
                        }

                        account.balance == U256_ZERO
                            && account.nonce == U256_ZERO
                            && account.code.is_empty()
                    };

                    if is_empty && delete_empty {
                        self.state.remove(&address);
                    }
                }
                Apply::Delete { address } => {
                    self.state.remove(&address);
                }
            }
        }

        for log in logs {
            self.logs.push(log);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vicinity() -> MemoryVicinity {
        MemoryVicinity {
            gas_price: U256::zero(),
            effective_gas_price: U256::zero(),
            origin: H160::zero(),
            chain_id: U256::one(),
            block_hashes: Vec::new(),
            block_number: U256::zero(),
            block_coinbase: H160::zero(),
            block_timestamp: U256::zero(),
            block_difficulty: U256::zero(),
            block_randomness: None,
            block_gas_limit: U256::zero(),
            block_base_fee_per_gas: U256::zero(),
            blob_gas_price: None,
            blob_hashes: Vec::new(),
        }
    }

    fn account(balance: u64, nonce: u64, code: Vec<u8>) -> MemoryAccount {
        MemoryAccount {
            balance: U256::from(balance),
            nonce: U256::from(nonce),
            storage: BTreeMap::new(),
            code,
        }
    }

    /// `has_code` is `code_hash != KECCAK_EMPTY`, and `code_hash` is the hash of `code`.
    fn assert_code_invariants(backend: &MemoryBackend<'_>, address: H160) {
        let code_hash = backend.code_hash(address);
        assert_eq!(code_hash, code_hash_of(&backend.code(address)));
        assert_eq!(backend.has_code(address), code_hash != KECCAK_EMPTY);
    }

    #[test]
    fn code_hash_and_has_code_follow_the_stored_code() {
        let eoa = H160::from_low_u64_be(1);
        let contract = H160::from_low_u64_be(2);
        let absent = H160::from_low_u64_be(3);
        let code = vec![0x60, 0x01, 0x00];
        let vicinity = vicinity();
        let backend = MemoryBackend::new(
            &vicinity,
            BTreeMap::from([
                (eoa, account(1, 0, Vec::new())),
                (contract, account(0, 1, code.clone())),
            ]),
        );

        assert_eq!(backend.code_hash(eoa), KECCAK_EMPTY);
        assert!(!backend.has_code(eoa));
        assert_eq!(backend.code_hash(absent), KECCAK_EMPTY);
        assert!(!backend.has_code(absent));
        assert_eq!(backend.code_hash(contract), code_hash_of(&code));
        assert!(backend.has_code(contract));
        for address in [eoa, contract, absent] {
            assert_code_invariants(&backend, address);
        }
    }

    #[test]
    fn applied_code_changes_the_code_hash() {
        let address = H160::from_low_u64_be(1);
        let code = vec![0x60, 0x01, 0x00];
        let vicinity = vicinity();
        let mut backend = MemoryBackend::new(&vicinity, BTreeMap::new());
        let modify = |code: Option<Vec<u8>>| {
            vec![Apply::Modify {
                address,
                basic: Basic {
                    balance: U256::zero(),
                    nonce: U256::one(),
                },
                code,
                storage: Vec::<(H256, H256)>::new(),
                reset_storage: false,
            }]
        };

        backend.apply(modify(Some(code.clone())), Vec::<Log>::new(), true);
        assert_eq!(backend.code_hash(address), code_hash_of(&code));
        assert!(backend.has_code(address));
        assert_code_invariants(&backend, address);

        // `None` leaves the code unchanged.
        backend.apply(modify(None), Vec::<Log>::new(), true);
        assert_eq!(backend.code_hash(address), code_hash_of(&code));
        assert!(backend.has_code(address));

        backend.apply(modify(Some(Vec::new())), Vec::<Log>::new(), true);
        assert_eq!(backend.code_hash(address), KECCAK_EMPTY);
        assert!(!backend.has_code(address));
        assert_code_invariants(&backend, address);

        backend.apply(
            vec![Apply::<Vec<(H256, H256)>>::Delete { address }],
            Vec::<Log>::new(),
            true,
        );
        assert!(!backend.exists(address));
        assert_eq!(backend.code_hash(address), KECCAK_EMPTY);
        assert!(!backend.has_code(address));
    }
}
