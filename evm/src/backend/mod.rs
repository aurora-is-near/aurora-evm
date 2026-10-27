//! # EVM backends
//!
//! Backends store state information of the VM, and exposes it to runtime.
use crate::prelude::*;
use primitive_types::{H160, H256, U256};
use sha3::{Digest, Keccak256};

pub use self::memory::{MemoryAccount, MemoryBackend, MemoryVicinity};

mod memory;

/// `keccak256` of empty code: the code hash of an account without code.
pub const KECCAK_EMPTY: H256 = H256([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

/// `keccak256` of the code bytes.
pub(crate) fn code_hash_of(code: &[u8]) -> H256 {
    H256::from_slice(<[u8; 32]>::from(Keccak256::digest(code)).as_slice())
}

/// Basic account information.
///
#[derive(Clone, Eq, PartialEq, Debug, Default)]
#[cfg_attr(
    feature = "with-codec",
    derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Basic {
    /// Account balance.
    pub balance: U256,
    /// Account nonce.
    pub nonce: U256,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, rlp::RlpEncodable, rlp::RlpDecodable)]
#[cfg_attr(
    feature = "with-codec",
    derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Log {
    pub address: H160,
    pub topics: Vec<H256>,
    pub data: Vec<u8>,
}

/// Apply state operation.
#[derive(Clone, Debug)]
pub enum Apply<I> {
    /// Modify or create at address.
    Modify {
        /// Address.
        address: H160,
        /// Basic information of the address.
        basic: Basic,
        /// Code. `None` means leaving it unchanged.
        code: Option<Vec<u8>>,
        /// Storage iterator.
        storage: I,
        /// Whether storage should be wiped empty before applying the storage
        /// iterator.
        reset_storage: bool,
    },
    /// Delete address.
    Delete {
        /// Address.
        address: H160,
    },
}

/// EVM backend.
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait Backend {
    /// Gas price. Unused for London.
    fn gas_price(&self) -> U256;
    /// Origin.
    fn origin(&self) -> H160;
    /// Environmental block hash.
    fn block_hash(&self, number: U256) -> H256;
    /// Environmental block number.
    fn block_number(&self) -> U256;
    /// Environmental coinbase.
    fn block_coinbase(&self) -> H160;
    /// Environmental block timestamp.
    fn block_timestamp(&self) -> U256;
    /// Environmental block difficulty.
    fn block_difficulty(&self) -> U256;
    /// Get environmental block randomness.
    fn block_randomness(&self) -> Option<H256>;
    /// Environmental block gas limit.
    fn block_gas_limit(&self) -> U256;
    /// Environmental block base fee.
    fn block_base_fee_per_gas(&self) -> U256;
    /// Environmental chain ID.
    fn chain_id(&self) -> U256;

    /// Whether account at address exists.
    fn exists(&self, address: H160) -> bool;
    /// Get basic account information.
    fn basic(&self, address: H160) -> Basic;
    /// Get account code.
    fn code(&self, address: H160) -> Vec<u8>;
    /// Get account code hash: `keccak256` of the code, [`KECCAK_EMPTY`] for an account
    /// without code, including a non-existent one.
    ///
    /// A backend that stores the hash, like a witness, can answer without the code bytes.
    fn code_hash(&self, address: H160) -> H256 {
        code_hash_of(&self.code(address))
    }
    /// Check if the account has code, i.e. its code hash is not [`KECCAK_EMPTY`].
    fn has_code(&self, address: H160) -> bool {
        !self.code(address).is_empty()
    }
    /// Get storage value of address at index.
    fn storage(&self, address: H160, index: H256) -> H256;
    /// Check if the storage of the address is empty.
    fn is_empty_storage(&self, address: H160) -> bool;
    /// Get original storage value of address at index, if available.
    fn original_storage(&self, address: H160, index: H256) -> Option<H256>;
    /// CANCUN hard fork
    /// [EIP-4844]: Shard Blob Transactions
    /// [EIP-7516]: BLOBBASEFEE instruction
    fn blob_gas_price(&self) -> Option<u128>;
    /// Get `blob_hash` from `blob_versioned_hashes` by index
    /// [EIP-4844]: BLOBHASH - <https://eips.ethereum.org/EIPS/eip-4844#opcode-to-get-versioned-hashes>
    fn get_blob_hash(&self, index: usize) -> Option<U256>;
}

/// EVM backend that can apply changes.
pub trait ApplyBackend {
    /// Apply given values and logs at backend.
    fn apply<A, I, L>(&mut self, values: A, logs: L, delete_empty: bool)
    where
        A: IntoIterator<Item = Apply<I>>,
        I: IntoIterator<Item = (H256, H256)>,
        L: IntoIterator<Item = Log>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend with code only, so `code_hash` and `has_code` come from the trait defaults.
    struct CodeOnly(Vec<u8>);

    impl Backend for CodeOnly {
        fn gas_price(&self) -> U256 {
            U256::zero()
        }
        fn origin(&self) -> H160 {
            H160::zero()
        }
        fn block_hash(&self, _: U256) -> H256 {
            H256::zero()
        }
        fn block_number(&self) -> U256 {
            U256::zero()
        }
        fn block_coinbase(&self) -> H160 {
            H160::zero()
        }
        fn block_timestamp(&self) -> U256 {
            U256::zero()
        }
        fn block_difficulty(&self) -> U256 {
            U256::zero()
        }
        fn block_randomness(&self) -> Option<H256> {
            None
        }
        fn block_gas_limit(&self) -> U256 {
            U256::zero()
        }
        fn block_base_fee_per_gas(&self) -> U256 {
            U256::zero()
        }
        fn chain_id(&self) -> U256 {
            U256::zero()
        }
        fn exists(&self, _: H160) -> bool {
            true
        }
        fn basic(&self, _: H160) -> Basic {
            Basic::default()
        }
        fn code(&self, _: H160) -> Vec<u8> {
            self.0.clone()
        }
        fn storage(&self, _: H160, _: H256) -> H256 {
            H256::zero()
        }
        fn is_empty_storage(&self, _: H160) -> bool {
            true
        }
        fn original_storage(&self, _: H160, _: H256) -> Option<H256> {
            None
        }
        fn blob_gas_price(&self) -> Option<u128> {
            None
        }
        fn get_blob_hash(&self, _: usize) -> Option<U256> {
            None
        }
    }

    fn code_hash_of_backend<B: Backend>(backend: B) -> (H256, bool) {
        let address = H160::zero();
        (backend.code_hash(address), backend.has_code(address))
    }

    #[test]
    fn keccak_empty_is_the_hash_of_empty_code() {
        assert_eq!(code_hash_of(&[]), KECCAK_EMPTY);
        assert_ne!(code_hash_of(&[0x00]), KECCAK_EMPTY);
    }

    #[test]
    fn default_code_hash_and_has_code_derive_from_code() {
        assert_eq!(
            code_hash_of_backend(CodeOnly(Vec::new())),
            (KECCAK_EMPTY, false)
        );

        let code = vec![0x60, 0x01, 0x00];
        let (code_hash, has_code) = code_hash_of_backend(CodeOnly(code.clone()));
        assert_eq!(code_hash, code_hash_of(&code));
        assert_ne!(code_hash, KECCAK_EMPTY);
        assert!(has_code);
    }

    #[test]
    fn default_methods_are_forwarded_through_references_and_boxes() {
        let code = vec![0x60, 0x01, 0x00];
        let expected = (code_hash_of(&code), true);
        let contract = CodeOnly(code);
        assert_eq!(code_hash_of_backend(&contract), expected);
        assert_eq!(code_hash_of_backend(Box::new(contract)), expected);
    }
}
