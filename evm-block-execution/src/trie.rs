//! Merkle-Patricia trie roots and account trie encoding.
//!
//! Ordered roots use the known RLP-index key shape; secure state/storage roots use `triehash`.

use crate::crypto::keccak256;
use aurora_evm::backend::MemoryAccount;
use hash_db::Hasher;
use plain_hasher::PlainHasher;
use std::collections::BTreeMap;

use primitive_types::{H160, H256, U256};

#[cfg(test)]
mod tests;

/// Ethereum account as encoded in the state trie.
///
/// Encoded as a four-item list `[nonce, balance, storage_root, code_hash]` while
/// `code_version == 0` (current mainnet); a fifth item is appended otherwise.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrieAccount {
    /// Account nonce.
    pub nonce: U256,
    /// Account balance.
    pub balance: U256,
    /// Root of the account storage trie.
    pub storage_root: H256,
    /// Hash of the account code (`keccak256("")` for an empty account).
    pub code_hash: H256,
    /// Code version (always zero on mainnet).
    pub code_version: U256,
}

impl rlp::Encodable for TrieAccount {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        let short = self.code_version.is_zero();
        stream.begin_list(if short { 4 } else { 5 });
        stream.append(&self.nonce);
        stream.append(&self.balance);
        stream.append(&self.storage_root);
        stream.append(&self.code_hash);
        if !short {
            stream.append(&self.code_version);
        }
    }
}

impl rlp::Decodable for TrieAccount {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let short = match crate::rlp_strict::checked_len(rlp)? {
            4 => true,
            5 => false,
            _ => return Err(rlp::DecoderError::RlpIncorrectListLen),
        };
        Ok(Self {
            nonce: rlp.val_at(0)?,
            balance: rlp.val_at(1)?,
            storage_root: rlp.val_at(2)?,
            code_hash: rlp.val_at(3)?,
            code_version: if short { U256::zero() } else { rlp.val_at(4)? },
        })
    }
}

/// `hash_db::Hasher` over Keccak-256 producing `H256`. Drives `triehash`'s standard Ethereum MPT
/// (RLP-encoded nodes hashed with keccak).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct KeccakHasher;

impl Hasher for KeccakHasher {
    type Out = H256;
    type StdHasher = PlainHasher;
    const LENGTH: usize = 32;

    fn hash(bytes: &[u8]) -> Self::Out {
        keccak256(bytes)
    }
}

/// Ordered trie root over RLP-indexed items (keys are `rlp(index)`).
///
/// Used for `receipts_root`, `transactions_root` and `withdrawals_root`.
/// Borrows an indexed collection; it does not collect an iterator or copy its values.
#[must_use]
pub fn ordered_trie_root<V: AsRef<[u8]>>(items: impl AsRef<[V]>) -> H256 {
    H256(aurora_evm_trie::ordered_trie_root(items.as_ref()))
}

/// Encodes each leaf into one reusable stream; no encoded values are retained by the trie.
pub(crate) fn ordered_trie_root_with_encoder<T, F>(items: &[T], encode: F) -> H256
where
    F: for<'s> FnMut(&T, &'s mut rlp::RlpStream) -> &'s [u8],
{
    H256(aurora_evm_trie::ordered_trie_root_with_encoder(
        items, encode,
    ))
}

/// Receipt commitment, encoding one receipt at a time into reusable scratch.
#[must_use]
pub fn receipts_root(receipts: &[crate::receipt::Receipt]) -> H256 {
    ordered_trie_root_with_encoder(receipts, crate::receipt::Receipt::encode_2718_in)
}

/// Secure (key-hashed) trie root: keys are hashed with keccak before insertion.
///
/// Used for `state_root` and per-account `storage_root`.
#[must_use]
pub fn sec_trie_root<I, K, V>(items: I) -> H256
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    triehash::sec_trie_root::<KeccakHasher, _, _, _>(items)
}

/// Computes the storage trie root for an account's storage map.
///
/// Zero-valued slots are excluded (they are not present in the trie).
#[must_use]
pub fn storage_root(storage: &BTreeMap<H256, H256>) -> H256 {
    sec_trie_root(
        storage
            .iter()
            .filter(|(_, value)| !value.is_zero())
            .map(|(slot, value)| (*slot, rlp::encode(&U256::from_big_endian(value.as_bytes())))),
    )
}

/// Builds the trie representation of an in-memory account, deriving `storage_root` and
/// `code_hash` on the fly.
#[must_use]
pub fn trie_account(account: &MemoryAccount) -> TrieAccount {
    TrieAccount {
        nonce: account.nonce,
        balance: account.balance,
        storage_root: storage_root(&account.storage),
        code_hash: keccak256(&account.code),
        code_version: U256::zero(),
    }
}

/// EIP-161 "empty" account: zero nonce, zero balance and no code. Such accounts are never part
/// of the post-Spurious-Dragon state trie.
const fn is_empty_account(account: &MemoryAccount) -> bool {
    account.nonce.is_zero() && account.balance.is_zero() && account.code.is_empty()
}

/// Computes the canonical Ethereum state root from a fully materialized account map.
///
/// Addresses are secure-trie keys; storage roots and code hashes are derived from each account.
/// EIP-161 empty accounts are omitted. A partial witness must instead update an authenticated sparse
/// trie rooted at the parent state.
#[must_use]
pub fn state_root(accounts: &BTreeMap<H160, MemoryAccount>) -> H256 {
    sec_trie_root(
        accounts
            .iter()
            .filter(|(_, account)| !is_empty_account(account))
            .map(|(address, account)| (*address, rlp::encode(&trie_account(account)))),
    )
}
