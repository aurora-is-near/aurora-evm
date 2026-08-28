//! Merkle-Patricia trie roots and account trie encoding.
//!
//! Roots are computed as pure functions via the `triehash` crate (the standard Ethereum
//! keccak/RLP Merkle-Patricia trie), i.e. one pass without building a persistent trie.

use crate::crypto::keccak256;
use aurora_evm::backend::MemoryAccount;
use hash_db::Hasher;
use plain_hasher::PlainHasher;
use std::collections::BTreeMap;

use primitive_types::{H160, H256, U256};

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
#[must_use]
pub fn ordered_trie_root<I, V>(items: I) -> H256
where
    I: IntoIterator<Item = V>,
    V: AsRef<[u8]>,
{
    triehash::ordered_trie_root::<KeccakHasher, _>(items)
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

#[cfg(test)]
mod tests {
    use super::{
        KeccakHasher, TrieAccount, ordered_trie_root, state_root, storage_root, trie_account,
    };
    use crate::constants::{EMPTY_ROOT_HASH, KECCAK_EMPTY};
    use crate::crypto::keccak256;
    use aurora_evm::backend::MemoryAccount;
    use hash_db::Hasher;
    use hex_literal::hex;
    use primitive_types::{H160, H256, U256};
    use std::collections::BTreeMap;

    /// The hard-coded `EMPTY_ROOT_HASH` is the canonical empty MPT root and equals
    /// `keccak256(rlp("")) == keccak256(0x80)` — a non-tautological external anchor.
    #[test]
    fn empty_root_constant_is_keccak_of_rlp_empty() {
        assert_eq!(EMPTY_ROOT_HASH, keccak256(&[0x80]));
    }

    #[test]
    fn keccak_hasher_matches_keccak256() {
        // The `triehash` driver hashes nodes through `KeccakHasher`; it must equal `keccak256`.
        assert_eq!(<KeccakHasher as Hasher>::hash(b"abc"), keccak256(b"abc"));
        assert_eq!(<KeccakHasher as Hasher>::hash(&[]), keccak256(&[]));
    }

    #[test]
    fn empty_roots_match_constant() {
        let no_items: Vec<Vec<u8>> = Vec::new();
        assert_eq!(ordered_trie_root(no_items), EMPTY_ROOT_HASH);
        assert_eq!(
            state_root(&BTreeMap::<H160, MemoryAccount>::new()),
            EMPTY_ROOT_HASH
        );
        assert_eq!(storage_root(&BTreeMap::new()), EMPTY_ROOT_HASH);
    }

    #[test]
    fn empty_account_derives_empty_hashes() {
        let ta = trie_account(&MemoryAccount::default());
        assert_eq!(ta.code_hash, KECCAK_EMPTY);
        assert_eq!(ta.storage_root, EMPTY_ROOT_HASH);
    }

    fn sample_account() -> MemoryAccount {
        let mut acc = MemoryAccount {
            nonce: U256::one(),
            balance: U256::from(1_000u64),
            storage: BTreeMap::new(),
            code: vec![0x60, 0x00],
        };
        acc.storage
            .insert(H256::from_low_u64_be(1), H256::from_low_u64_be(42));
        acc
    }

    #[test]
    fn state_root_is_deterministic_and_nonempty() {
        let mut accounts: BTreeMap<H160, MemoryAccount> = BTreeMap::new();
        accounts.insert(H160::repeat_byte(0x11), sample_account());
        let root = state_root(&accounts);
        assert_eq!(root, state_root(&accounts));
        assert_ne!(root, EMPTY_ROOT_HASH);
    }

    #[test]
    fn state_root_ignores_empty_accounts() {
        // An EIP-161 empty account must not affect the root (it is not part of the trie).
        let mut with_empty: BTreeMap<H160, MemoryAccount> = BTreeMap::new();
        with_empty.insert(H160::repeat_byte(0x11), sample_account());
        with_empty.insert(H160::repeat_byte(0x22), MemoryAccount::default());
        let mut without: BTreeMap<H160, MemoryAccount> = BTreeMap::new();
        without.insert(H160::repeat_byte(0x11), sample_account());
        assert_eq!(state_root(&with_empty), state_root(&without));
    }

    #[test]
    fn storage_root_skips_zero_slots() {
        // A slot set to zero is not part of the trie, so it must not change the root.
        let mut with_zero = BTreeMap::new();
        with_zero.insert(H256::from_low_u64_be(1), H256::from_low_u64_be(42));
        with_zero.insert(H256::from_low_u64_be(2), H256::zero());
        let mut without = BTreeMap::new();
        without.insert(H256::from_low_u64_be(1), H256::from_low_u64_be(42));
        assert_eq!(storage_root(&with_zero), storage_root(&without));
    }

    #[test]
    fn trie_account_rlp_roundtrip_short() {
        let ta = trie_account(&sample_account());
        let encoded = rlp::encode(&ta);
        assert_eq!(rlp::Rlp::new(&encoded).item_count().unwrap(), 4);
        let decoded: TrieAccount = rlp::decode(&encoded).unwrap();
        assert_eq!(decoded, ta);
    }

    #[test]
    fn trie_account_rlp_roundtrip_long_when_code_version_set() {
        let ta = TrieAccount {
            nonce: U256::from(7u64),
            balance: U256::from(8u64),
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
            code_version: U256::one(),
        };
        let encoded = rlp::encode(&ta);
        assert_eq!(rlp::Rlp::new(&encoded).item_count().unwrap(), 5);
        let decoded: TrieAccount = rlp::decode(&encoded).unwrap();
        assert_eq!(decoded, ta);
    }

    #[test]
    fn empty_account_rlp_exact_bytes() {
        // Known-answer byte vector: [nonce=0, balance=0, storage_root=EMPTY, code_hash=KECCAK_EMPTY].
        // 0xf8 0x44 (list, 68 bytes) | 0x80 0x80 | 0xa0 <32> | 0xa0 <32>.
        let ta = TrieAccount {
            nonce: U256::zero(),
            balance: U256::zero(),
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
            code_version: U256::zero(),
        };
        let mut expected = vec![0xf8, 0x44, 0x80, 0x80, 0xa0];
        expected.extend_from_slice(EMPTY_ROOT_HASH.as_bytes());
        expected.push(0xa0);
        expected.extend_from_slice(KECCAK_EMPTY.as_bytes());
        assert_eq!(rlp::encode(&ta).to_vec(), expected);
    }

    #[test]
    fn receipts_root_of_empty_list_is_empty_root() {
        let items: Vec<Vec<u8>> = Vec::new();
        assert_eq!(ordered_trie_root(items), EMPTY_ROOT_HASH);
    }

    /// Two successful, log-free legacy receipts from EEST's Cancun `tstore_clear_after_tx` block.
    fn eest_legacy_receipt(cumulative_gas_used: [u8; 2]) -> Vec<u8> {
        let mut receipt = vec![0xf9, 0x01, 0x08, 0x01, 0x82];
        receipt.extend_from_slice(&cumulative_gas_used);
        receipt.extend_from_slice(&[0xb9, 0x01, 0x00]);
        receipt.extend_from_slice(&[0; 256]);
        receipt.push(0xc0);
        receipt
    }

    #[test]
    fn ordered_root_matches_a_multi_receipt_eest_block() {
        let receipts = [
            eest_legacy_receipt([0x5b, 0x74]),
            eest_legacy_receipt([0xb6, 0xe8]),
        ];

        assert_eq!(
            ordered_trie_root(receipts),
            H256(hex!(
                "8f668f8b9d0cafee86ca26ba619eda34bef9f00e8694ee97efa8d363bda58fe3"
            ))
        );
    }

    #[test]
    fn secure_root_matches_the_ethereum_trie_vector() {
        // Final key/value set of TrieTests/trietest_secureTrie.json::emptyValues after deletions.
        let entries: [(&[u8], &[u8]); 4] = [
            (b"do", b"verb"),
            (b"horse", b"stallion"),
            (b"doge", b"coin"),
            (b"dog", b"puppy"),
        ];

        assert_eq!(
            super::sec_trie_root(entries),
            H256(hex!(
                "29b235a58c3c25ab83010c327d5932bcf05324b7d6b1185e650798034783ca9d"
            ))
        );
    }
}
