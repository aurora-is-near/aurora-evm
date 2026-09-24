//! Tests for ordered, state and storage trie roots and account encoding.

mod ordered_roots;

use super::{KeccakHasher, TrieAccount, ordered_trie_root, state_root, storage_root, trie_account};
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
fn state_root_preserves_empty_accounts_with_or_without_storage() {
    let address = H160::repeat_byte(0x22);
    for storage in [
        BTreeMap::new(),
        BTreeMap::from([(H256::zero(), H256::repeat_byte(1))]),
    ] {
        let account = MemoryAccount {
            storage,
            ..MemoryAccount::default()
        };
        let mut path = vec![0x20];
        path.extend_from_slice(keccak256(address.as_bytes()).as_bytes());
        let mut leaf = rlp::RlpStream::new_list(2);
        leaf.append(&path);
        leaf.append(&rlp::encode(&trie_account(&account)).as_ref());
        let expected = keccak256(&leaf.out());
        let accounts = BTreeMap::from([(address, account)]);
        assert_eq!(state_root(&accounts), expected);
        assert_ne!(expected, EMPTY_ROOT_HASH);
    }
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
    let receipts = [0x5b74, 0xb6e8].map(|gas| {
        crate::receipt::Receipt::new(crate::transaction::TxType::Legacy, true, gas, Vec::new())
    });
    assert_eq!(
        super::receipts_root(&receipts),
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
