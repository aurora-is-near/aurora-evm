//! Unit tests: revealed maps, lazy trie resolution, complete-state coverage and credits.

use super::{
    RevealedAccount, WitnessAccount, WitnessBackend, WitnessDbError, WitnessState,
    WitnessStateError,
};
use crate::constants::{BLOCKHASH_WINDOW, EMPTY_ROOT_HASH, KECCAK_EMPTY};
use crate::crypto::keccak256;
use crate::execution_types::witness::ExecutionWitness;
use aurora_evm::backend::{Apply, ApplyBackend, Backend, Basic, MemoryAccount, MemoryVicinity};
use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

const CODE: &[u8] = &[0x60, 0x00, 0x49, 0x60, 0x00, 0x55, 0x00];

fn addr(byte: u8) -> H160 {
    H160::repeat_byte(byte)
}

fn slot(byte: u8) -> H256 {
    H256::repeat_byte(byte)
}

fn vicinity() -> MemoryVicinity {
    MemoryVicinity {
        gas_price: U256::zero(),
        effective_gas_price: U256::zero(),
        origin: H160::zero(),
        block_hashes: vec![],
        block_number: U256::from(1_000u64),
        block_coinbase: H160::zero(),
        block_timestamp: U256::zero(),
        block_difficulty: U256::zero(),
        block_gas_limit: U256::zero(),
        chain_id: U256::one(),
        block_base_fee_per_gas: U256::zero(),
        block_randomness: None,
        blob_gas_price: None,
        blob_hashes: vec![],
    }
}

/// An account with code, whose `code_hash` is `keccak256(CODE)` — as a trie leaf would give it.
fn account_with_code() -> WitnessAccount {
    WitnessAccount {
        nonce: U256::one(),
        balance: U256::from(7u64),
        code_hash: keccak256(CODE),
        storage_root: EMPTY_ROOT_HASH,
        storage: BTreeMap::new(),
        storage_wiped: false,
    }
}

fn backend(accounts: Vec<(H160, RevealedAccount)>, codes: Vec<Vec<u8>>) -> WitnessBackend {
    WitnessBackend::try_new(
        vicinity(),
        accounts.into_iter().collect(),
        codes,
        BTreeMap::new(),
    )
    .expect("test fixtures are self-consistent")
}

fn memory_account(
    balance: u64,
    nonce: u64,
    code: &[u8],
    storage: &[(H256, H256)],
) -> MemoryAccount {
    MemoryAccount {
        nonce: U256::from(nonce),
        balance: U256::from(balance),
        storage: storage.iter().copied().collect(),
        code: code.to_vec(),
    }
}

/// A witness over `accounts` (see [`crate::test_support::witness_of`]) and the root it proves.
fn witness_of(accounts: &[(H160, MemoryAccount)]) -> (H256, ExecutionWitness) {
    crate::test_support::witness_of(&accounts.iter().cloned().collect())
}

/// The defect this module exists for: the witness reveals the *account* but not its *code*.
///
/// A derived code hash would silently turn such an account into an empty one; here the leaf value
/// survives, and the unprovable read is reported instead of being answered.
#[test]
fn a_touched_account_whose_code_is_absent_is_reported_not_emptied() {
    let who = addr(0xc0);
    // The account is revealed; its code bytes are NOT supplied.
    let db = backend(
        vec![(who, RevealedAccount::Present(account_with_code()))],
        vec![],
    );

    // The leaf value is intact, which is what a state root must be built from.
    let RevealedAccount::Present(account) = db.accounts()[&who].clone() else {
        panic!("account must be present");
    };
    assert_eq!(account.code_hash, keccak256(CODE));
    assert!(account.has_code());
    assert_ne!(account.code_hash, KECCAK_EMPTY);

    // Reading the code cannot answer, so it poisons.
    assert!(db.code(who).is_empty());
    assert_eq!(
        db.missing(),
        Some(WitnessDbError::Code {
            address: who,
            code_hash: keccak256(CODE),
        })
    );
}

#[test]
fn code_is_returned_when_the_witness_supplied_it() {
    let who = addr(0xc0);
    let db = backend(
        vec![(who, RevealedAccount::Present(account_with_code()))],
        vec![CODE.to_vec()],
    );
    assert_eq!(db.code(who), CODE);
    assert_eq!(db.missing(), None);
}

#[test]
fn an_account_proven_to_have_no_code_needs_no_bytes() {
    let who = addr(0xc0);
    let db = backend(
        vec![(who, RevealedAccount::Present(WitnessAccount::empty()))],
        vec![],
    );
    assert!(db.code(who).is_empty());
    assert_eq!(db.missing(), None, "KECCAK_EMPTY is a proof, not a miss");
}

/// Proven-absent reads as empty and is silent; unrevealed reads as empty and poisons. The two
/// answers are identical — only `missing()` separates them, which is the whole point.
#[test]
fn proven_absent_is_silent_and_unrevealed_poisons() {
    let absent = addr(0xa0);
    let unknown = addr(0xb0);

    let db = backend(vec![(absent, RevealedAccount::Absent)], vec![]);
    assert!(!db.exists(absent));
    assert_eq!(db.basic(absent), Basic::default());
    assert_eq!(db.storage(absent, slot(1)), H256::zero());
    assert_eq!(db.missing(), None);

    let db = backend(vec![], vec![]);
    assert!(!db.exists(unknown));
    assert_eq!(db.basic(unknown), Basic::default());
    assert_eq!(
        db.missing(),
        Some(WitnessDbError::Account { address: unknown })
    );
}

#[test]
fn basic_reads_the_revealed_fields() {
    let who = addr(0xc0);
    let db = backend(
        vec![(who, RevealedAccount::Present(account_with_code()))],
        vec![],
    );
    assert!(db.exists(who));
    assert_eq!(
        db.basic(who),
        Basic {
            balance: U256::from(7u64),
            nonce: U256::one(),
        }
    );
    assert_eq!(db.missing(), None);
}

/// A revealed zero and an unmentioned slot both read as zero; only the second is a miss.
#[test]
fn storage_distinguishes_a_revealed_zero_from_an_unmentioned_slot() {
    let who = addr(0xc0);
    let mut account = account_with_code();
    account.storage_root = H256::repeat_byte(0x99); // non-empty storage
    account.storage.insert(slot(1), H256::repeat_byte(0x11));
    account.storage.insert(slot(2), H256::zero()); // resolved *to* zero

    let db = backend(vec![(who, RevealedAccount::Present(account))], vec![]);
    assert_eq!(db.storage(who, slot(1)), H256::repeat_byte(0x11));
    assert_eq!(db.storage(who, slot(2)), H256::zero());
    assert_eq!(db.missing(), None, "a resolved zero is proven");

    assert_eq!(db.storage(who, slot(3)), H256::zero());
    assert_eq!(
        db.missing(),
        Some(WitnessDbError::StorageSlot {
            address: who,
            slot: slot(3),
        })
    );
}

#[test]
fn an_empty_storage_root_proves_every_slot_zero() {
    let who = addr(0xc0);
    let db = backend(
        vec![(who, RevealedAccount::Present(account_with_code()))],
        vec![],
    );
    // `storage_root == EMPTY_ROOT_HASH`, so no slot needs revealing.
    assert_eq!(db.storage(who, slot(7)), H256::zero());
    assert!(db.is_empty_storage(who));
    assert_eq!(db.missing(), None);
}

/// EIP-7610 asks `is_empty_storage` about accounts a create collides with, whose storage a
/// witness has no reason to reveal — so it must answer from the leaf and never poison.
#[test]
fn is_empty_storage_answers_from_the_leaf_without_poisoning() {
    let who = addr(0xc0);
    let mut account = account_with_code();
    account.storage_root = H256::repeat_byte(0x99);

    let db = backend(vec![(who, RevealedAccount::Present(account))], vec![]);
    assert!(!db.is_empty_storage(who), "a non-empty root means storage");
    assert_eq!(db.missing(), None);

    // The account itself must be revealed, though: nothing is known about an unknown one.
    let blind = backend(vec![], vec![]);
    assert!(blind.is_empty_storage(addr(0xee)));
    assert_eq!(
        blind.missing(),
        Some(WitnessDbError::Account {
            address: addr(0xee)
        })
    );
}

#[test]
fn only_the_first_missing_read_is_kept() {
    let first = addr(0xa0);
    let second = addr(0xb0);
    let db = backend(vec![], vec![]);
    let _ = db.basic(first);
    let _ = db.basic(second);
    assert_eq!(
        db.missing(),
        Some(WitnessDbError::Account { address: first }),
        "the first miss explains the rest"
    );
}

#[test]
fn blockhash_is_zero_outside_the_window_and_poisons_inside_it() {
    let known = H256::repeat_byte(0x77);
    let db = WitnessBackend::try_new(
        vicinity(), // block_number = 1000
        BTreeMap::new(),
        Vec::new(),
        core::iter::once((999u64, known)).collect(),
    )
    .unwrap();

    // The current block and later: zero by definition, no proof needed.
    assert_eq!(db.block_hash(U256::from(1_000u64)), H256::zero());
    assert_eq!(db.block_hash(U256::from(1_001u64)), H256::zero());
    assert_eq!(db.missing(), None);

    // Older than the window: zero by definition.
    let far = U256::from(1_000usize - BLOCKHASH_WINDOW - 1);
    assert_eq!(db.block_hash(far), H256::zero());
    assert_eq!(db.missing(), None);

    // Supplied ancestor.
    assert_eq!(db.block_hash(U256::from(999u64)), known);
    assert_eq!(db.missing(), None);

    // Inside the window, not supplied: fail closed rather than answer a legal-looking zero.
    assert_eq!(db.block_hash(U256::from(998u64)), H256::zero());
    assert_eq!(
        db.missing(),
        Some(WitnessDbError::AncestorHash { number: 998 })
    );
}

#[test]
fn apply_registers_created_code_under_its_hash() {
    let who = addr(0xc0);
    let mut db = backend(
        vec![(who, RevealedAccount::Present(WitnessAccount::empty()))],
        vec![],
    );

    db.apply(
        vec![Apply::Modify {
            address: who,
            basic: Basic {
                balance: U256::one(),
                nonce: U256::one(),
            },
            code: Some(CODE.to_vec()),
            storage: Vec::<(H256, H256)>::new(),
            reset_storage: false,
        }],
        Vec::new(),
        false,
    );

    // The created contract is readable by the next transaction, with no witness entry for it.
    assert_eq!(db.code(who), CODE);
    assert_eq!(db.codes()[&keccak256(CODE)], CODE);
    assert_eq!(db.missing(), None);
}

/// The wipe flag is the only record that unlisted slots became provably zero, so it must survive
/// `apply` — the full-state backend drops it.
#[test]
fn reset_storage_records_the_wipe_and_stops_poisoning() {
    let who = addr(0xc0);
    let mut account = account_with_code();
    account.storage_root = H256::repeat_byte(0x99);
    account.storage.insert(slot(1), H256::repeat_byte(0x11));

    let db = backend(vec![(who, RevealedAccount::Present(account))], vec![]);
    // Before the wipe an unmentioned slot has no proof.
    assert_eq!(db.storage(who, slot(5)), H256::zero());
    assert!(db.missing().is_some());

    let mut fresh = WitnessBackend::try_new(
        vicinity(),
        db.accounts().clone(),
        Vec::new(),
        BTreeMap::new(),
    )
    .unwrap();
    fresh.apply(
        vec![Apply::Modify {
            address: who,
            basic: Basic {
                balance: U256::one(),
                nonce: U256::one(),
            },
            code: None,
            storage: Vec::<(H256, H256)>::new(),
            reset_storage: true,
        }],
        Vec::new(),
        false,
    );

    let RevealedAccount::Present(after) = fresh.accounts()[&who].clone() else {
        panic!("account must be present");
    };
    assert!(after.storage_wiped);
    assert!(after.storage.is_empty());
    assert!(after.is_storage_empty());
    // After a wipe every unlisted slot is provably zero.
    assert_eq!(fresh.storage(who, slot(5)), H256::zero());
    assert_eq!(fresh.missing(), None);
    assert!(fresh.is_empty_storage(who));
}

#[test]
fn delete_and_empty_pruning_record_proven_absence() {
    let deleted = addr(0xd0);
    let pruned = addr(0xe0);
    let mut db = backend(
        vec![
            (deleted, RevealedAccount::Present(account_with_code())),
            (pruned, RevealedAccount::Present(account_with_code())),
        ],
        vec![],
    );

    db.apply(
        vec![
            Apply::Delete { address: deleted },
            Apply::Modify {
                address: pruned,
                basic: Basic {
                    balance: U256::zero(),
                    nonce: U256::zero(),
                },
                // Clearing the code is what makes it EIP-161 empty.
                code: Some(Vec::new()),
                storage: Vec::<(H256, H256)>::new(),
                reset_storage: true,
            },
        ],
        Vec::new(),
        true,
    );

    // Both are *proven* absent now, so later reads are silent rather than poisoning.
    assert_eq!(db.accounts()[&deleted], RevealedAccount::Absent);
    assert_eq!(db.accounts()[&pruned], RevealedAccount::Absent);
    assert!(!db.exists(deleted));
    assert!(!db.exists(pruned));
    assert_eq!(db.missing(), None);
}

/// Modifying an account the witness never revealed is itself unproven: the pre-state it is
/// modified *from* is unknown, so the write must not launder it into a known account.
#[test]
fn modifying_an_unrevealed_account_poisons() {
    let who = addr(0xf0);
    let mut db = backend(vec![], vec![]);

    db.apply(
        vec![Apply::Modify {
            address: who,
            basic: Basic {
                balance: U256::one(),
                nonce: U256::zero(),
            },
            code: None,
            storage: Vec::<(H256, H256)>::new(),
            reset_storage: false,
        }],
        Vec::new(),
        false,
    );

    assert_eq!(db.missing(), Some(WitnessDbError::Account { address: who }));
}

/// EIP-161 emptiness is nonce, balance and code hash. Storage is not part of it, so an account
/// that is empty by those three must be pruned even with storage still on it — the very shape
/// EIP-7610 exists for. Keeping it would leave a leaf no state root expects, and silently:
/// `missing()` stays `None`.
#[test]
fn eip161_pruning_ignores_storage() {
    let who = addr(0xc0);
    let mut account = WitnessAccount::empty();
    // Empty by EIP-161, yet carrying storage.
    account.storage_root = H256::repeat_byte(0x99);
    account.storage.insert(slot(1), H256::repeat_byte(0x11));
    assert!(account.is_empty());
    assert!(!account.is_storage_empty());

    let mut db = backend(vec![(who, RevealedAccount::Present(account))], vec![]);
    db.apply(
        vec![Apply::Modify {
            address: who,
            basic: Basic {
                balance: U256::zero(),
                nonce: U256::zero(),
            },
            code: None,
            storage: Vec::<(H256, H256)>::new(),
            reset_storage: false,
        }],
        Vec::new(),
        true,
    );

    assert_eq!(
        db.accounts()[&who],
        RevealedAccount::Absent,
        "storage must not keep an EIP-161-empty account alive"
    );
    assert_eq!(db.missing(), None);
}

/// Resurrection after a delete must set the wipe flag, not only inherit an empty `storage_root`:
/// the two fields are one encoding, and the sparse-trie stage will read `storage_wiped`.
#[test]
fn resurrection_after_delete_records_the_wipe() {
    let who = addr(0xc0);
    let mut db = backend(vec![(who, RevealedAccount::Absent)], vec![]);

    db.apply(
        vec![Apply::Modify {
            address: who,
            basic: Basic {
                balance: U256::one(),
                nonce: U256::zero(),
            },
            code: None,
            storage: Vec::<(H256, H256)>::new(),
            reset_storage: false,
        }],
        Vec::new(),
        false,
    );

    let RevealedAccount::Present(after) = db.accounts()[&who].clone() else {
        panic!("account must be resurrected");
    };
    assert!(
        after.storage_wiped,
        "deletion destroyed the storage; both halves of the encoding must say so"
    );
    assert!(after.is_storage_empty());
    // No slot needs revealing after a wipe.
    assert_eq!(db.storage(who, slot(4)), H256::zero());
    assert_eq!(db.missing(), None);
}

/// The post-state cannot be taken out of a backend whose reads were not all proven.
#[test]
fn try_into_state_refuses_an_unproven_state() {
    let who = addr(0xc0);

    let proven = backend(
        vec![(who, RevealedAccount::Present(WitnessAccount::empty()))],
        vec![],
    );
    let state = proven.try_into_state().expect("nothing was unproven");
    assert_eq!(state.accounts.len(), 1);

    let poisoned = backend(vec![], vec![]);
    let _ = poisoned.basic(addr(0xee));
    assert_eq!(
        poisoned.try_into_state().unwrap_err(),
        WitnessDbError::Account {
            address: addr(0xee)
        },
        "an unproven read must not yield a post-state"
    );
}

/// The code map is keyed here, not by the caller, so bytes filed under a hash that is not their
/// own cannot be expressed at all.
#[test]
fn code_is_keyed_from_the_bytes_themselves() {
    let who = addr(0xc0);
    let db = backend(
        vec![(who, RevealedAccount::Present(account_with_code()))],
        vec![CODE.to_vec()],
    );
    assert_eq!(
        db.codes().keys().copied().collect::<Vec<_>>(),
        vec![keccak256(CODE)]
    );
    assert_eq!(db.code(who), CODE);
    assert_eq!(db.missing(), None);
}

/// An empty storage root promises every slot is zero, and `storage()` answers unlisted slots from
/// that promise. A witness that breaks it would turn the promise into a silent wrong answer, so
/// the backend refuses to exist.
#[test]
fn a_witness_that_contradicts_itself_is_rejected() {
    let who = addr(0xc0);
    let mut account = WitnessAccount::empty(); // storage_root == EMPTY_ROOT_HASH
    account.storage.insert(slot(1), H256::repeat_byte(0x11));

    assert_eq!(
        WitnessBackend::try_new(
            vicinity(),
            core::iter::once((who, RevealedAccount::Present(account))).collect(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap_err(),
        WitnessStateError::StorageContradictsRoot {
            address: who,
            slot: slot(1),
        }
    );
}

/// A revealed *zero* under an empty root is consistent — it says the same thing the root says.
#[test]
fn a_revealed_zero_under_an_empty_root_is_accepted() {
    let who = addr(0xc0);
    let mut account = WitnessAccount::empty();
    account.storage.insert(slot(1), H256::zero());
    assert!(
        WitnessBackend::try_new(
            vicinity(),
            core::iter::once((who, RevealedAccount::Present(account))).collect(),
            Vec::new(),
            BTreeMap::new(),
        )
        .is_ok()
    );
}

/// The invariant is a *construction-time* one: execution legitimately writes slots into an
/// account that started empty, and that must not be mistaken for a contradiction.
#[test]
fn writing_into_an_originally_empty_storage_is_not_a_contradiction() {
    let who = addr(0xc0);
    let mut db = backend(
        vec![(who, RevealedAccount::Present(WitnessAccount::empty()))],
        vec![],
    );
    db.apply(
        vec![Apply::Modify {
            address: who,
            basic: Basic {
                balance: U256::one(),
                nonce: U256::one(),
            },
            code: None,
            storage: vec![(slot(1), H256::repeat_byte(0x11))],
            reset_storage: false,
        }],
        Vec::new(),
        false,
    );
    assert_eq!(db.storage(who, slot(1)), H256::repeat_byte(0x11));
    assert_eq!(db.missing(), None);
}

#[test]
fn block_environment_comes_from_the_owned_vicinity() {
    let mut db = backend(vec![], vec![]);
    assert_eq!(db.block_number(), U256::from(1_000u64));
    assert_eq!(db.chain_id(), U256::one());
    assert_eq!(db.blob_gas_price(), None);
    assert_eq!(db.get_blob_hash(0), None);

    // Per-transaction fields are set through the mutable view.
    db.vicinity_mut().origin = addr(0x0a);
    db.vicinity_mut().blob_hashes = vec![U256::from(5u64)];
    assert_eq!(db.origin(), addr(0x0a));
    assert_eq!(db.get_blob_hash(0), Some(U256::from(5u64)));
    assert_eq!(db.vicinity().origin, addr(0x0a));
}

// --- lazy resolution from witness trie nodes ---

#[test]
fn from_witness_resolves_accounts_and_slots_by_proof() {
    let contract = addr(0xc0);
    let holder = addr(0xb0);
    let (root, witness) = witness_of(&[
        (
            contract,
            memory_account(
                7,
                1,
                CODE,
                &[
                    (slot(1), H256::repeat_byte(0x11)),
                    (slot(2), H256::repeat_byte(0x22)),
                ],
            ),
        ),
        (holder, memory_account(1_000, 3, &[], &[])),
    ]);
    let db = WitnessBackend::from_witness(vicinity(), witness, root, BTreeMap::new()).unwrap();

    // Nothing is resolved until it is read.
    assert!(db.accounts().is_empty());

    assert_eq!(
        db.basic(contract),
        Basic {
            balance: U256::from(7u64),
            nonce: U256::one(),
        }
    );
    assert_eq!(db.code(contract), CODE);
    assert_eq!(db.storage(contract, slot(1)), H256::repeat_byte(0x11));
    assert_eq!(db.storage(contract, slot(2)), H256::repeat_byte(0x22));
    // A slot the storage trie proves absent is a zero, not a gap.
    assert_eq!(db.storage(contract, slot(3)), H256::zero());
    assert!(!db.is_empty_storage(contract));

    assert_eq!(
        db.basic(holder),
        Basic {
            balance: U256::from(1_000u64),
            nonce: U256::from(3u64),
        }
    );
    assert!(db.code(holder).is_empty());
    assert!(db.is_empty_storage(holder));

    // An address the state trie proves absent.
    assert!(!db.exists(addr(0xee)));
    assert_eq!(db.basic(addr(0xee)), Basic::default());
    assert_eq!(db.storage(addr(0xee), slot(1)), H256::zero());

    assert_eq!(db.missing(), None);
    let RevealedAccount::Present(resolved) = db.accounts()[&contract].clone() else {
        panic!("resolved by proof");
    };
    assert_eq!(resolved.code_hash, keccak256(CODE));
    // Resolved slots are cached, the proven zero included.
    assert_eq!(resolved.storage.len(), 3);
    assert_eq!(db.accounts()[&addr(0xee)], RevealedAccount::Absent);

    let WitnessState { accounts, codes } = db.try_into_state().unwrap();
    assert_eq!(accounts.len(), 3);
    assert_eq!(codes[&keccak256(CODE)], CODE);
}

#[test]
fn from_witness_requires_the_pre_state_root_node() {
    let (root, witness) = witness_of(&[(addr(0xc0), memory_account(1, 0, &[], &[]))]);
    let other_root = H256::repeat_byte(0x42);
    assert_eq!(
        WitnessBackend::from_witness(vicinity(), witness.clone(), other_root, BTreeMap::new())
            .unwrap_err(),
        WitnessStateError::PreStateRootNotRevealed {
            pre_state_root: other_root
        }
    );
    assert!(WitnessBackend::from_witness(vicinity(), witness, root, BTreeMap::new()).is_ok());

    // The empty trie needs no nodes at all.
    let empty = ExecutionWitness::default();
    let db =
        WitnessBackend::from_witness(vicinity(), empty, EMPTY_ROOT_HASH, BTreeMap::new()).unwrap();
    assert!(!db.exists(addr(0x01)));
    assert_eq!(db.missing(), None);
}

#[test]
fn a_withheld_node_poisons_only_the_reads_that_need_it() {
    let contract = addr(0xc0);
    let holder = addr(0xb0);
    let (root, mut witness) = witness_of(&[
        (
            contract,
            memory_account(7, 1, CODE, &[(slot(1), H256::repeat_byte(0x11))]),
        ),
        (holder, memory_account(1_000, 3, &[], &[])),
    ]);
    // The contract's storage trie is a single leaf; withhold it.
    let storage_leaf = witness
        .state
        .iter()
        .position(|node| {
            let key = keccak256(slot(1).as_bytes());
            // A leaf holding this slot's value under the hashed slot key.
            node.len() > 32 && rlp::Rlp::new(node).item_count() == Ok(2) && {
                let value: Vec<u8> = rlp::Rlp::new(node).val_at(1).unwrap_or_default();
                value
                    == rlp::encode(&U256::from_big_endian(H256::repeat_byte(0x11).as_bytes()))
                        .to_vec()
                    && !key.is_zero()
            }
        })
        .expect("the storage leaf is a hashed node");
    let withheld = keccak256(&witness.state.remove(storage_leaf));
    let db = WitnessBackend::from_witness(vicinity(), witness, root, BTreeMap::new()).unwrap();

    // Account leaves are still provable.
    assert_eq!(db.basic(holder).balance, U256::from(1_000u64));
    assert_eq!(db.basic(contract).balance, U256::from(7u64));
    assert_eq!(db.missing(), None);

    // The slot behind the withheld node is not.
    assert_eq!(db.storage(contract, slot(1)), H256::zero());
    assert_eq!(
        db.missing(),
        Some(WitnessDbError::TrieNode { hash: withheld })
    );
}

#[test]
fn from_witness_reports_omitted_code_of_a_proven_account() {
    let contract = addr(0xc0);
    let (root, mut witness) = witness_of(&[(contract, memory_account(7, 1, CODE, &[]))]);
    witness.contract_codes.clear();
    let db = WitnessBackend::from_witness(vicinity(), witness, root, BTreeMap::new()).unwrap();
    assert!(db.code(contract).is_empty());
    assert_eq!(
        db.missing(),
        Some(WitnessDbError::Code {
            address: contract,
            code_hash: keccak256(CODE)
        })
    );
}

// --- complete-state coverage ---

#[test]
fn a_complete_state_treats_absence_as_proof() {
    let who = addr(0xc0);
    let mut db = WitnessBackend::from_full_state(
        vicinity(),
        BTreeMap::from([(
            who,
            memory_account(5, 2, CODE, &[(slot(1), H256::repeat_byte(0x11))]),
        )]),
        BTreeMap::new(),
    );
    assert_eq!(db.basic(who).balance, U256::from(5u64));
    assert_eq!(db.code(who), CODE);
    assert_eq!(db.storage(who, slot(1)), H256::repeat_byte(0x11));
    // Unlisted slot under a non-empty root: zero, because the map is the whole storage.
    assert_eq!(db.storage(who, slot(9)), H256::zero());
    assert!(!db.is_empty_storage(who));

    // Unknown address: absent, silently.
    assert!(!db.exists(addr(0xee)));
    assert!(db.is_empty_storage(addr(0xee)));
    assert_eq!(db.missing(), None);

    // Writes and credits to unknown addresses create them without a gap.
    db.increment_balances([(addr(0xee), U256::from(3u64))]);
    db.apply(
        vec![Apply::Modify {
            address: addr(0xdd),
            basic: Basic {
                balance: U256::one(),
                nonce: U256::zero(),
            },
            code: None,
            storage: Vec::<(H256, H256)>::new(),
            reset_storage: false,
        }],
        Vec::new(),
        true,
    );
    assert_eq!(db.basic(addr(0xee)).balance, U256::from(3u64));
    assert_eq!(db.basic(addr(0xdd)).balance, U256::one());
    assert_eq!(db.missing(), None);
    // The leaf fields were derived from the contents.
    let RevealedAccount::Present(account) = db.accounts()[&who].clone() else {
        panic!("present");
    };
    assert_eq!(account.code_hash, keccak256(CODE));
    assert_ne!(account.storage_root, EMPTY_ROOT_HASH);
}

// --- balance increments ---

#[test]
fn increments_add_to_present_create_from_absent_and_poison_unknown() {
    let present = addr(0xc0);
    let absent = addr(0xa0);
    let unknown = addr(0xee);
    let mut db = backend(
        vec![
            (present, RevealedAccount::Present(account_with_code())),
            (absent, RevealedAccount::Absent),
        ],
        vec![],
    );

    db.increment_balances([(present, U256::from(10u64))]);
    assert_eq!(db.basic(present).balance, U256::from(17u64));

    db.increment_balances([(absent, U256::from(4u64))]);
    let RevealedAccount::Present(created) = db.accounts()[&absent].clone() else {
        panic!("the increment creates the account");
    };
    assert_eq!(created.balance, U256::from(4u64));
    assert!(
        created.storage_wiped,
        "a created account has provably empty storage"
    );
    assert_eq!(db.missing(), None);

    db.increment_balances([(unknown, U256::one())]);
    assert_eq!(db.basic(unknown).balance, U256::one());
    assert_eq!(
        db.missing(),
        Some(WitnessDbError::Account { address: unknown })
    );
}

/// An increment is a touch: zero to an empty account clears it, zero to an absent one creates
/// nothing.
#[test]
fn a_zero_increment_touches_without_creating() {
    let empty = addr(0xe0);
    let absent = addr(0xa0);
    let mut db = backend(
        vec![
            (empty, RevealedAccount::Present(WitnessAccount::empty())),
            (absent, RevealedAccount::Absent),
        ],
        vec![],
    );
    db.increment_balances([(empty, U256::zero()), (absent, U256::zero())]);
    assert_eq!(db.accounts()[&empty], RevealedAccount::Absent);
    assert_eq!(db.accounts()[&absent], RevealedAccount::Absent);
    assert_eq!(db.missing(), None);

    // An account with a nonce or code is not empty and survives a zero increment.
    let alive = addr(0xa1);
    let mut db = backend(
        vec![(alive, RevealedAccount::Present(account_with_code()))],
        vec![],
    );
    db.increment_balances([(alive, U256::zero())]);
    assert_eq!(db.basic(alive).balance, U256::from(7u64));
}

/// Removal follows the whole phase, not the single increment: an empty account incremented by zero
/// and then funded survives with the storage an immediate removal would have wiped.
#[test]
fn a_zero_increment_before_a_funding_one_keeps_the_account_and_its_storage() {
    let who = addr(0xe0);
    let empty_with_storage = WitnessAccount {
        storage_root: H256::repeat_byte(0x5a),
        storage: BTreeMap::from([(slot(1), H256::repeat_byte(0x11))]),
        ..WitnessAccount::empty()
    };
    let mut db = backend(
        vec![(who, RevealedAccount::Present(empty_with_storage))],
        vec![],
    );

    db.increment_balances([(who, U256::zero()), (who, U256::from(5u64))]);

    let RevealedAccount::Present(account) = db.accounts()[&who].clone() else {
        panic!("the funded account must survive the phase");
    };
    assert_eq!(account.balance, U256::from(5u64));
    assert!(!account.storage_wiped);
    assert_eq!(db.storage(who, slot(1)), H256::repeat_byte(0x11));
    assert_eq!(db.missing(), None);
}
