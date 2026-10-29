//! Sparse roots checked against complete-state reconstruction and minimal witnesses.

use super::*;
use crate::execution_types::witness::ExecutionWitness;
use crate::test_utils::witness_of;
use crate::trie::{StateRootError, witness_state_root};
use crate::witness_backend::WitnessBackend;
use aurora_evm::backend::{Apply, ApplyBackend, Backend, Basic, MemoryBackend, MemoryVicinity};
use aurora_evm_trie::sparse::{LookupError, PatchError};

type Update = Apply<Vec<(H256, H256)>>;

fn vicinity() -> MemoryVicinity {
    MemoryVicinity {
        gas_price: U256::zero(),
        effective_gas_price: U256::zero(),
        origin: H160::zero(),
        chain_id: U256::one(),
        block_hashes: Vec::new(),
        block_number: U256::one(),
        block_coinbase: H160::zero(),
        block_timestamp: U256::zero(),
        block_difficulty: U256::zero(),
        block_gas_limit: U256::from(30_000_000),
        block_base_fee_per_gas: U256::zero(),
        block_randomness: None,
        blob_gas_price: None,
        blob_hashes: Vec::new(),
    }
}

fn db(root: H256, witness: ExecutionWitness) -> WitnessBackend {
    WitnessBackend::from_witness(vicinity(), witness, root, BTreeMap::new()).unwrap()
}

fn funded(balance: u64) -> MemoryAccount {
    MemoryAccount {
        balance: U256::from(balance),
        ..MemoryAccount::default()
    }
}

fn modify(address: H160, balance: u64, storage: Vec<(H256, H256)>, reset_storage: bool) -> Update {
    Apply::Modify {
        address,
        basic: Basic {
            balance: U256::from(balance),
            nonce: U256::zero(),
        },
        code: None,
        storage,
        reset_storage,
    }
}

fn apply(db: &mut WitnessBackend, updates: Vec<Update>) {
    db.apply(updates, Vec::new(), true);
}

fn hash_error(hash: H256) -> StateRootError {
    StateRootError::Patch(PatchError::Node(LookupError::BlindedNode(hash.0)))
}

/// Remove one leaf by its value, keeping its parent's hash reference intact.
fn withhold(witness: &mut ExecutionWitness, value: &[u8]) -> H256 {
    let index = witness
        .state
        .iter()
        .position(|node| {
            let rlp = rlp::Rlp::new(node);
            rlp.item_count() == Ok(2) && rlp.val_at::<Vec<u8>>(1).is_ok_and(|bytes| bytes == value)
        })
        .unwrap();
    keccak256(&witness.state.remove(index))
}

/// Three secure keys on different first-nibble branches, without relying on address ordering.
fn addresses() -> [H160; 3] {
    let mut seen = std::collections::BTreeSet::new();
    (1..100)
        .map(H160::from_low_u64_be)
        .filter(|address| seen.insert(keccak256(address.as_bytes()).0[0] >> 4))
        .take(3)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn slots() -> [H256; 3] {
    let mut seen = std::collections::BTreeSet::new();
    (1..100)
        .map(H256::from_low_u64_be)
        .filter(|slot| seen.insert(keccak256(slot.as_bytes()).0[0] >> 4))
        .take(3)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

#[test]
fn no_trie_is_not_an_empty_witness() {
    let complete = WitnessBackend::from_full_state(vicinity(), BTreeMap::new(), BTreeMap::new())
        .try_into_state()
        .unwrap();
    let partial = WitnessBackend::try_new(vicinity(), BTreeMap::new(), Vec::new(), BTreeMap::new())
        .unwrap()
        .try_into_state()
        .unwrap();
    assert_eq!(witness_state_root(&complete), Err(StateRootError::NoTrie));
    assert_eq!(witness_state_root(&partial), Err(StateRootError::NoTrie));

    let empty = db(EMPTY_ROOT_HASH, ExecutionWitness::default())
        .try_into_state()
        .unwrap();
    assert_eq!(witness_state_root(&empty), Ok(EMPTY_ROOT_HASH));
}

#[test]
fn reads_and_equal_writes_do_not_enter_the_changeset() {
    let who = addresses()[0];
    let key = slots()[0];
    let account = MemoryAccount {
        storage: BTreeMap::from([(key, H256::from_low_u64_be(7))]),
        ..funded(1)
    };
    let (root, witness) = witness_of(&BTreeMap::from([(who, account)]));
    let mut backend = db(root, witness);
    assert_eq!(backend.storage(who, key), H256::from_low_u64_be(7));

    backend.basic(who);
    backend.exists(addresses()[1]);
    backend.increment_balances(&BTreeMap::from([(who, U256::zero())]));
    apply(
        &mut backend,
        vec![modify(who, 1, vec![(key, H256::from_low_u64_be(7))], false)],
    );

    let state = backend.try_into_state().unwrap();
    assert!(state.changes.is_empty());
    assert_eq!(witness_state_root(&state), Ok(root));
}

#[test]
fn balance_changes_preserve_unrevealed_storage_and_code() {
    let who = addresses()[0];
    let mut account = MemoryAccount {
        code: vec![0x00],
        storage: BTreeMap::from([(slots()[0], H256::from_low_u64_be(9))]),
        ..funded(1)
    };
    let (root, mut witness) = witness_of(&BTreeMap::from([(who, account.clone())]));
    let storage_root = storage_root(&account.storage);
    witness.state.retain(|node| keccak256(node) == root);
    witness.contract_codes.clear();
    assert!(
        !witness
            .state
            .iter()
            .any(|node| keccak256(node) == storage_root)
    );

    let mut backend = db(root, witness);
    backend.increment_balances(&BTreeMap::from([(who, U256::from(5))]));
    account.balance += U256::from(5);
    let state = backend.try_into_state().unwrap();
    assert!(state.codes.is_empty());
    assert!(state.changes[&who].is_empty());
    assert_eq!(
        witness_state_root(&state),
        Ok(state_root(&BTreeMap::from([(who, account)])))
    );
}

#[test]
fn account_upserts_precede_removals_without_hidden_siblings() {
    let [removed, hidden, created] = addresses();
    let mut pre = BTreeMap::from([(removed, funded(1)), (hidden, funded(2))]);
    let (root, mut witness) = witness_of(&pre);
    let missing = withhold(&mut witness, &rlp::encode(&trie_account(&pre[&hidden])));
    let mut backend = db(root, witness);
    assert!(backend.exists(removed));
    apply(&mut backend, vec![Apply::Delete { address: removed }]);
    let state = backend.clone().try_into_state().unwrap();
    let before = state.clone();
    assert_eq!(witness_state_root(&state), Err(hash_error(missing)));
    assert_eq!(witness_state_root(&state), Err(hash_error(missing)));
    assert_eq!(
        state, before,
        "failed reconstruction must not consume or mutate evidence"
    );

    apply(&mut backend, vec![modify(created, 3, Vec::new(), false)]);
    pre.remove(&removed);
    pre.insert(created, funded(3));
    let state = backend.try_into_state().unwrap();
    assert!(!state.accounts().contains_key(&hidden));
    assert_eq!(witness_state_root(&state), Ok(state_root(&pre)));
}

#[test]
fn storage_upserts_precede_removals_and_collapse_requires_a_sibling() {
    let who = addresses()[0];
    let [removed, hidden, created] = slots();
    let mut account = MemoryAccount {
        storage: BTreeMap::from([
            (removed, H256::from_low_u64_be(1)),
            (hidden, H256::from_low_u64_be(2)),
        ]),
        ..funded(1)
    };
    let (root, mut witness) = witness_of(&BTreeMap::from([(who, account.clone())]));
    let missing = withhold(&mut witness, &rlp::encode(&2u64));
    let mut backend = db(root, witness);
    assert_eq!(backend.storage(who, removed), H256::from_low_u64_be(1));

    apply(
        &mut backend,
        vec![modify(who, 1, vec![(removed, H256::zero())], false)],
    );
    assert_eq!(
        witness_state_root(&backend.clone().try_into_state().unwrap()),
        Err(hash_error(missing))
    );

    apply(
        &mut backend,
        vec![modify(
            who,
            1,
            vec![(created, H256::from_low_u64_be(3))],
            false,
        )],
    );
    account.storage.remove(&removed);
    account.storage.insert(created, H256::from_low_u64_be(3));
    let state = backend.try_into_state().unwrap();
    assert_eq!(
        witness_state_root(&state),
        Ok(state_root(&BTreeMap::from([(who, account)])))
    );
}

#[test]
fn wipe_and_delete_recreate_discard_prior_slot_updates() {
    let [who, hidden, _] = addresses();
    let [a, b, c] = slots();
    let mut pre = BTreeMap::from([(
        who,
        MemoryAccount {
            storage: BTreeMap::from([(a, H256::repeat_byte(1))]),
            ..funded(1)
        },
    )]);
    pre.insert(hidden, funded(9));
    let (root, mut witness) = witness_of(&pre);
    // Only the root branch and touched account leaf: no old storage or untouched sibling.
    let value = rlp::encode(&trie_account(&pre[&who]));
    witness.state.retain(|node| {
        keccak256(node) == root
            || rlp::Rlp::new(node)
                .val_at::<Vec<u8>>(1)
                .is_ok_and(|bytes| bytes == value.as_ref())
    });
    assert_eq!(witness.state.len(), 2);
    let mut backend = db(root, witness);
    apply(
        &mut backend,
        vec![modify(who, 1, vec![(b, H256::repeat_byte(2))], true)],
    );
    apply(
        &mut backend,
        vec![modify(who, 1, vec![(c, H256::repeat_byte(3))], true)],
    );

    let state = backend.clone().try_into_state().unwrap();
    assert_eq!(state.changes[&who], std::collections::BTreeSet::from([c]));
    let mut expected = BTreeMap::from([(
        who,
        MemoryAccount {
            storage: BTreeMap::from([(c, H256::repeat_byte(3))]),
            ..funded(1)
        },
    )]);
    expected.insert(hidden, funded(9));
    assert!(!state.accounts().contains_key(&hidden));
    assert_eq!(witness_state_root(&state), Ok(state_root(&expected)));

    apply(
        &mut backend,
        vec![
            Apply::Delete { address: who },
            modify(who, 4, vec![(b, H256::repeat_byte(4))], false),
        ],
    );
    let mut expected = BTreeMap::from([(
        who,
        MemoryAccount {
            storage: BTreeMap::from([(b, H256::repeat_byte(4))]),
            ..funded(4)
        },
    )]);
    expected.insert(hidden, funded(9));
    assert_eq!(
        witness_state_root(&backend.try_into_state().unwrap()),
        Ok(state_root(&expected))
    );
}

#[test]
fn empty_wipes_and_code_only_writes_are_tracked() {
    let who = addresses()[0];
    let mut account = MemoryAccount {
        code: vec![0x00],
        storage: BTreeMap::from([(slots()[0], H256::from_low_u64_be(9))]),
        ..funded(1)
    };
    let (root, mut witness) = witness_of(&BTreeMap::from([(who, account.clone())]));
    witness.state.retain(|node| keccak256(node) == root);
    let mut backend = db(root, witness);
    apply(&mut backend, vec![modify(who, 1, Vec::new(), true)]);
    account.storage.clear();
    let state = backend.clone().try_into_state().unwrap();
    assert!(state.changes[&who].is_empty());
    assert_eq!(
        witness_state_root(&state),
        Ok(state_root(&BTreeMap::from([(who, account.clone())])))
    );

    let code_update = Apply::Modify {
        address: who,
        basic: Basic {
            balance: U256::one(),
            nonce: U256::zero(),
        },
        code: Some(Vec::new()),
        storage: Vec::new(),
        reset_storage: false,
    };
    // Independently test a code-only write, without an earlier wipe marking the account dirty.
    let (root, witness) = witness_of(&BTreeMap::from([(who, account.clone())]));
    let mut backend = db(root, witness);
    apply(&mut backend, vec![code_update]);
    account.code.clear();
    assert_eq!(
        witness_state_root(&backend.try_into_state().unwrap()),
        Ok(state_root(&BTreeMap::from([(who, account)])))
    );
}

#[test]
fn deleting_the_last_account_and_recreating_by_credit_resets_storage() {
    let who = addresses()[0];
    let pre = BTreeMap::from([(
        who,
        MemoryAccount {
            storage: BTreeMap::from([(slots()[0], H256::from_low_u64_be(9))]),
            ..funded(1)
        },
    )]);
    let (root, mut witness) = witness_of(&pre);
    witness.state.retain(|node| keccak256(node) == root);
    let mut backend = db(root, witness);
    assert!(backend.exists(who));
    apply(&mut backend, vec![Apply::Delete { address: who }]);
    assert_eq!(
        witness_state_root(&backend.clone().try_into_state().unwrap()),
        Ok(EMPTY_ROOT_HASH)
    );
    backend.increment_balances(&BTreeMap::from([(who, U256::from(5))]));
    assert_eq!(
        witness_state_root(&backend.try_into_state().unwrap()),
        Ok(state_root(&BTreeMap::from([(who, funded(5))])))
    );
}

#[test]
fn untouched_empty_accounts_survive_but_zero_credits_prune_touched_ones() {
    let [untouched, pruned, created] = addresses();
    let mut pre = BTreeMap::from([
        (untouched, MemoryAccount::default()),
        (pruned, MemoryAccount::default()),
    ]);
    let (root, witness) = witness_of(&pre);
    let mut backend = db(root, witness);
    backend.basic(untouched);
    backend.increment_balances(&BTreeMap::from([
        (pruned, U256::zero()),
        (created, U256::from(7)),
    ]));
    pre.remove(&pruned);
    pre.insert(created, funded(7));
    let state = backend.try_into_state().unwrap();
    assert!(!state.changes.contains_key(&untouched));
    assert_eq!(witness_state_root(&state), Ok(state_root(&pre)));
}

#[test]
fn malformed_collapse_sibling_is_not_missing_witness_data() {
    let [removed, sibling, _] = addresses();
    let key = keccak256(removed.as_bytes());
    let sibling_key = keccak256(sibling.as_bytes());
    let mut suffix = key.0;
    suffix[0] = 0x30 | (suffix[0] & 0x0f);
    let mut leaf = rlp::RlpStream::new_list(2);
    leaf.append(&suffix.as_slice());
    leaf.append(&rlp::encode(&trie_account(&funded(1))).as_ref());
    let leaf = leaf.out().to_vec();
    let malformed = vec![0xc0];
    let hash = keccak256(&malformed);
    let mut branch = rlp::RlpStream::new_list(17);
    for nibble in 0..16 {
        if nibble == key.0[0] >> 4 {
            branch.append(&keccak256(&leaf));
        } else if nibble == sibling_key.0[0] >> 4 {
            branch.append(&hash);
        } else {
            branch.append_empty_data();
        }
    }

    branch.append_empty_data();
    let branch = branch.out().to_vec();
    let mut backend = db(
        keccak256(&branch),
        ExecutionWitness {
            state: vec![branch, leaf, malformed],
            ..ExecutionWitness::default()
        },
    );
    assert_eq!(backend.basic(removed).balance, U256::one());
    apply(&mut backend, vec![Apply::Delete { address: removed }]);

    let state = backend.try_into_state().unwrap();
    assert_eq!(
        witness_state_root(&state),
        Err(StateRootError::Patch(PatchError::Node(
            LookupError::MalformedNode(hash.0)
        )))
    );
}

#[test]
fn inconsistent_changesets_fail_instead_of_returning_partial_roots() {
    let who = addresses()[0];
    let slot = slots()[0];
    let mut backend = db(EMPTY_ROOT_HASH, ExecutionWitness::default());
    apply(
        &mut backend,
        vec![modify(
            who,
            1,
            vec![(slot, H256::from_low_u64_be(1))],
            false,
        )],
    );

    let mut state = backend.try_into_state().unwrap();
    let mut missing_account = state.clone();
    missing_account.accounts.clear();
    assert_eq!(
        witness_state_root(&missing_account),
        Err(StateRootError::MissingAccount(who))
    );
    let crate::witness_backend::RevealedAccount::Present(account) =
        state.accounts.get_mut(&who).unwrap()
    else {
        panic!("created account must exist");
    };
    account.storage.clear();
    assert_eq!(
        witness_state_root(&state),
        Err(StateRootError::MissingStorageSlot { address: who, slot })
    );
}

#[test]
fn reused_storage_overlay_and_rlp_scratch_handle_integer_boundaries() {
    let env = vicinity();
    let mut backend = db(EMPTY_ROOT_HASH, ExecutionWitness::default());
    let mut oracle = MemoryBackend::new(&env, BTreeMap::new());
    let values = [
        U256::MAX,
        U256::one(),
        U256::from(128),
        U256::from(127),
        U256::from(256),
        U256::from(255),
        U256::zero(),
    ];

    for (index, value) in values.into_iter().enumerate() {
        let update = Apply::Modify {
            address: H160::from_low_u64_be(u64::try_from(index).unwrap()),
            basic: Basic {
                balance: value,
                nonce: U256::one(),
            },
            code: Some(vec![0x60, 0x00]),
            storage: vec![(H256::zero(), H256(value.to_big_endian()))],
            reset_storage: true,
        };
        oracle.apply([update.clone()], Vec::new(), true);
        apply(&mut backend, vec![update]);
    }
    let state = backend.try_into_state().unwrap();
    let expected = state_root(oracle.state());
    assert_eq!(witness_state_root(&state), Ok(expected));
    assert_eq!(witness_state_root(&state), Ok(expected));
}

#[test]
fn differential_multitransaction_updates_match_memory_backend() {
    let env = vicinity();
    for seed in 1..=4u64 {
        let mut random = seed;
        let pre: BTreeMap<_, _> = (1..=16)
            .map(|i| (H160::from_low_u64_be(i), funded(i)))
            .collect();
        let (root, witness) = witness_of(&pre);
        let mut backend = db(root, witness);
        let mut oracle = MemoryBackend::new(&env, pre);
        for step in 0..150 {
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let who = H160::from_low_u64_be(1 + (random >> 32) % 24);
            let key = H256::from_low_u64_be((random >> 16) % 8);
            // Reads populate caches but must not enlarge the changeset by themselves.
            assert_eq!(backend.storage(who, key), oracle.storage(who, key));
            let update = if step % 7 == 0 {
                Apply::Delete { address: who }
            } else {
                Apply::Modify {
                    address: who,
                    basic: Basic {
                        balance: U256::from(random % 100),
                        nonce: U256::from(random % 4),
                    },
                    code: (step % 5 == 0).then(|| vec![0x60, 0x01, 0x00]),
                    storage: vec![(
                        key,
                        if step % 3 == 0 {
                            H256::zero()
                        } else {
                            H256::from_low_u64_be(random)
                        },
                    )],
                    reset_storage: step % 11 == 0,
                }
            };
            oracle.apply([update.clone()], Vec::new(), true);
            apply(&mut backend, vec![update]);
            let state = backend.clone().try_into_state().unwrap();
            assert_eq!(
                witness_state_root(&state),
                Ok(state_root(oracle.state())),
                "seed={seed}, step={step}"
            );
        }
    }
}

/// EEST v5.4.0 `berlin/eip2930_access_list/test_repeated_address_acl.json`, Berlin variant.
/// Replays its state diff only; the pinned post-root is independent of both local trie builders.
#[test]
fn eest_access_list_diff_matches_official_root() {
    let sender = H160(hex!("f7e89272be947560f09d73c2cd1e8a388d017593"));
    let contract = H160(hex!("8cdf9cd5727230f7cf60842520379509cfa50825"));
    let beneficiary = H160(hex!("2adc25665018aa1fe0e6bc666dac8fc2697ff9ba"));
    let pre = BTreeMap::from([
        (
            sender,
            MemoryAccount {
                balance: U256::from_str_radix("3635c9adc5dea00000", 16).unwrap(),
                ..MemoryAccount::default()
            },
        ),
        (
            contract,
            MemoryAccount {
                nonce: U256::one(),
                code: hex!("5a6000545a90509003600590036000555a6001545a905090036005900360015500")
                    .to_vec(),
                ..MemoryAccount::default()
            },
        ),
    ]);
    let (root, witness) = witness_of(&pre);
    assert_eq!(
        root,
        H256(hex!(
            "8941020a3e31617a8d1811dc70a5b37771c973f5026473baeb3e5ea342dc2c7c"
        ))
    );
    let mut backend = db(root, witness);
    apply(
        &mut backend,
        vec![
            Apply::Modify {
                address: sender,
                basic: Basic {
                    nonce: U256::one(),
                    balance: U256::from_str_radix("3635c9adc5de955718", 16).unwrap(),
                },
                code: None,
                storage: Vec::new(),
                reset_storage: false,
            },
            Apply::Modify {
                address: contract,
                basic: Basic {
                    nonce: U256::one(),
                    balance: U256::zero(),
                },
                code: None,
                storage: vec![
                    (H256::zero(), H256::from_low_u64_be(100)),
                    (H256::from_low_u64_be(1), H256::from_low_u64_be(100)),
                ],
                reset_storage: false,
            },
        ],
    );
    backend.increment_balances(&BTreeMap::from([(
        beneficiary,
        U256::from_str_radix("1bc16d674ed2a8e8", 16).unwrap(),
    )]));
    assert_eq!(
        witness_state_root(&backend.try_into_state().unwrap()),
        Ok(H256(hex!(
            "ea0013a3ab0946647c0aa40e90a65367c4bc8dd9fef50df1a7e0d30a510d79f4"
        )))
    );
}
