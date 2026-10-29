//! Ownership transfer and preservation of the pre-state trie after execution.

use super::*;

#[test]
fn state_transfer_keeps_unread_nodes_and_moves_buffers() {
    let who = addr(0xc0);
    let storage_key = slot(1);
    let value = slot(0x11);
    let (root, witness) = witness_of(&[(who, memory_account(7, 1, CODE, &[(storage_key, value)]))]);
    let db = WitnessBackend::from_witness(vicinity(), witness, root, BTreeMap::new()).unwrap();
    let trie = db.trie.as_ref().unwrap();
    let key = keccak256(who.as_bytes());
    let leaf = trie.nodes().get(root.0, key.as_bytes()).unwrap().unwrap();
    let leaf_ptr = leaf.as_ptr();
    let account = super::super::decode_account_leaf(leaf).unwrap();
    let slot_key = keccak256(storage_key.as_bytes());
    let slot_ptr = trie
        .nodes()
        .get(account.storage_root.0, slot_key.as_bytes())
        .unwrap()
        .unwrap()
        .as_ptr();
    let node_count = trie.nodes().len();
    let code_ptr = db.codes()[&keccak256(CODE)].as_ptr();

    let state = db.try_into_state().unwrap();
    assert!(
        state.accounts.is_empty(),
        "transfer must not resolve accounts"
    );
    assert_eq!(state.codes[&keccak256(CODE)].as_ptr(), code_ptr);
    let trie = state.trie.as_ref().unwrap();
    assert_eq!(trie.state_root(), root);
    assert_eq!(trie.nodes().len(), node_count);
    assert_eq!(
        trie.nodes()
            .get(root.0, key.as_bytes())
            .unwrap()
            .unwrap()
            .as_ptr(),
        leaf_ptr,
        "account node bytes must be moved, not cloned"
    );
    assert_eq!(
        trie.nodes()
            .get(account.storage_root.0, slot_key.as_bytes())
            .unwrap()
            .unwrap()
            .as_ptr(),
        slot_ptr,
        "storage node bytes must be moved, not cloned"
    );
    assert_eq!(
        trie.account(who).unwrap(),
        RevealedAccount::Present(account.clone())
    );
    assert_eq!(
        trie.slot(who, account.storage_root, storage_key).unwrap(),
        value
    );
}

#[test]
fn post_state_changes_do_not_replace_pre_state_proofs() {
    let changed = addr(0xc0);
    let deleted = addr(0xd0);
    let old_value = slot(0x11);
    let new_value = slot(0x22);
    let new_code = vec![0x60, 0x01, 0x00];
    let new_code_hash = keccak256(&new_code);
    let (root, witness) = witness_of(&[
        (changed, memory_account(7, 1, CODE, &[(slot(1), old_value)])),
        (deleted, memory_account(9, 2, &[], &[])),
    ]);
    let mut db = WitnessBackend::from_witness(vicinity(), witness, root, BTreeMap::new()).unwrap();
    assert_eq!(db.storage(changed, slot(1)), old_value);
    assert!(db.exists(deleted));
    let basic = Basic {
        balance: U256::from(8),
        nonce: U256::from(2),
    };
    db.apply(
        [
            Apply::Modify {
                address: changed,
                basic: basic.clone(),
                code: Some(new_code.clone()),
                storage: vec![(slot(2), new_value)],
                reset_storage: true,
            },
            Apply::Delete { address: deleted },
        ],
        Vec::new(),
        true,
    );
    let state = db.try_into_state().unwrap();
    let RevealedAccount::Present(account) = &state.accounts[&changed] else {
        panic!("modified account must remain present");
    };
    assert_eq!(account.balance, basic.balance);
    assert_eq!(account.nonce, basic.nonce);
    assert_eq!(account.code_hash, new_code_hash);
    assert_eq!(state.codes[&new_code_hash], new_code);
    assert_eq!(state.codes[&keccak256(CODE)], CODE);
    assert!(account.storage_wiped);
    assert_eq!(account.storage, BTreeMap::from([(slot(2), new_value)]));
    assert_eq!(state.accounts[&deleted], RevealedAccount::Absent);

    let trie = state.trie.as_ref().unwrap();
    assert_eq!(
        trie.state_root(),
        root,
        "the retained root is not a post-state root"
    );
    let RevealedAccount::Present(original) = trie.account(changed).unwrap() else {
        panic!("pre-state account must still be provable");
    };
    assert_eq!(original.balance, U256::from(7));
    assert_eq!(original.nonce, U256::one());
    assert_eq!(original.code_hash, keccak256(CODE));
    assert_eq!(account.storage_root, original.storage_root);
    assert_eq!(
        trie.slot(changed, original.storage_root, slot(1)).unwrap(),
        old_value
    );
    assert_eq!(
        trie.slot(changed, original.storage_root, slot(2)).unwrap(),
        H256::zero()
    );
    assert!(matches!(
        trie.account(deleted).unwrap(),
        RevealedAccount::Present(_)
    ));
}

#[test]
fn empty_witness_trie_is_distinct_from_materialized_state() {
    let witness = WitnessBackend::from_witness(
        vicinity(),
        ExecutionWitness::default(),
        EMPTY_ROOT_HASH,
        BTreeMap::new(),
    )
    .unwrap()
    .try_into_state()
    .unwrap();
    let partial = backend(vec![], vec![]).try_into_state().unwrap();
    let complete = WitnessBackend::from_full_state(vicinity(), BTreeMap::new(), BTreeMap::new())
        .try_into_state()
        .unwrap();

    for state in [&witness, &partial, &complete] {
        assert!(state.accounts.is_empty());
        assert!(state.codes.is_empty());
    }
    let trie = witness.trie.as_ref().unwrap();
    assert_eq!(trie.state_root(), EMPTY_ROOT_HASH);
    assert!(trie.nodes().is_empty());
    assert_eq!(trie.account(addr(1)).unwrap(), RevealedAccount::Absent);
    assert!(partial.trie.is_none());
    assert!(complete.trie.is_none());
    // Equality covers the retained trie, not only the revealed maps.
    assert_ne!(witness, partial);
    assert_eq!(partial, complete);
}

#[test]
fn trie_transfer_preserves_missing_and_malformed_error_kinds() {
    let who = addr(0xc0);
    let (root, mut witness) =
        witness_of(&[(who, memory_account(7, 1, &[], &[(slot(1), slot(2))]))]);
    let storage_root = crate::trie::storage_root(&BTreeMap::from([(slot(1), slot(2))]));
    witness.state.retain(|node| keccak256(node) != storage_root);
    let db = WitnessBackend::from_witness(vicinity(), witness, root, BTreeMap::new()).unwrap();
    assert_eq!(db.storage(who, slot(1)), H256::zero());
    // A later failure must not replace the first missing-node error.
    db.block_hash(U256::from(999));
    assert_eq!(
        db.try_into_state().unwrap_err(),
        WitnessDbError::BlindedNode { hash: storage_root }
    );

    let malformed = vec![0xc0];
    let root = keccak256(&malformed);
    let witness = ExecutionWitness {
        state: vec![malformed],
        ..ExecutionWitness::default()
    };
    let db = WitnessBackend::from_witness(vicinity(), witness, root, BTreeMap::new()).unwrap();
    assert!(!db.exists(who));
    assert_eq!(
        db.try_into_state().unwrap_err(),
        WitnessDbError::MalformedNode { hash: root }
    );
}

#[test]
fn transfer_does_not_eagerly_validate_unused_witness_nodes() {
    let malformed = vec![0xc0];
    let hash = keccak256(&malformed);
    let witness = ExecutionWitness {
        state: vec![malformed],
        ..ExecutionWitness::default()
    };
    let db = WitnessBackend::from_witness(vicinity(), witness, EMPTY_ROOT_HASH, BTreeMap::new())
        .unwrap();
    let state = db.try_into_state().unwrap();
    let trie = state.trie.as_ref().unwrap();
    assert_eq!(trie.state_root(), EMPTY_ROOT_HASH);
    assert!(trie.nodes().contains(&hash.0));
    assert_eq!(
        trie.nodes().get(hash.0, &[0; 32]),
        Err(aurora_evm_trie::sparse::LookupError::MalformedNode(hash.0))
    );
}
