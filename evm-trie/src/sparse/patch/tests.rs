//! Differential roots, canonical compression, and fail-closed partial witnesses.

use super::*;
use crate::sparse::tests::reference::hashed_nodes;
use hash_db::Hasher;
use plain_hasher::PlainHasher;
use std::collections::BTreeMap;

#[derive(Debug)]
struct Keccak;

impl Hasher for Keccak {
    type Out = [u8; 32];
    type StdHasher = PlainHasher;
    const LENGTH: usize = 32;
    fn hash(bytes: &[u8]) -> Self::Out {
        keccak256(bytes)
    }
}

type Map = BTreeMap<Vec<u8>, Vec<u8>>;

fn root(map: &Map) -> [u8; 32] {
    // Keys are already hashed; sec_trie_root here would accidentally hash them a second time.
    triehash::trie_root::<Keccak, _, _, _>(map)
}

fn key(index: u64) -> [u8; 32] {
    keccak256(&index.to_be_bytes())
}

fn fixture(map: &Map) -> ([u8; 32], NodeStore) {
    let (hash, nodes) = hashed_nodes(map);
    assert_eq!(hash, root(map));
    (hash, NodeStore::new(nodes))
}

#[test]
fn empty_insert_replace_remove_and_reset() {
    let store = NodeStore::default();
    let mut trie = PatchTrie::new(&store, EMPTY_ROOT_HASH);
    let mut map = Map::new();
    assert_eq!(trie.root_hash(), Ok(root(&map)));
    assert_eq!(trie.remove(&key(1)), Ok(false));
    for value in [vec![1], vec![0; 100], vec![0x80]] {
        assert_eq!(trie.insert(&key(1), &value), Ok(true));
        map.insert(key(1).to_vec(), value);
        assert_eq!(trie.root_hash(), Ok(root(&map)));
    }
    assert_eq!(trie.remove(&key(1)), Ok(true));
    assert_eq!(trie.root_hash(), Ok(EMPTY_ROOT_HASH));
    let capacities = (
        trie.nodes.capacity(),
        trie.branches.capacity(),
        trie.values.capacity(),
    );
    trie.reset(EMPTY_ROOT_HASH);
    assert_eq!(
        (
            trie.nodes.capacity(),
            trie.branches.capacity(),
            trie.values.capacity()
        ),
        capacities
    );
    assert!(trie.nodes.is_empty() && trie.branches.is_empty() && trie.values.is_empty());
    assert_eq!(trie.insert(&key(2), &[2]), Ok(true));
    assert_eq!(
        trie.root_hash(),
        Ok(root(&Map::from([(key(2).to_vec(), vec![2])])))
    );
}

#[test]
fn noops_preserve_witness_hashes_without_retaining_readonly_paths() {
    let map = Map::from([
        (key(1).to_vec(), vec![1; 80]),
        (key(2).to_vec(), vec![2; 80]),
    ]);
    let (hash, store) = fixture(&map);
    let mut trie = PatchTrie::new(&store, hash);
    assert_eq!(trie.insert(&key(1), &[1; 80]), Ok(false));
    assert_eq!(trie.remove(&key(3)), Ok(false));
    assert_eq!(trie.root_hash(), Ok(hash));
    assert_eq!(trie.hashes, 0);
    assert!(trie.values.is_empty());
    assert!(trie.nodes.is_empty() && trie.branches.is_empty());
    let node_count = trie.nodes.len();
    assert_eq!(trie.insert(&key(1), &[1; 80]), Ok(false));
    assert_eq!(trie.nodes.len(), node_count);
}

#[test]
fn splitting_a_leaf_borrows_its_original_value() {
    let map = Map::from([(key(1).to_vec(), vec![1; 80])]);
    let (hash, store) = fixture(&map);
    let original = store.get(hash, &key(1)).unwrap().unwrap();
    let mut trie = PatchTrie::new(&store, hash);
    trie.insert(&key(2), &[2; 80]).unwrap();
    assert!(trie.nodes.iter().any(|node| matches!(node.kind,
        Kind::Leaf { value: Value::Borrowed(value), .. } if core::ptr::eq(value, original))));
    assert_eq!(trie.values.len(), 80);
}

#[test]
fn dirty_nodes_are_hashed_once_and_reset_preserves_arenas() {
    let map: Map = (0..32).map(|i| (key(i).to_vec(), vec![1; 80])).collect();
    let (hash, store) = fixture(&map);
    let mut trie = PatchTrie::new(&store, hash);
    assert!(trie.insert(&key(0), &[2; 80]).unwrap());
    let updated = trie.root_hash().unwrap();
    let hashes = trie.hashes;
    assert!(hashes > 0 && hashes < store.len());
    for _ in 0..4 {
        assert_eq!(trie.insert(&key(0), &[2; 80]), Ok(false));
        assert_eq!(trie.root_hash(), Ok(updated));
    }
    assert_eq!(trie.hashes, hashes);
    trie.reset(hash);
    assert_eq!(trie.root_hash(), Ok(hash));
    assert_eq!(trie.hashes, 0);
}

/// Adjacent suffixes force inline children and deep path compression without hash preimage search.
fn nearby(last: u8) -> [u8; 32] {
    let mut key = [0x12; 32];
    key[31] = last;
    key
}

#[test]
fn inline_hash_boundary_and_extension_splits_match_reference() {
    let mut map = Map::from([(nearby(0).to_vec(), vec![1]), (nearby(1).to_vec(), vec![2])]);
    let (hash, store) = fixture(&map);
    let mut trie = PatchTrie::new(&store, hash);
    // An empty suffix leaf has encoded length value.len() + 3: 31, 32, then 33 bytes.
    for length in [28, 29, 30, 1, 56, 55, 200, 1] {
        let value = vec![0x42; length];
        trie.insert(&nearby(0), &value).unwrap();
        map.insert(nearby(0).to_vec(), value);
        assert_eq!(trie.root_hash(), Ok(root(&map)), "value length {length}");
    }
    for position in [0, 1, 15, 30, 31] {
        let mut other = nearby(2);
        other[position] ^= 0xf0;
        trie.insert(&other, &[3]).unwrap();
        map.insert(other.to_vec(), vec![3]);
        assert_eq!(trie.root_hash(), Ok(root(&map)));
        trie.remove(&other).unwrap();
        map.remove(other.as_slice());
        assert_eq!(trie.root_hash(), Ok(root(&map)));
    }
    trie.remove(&nearby(1)).unwrap();
    map.remove(nearby(1).as_slice());
    assert_eq!(trie.root_hash(), Ok(root(&map)));
}

#[test]
fn canonical_upserts_avoid_an_unrevealed_collapse_sibling() {
    let a = [0; 32];
    let b = [0x10; 32];
    let c = [0x20; 32];
    let mut map = Map::from([(a.to_vec(), vec![1; 40]), (b.to_vec(), vec![2; 40])]);
    let (hash, nodes) = hashed_nodes(&map);
    let sibling = nodes
        .iter()
        .find(|node| {
            let decoded = Decoded::decode(node).unwrap();
            matches!(decoded.view(node), Node::Leaf { value, .. } if value == [2; 40])
        })
        .unwrap();
    let withheld = keccak256(sibling);
    let store = NodeStore::new(nodes.into_iter().filter(|node| keccak256(node) != withheld));
    let mut trie = PatchTrie::new(&store, hash);
    let error = PatchError::Node(LookupError::BlindedNode(withheld));
    assert_eq!(trie.remove(&a), Err(error));
    // The removal already touched the overlay; none of its intermediate roots may escape.
    assert_eq!(trie.root_hash(), Err(error));
    assert_eq!(trie.insert(&c, &[3; 40]), Err(error));
    assert_eq!(trie.remove(&c), Err(error));
    trie.reset(hash);
    trie.insert(&c, &[3; 40]).unwrap();
    trie.remove(&a).unwrap();
    map.insert(c.to_vec(), vec![3; 40]);
    map.remove(a.as_slice());
    assert_eq!(trie.root_hash(), Ok(root(&map)));
    assert!(!store.contains(&withheld));
}

#[test]
fn full_witness_allows_collapse_to_hashed_leaf_extension_and_branch() {
    for keys in [
        vec![[0; 32], [0x10; 32]],
        vec![[0; 32], nearby(0), nearby(1)],
        vec![[0; 32], [0x10; 32], [0x11; 32]],
    ] {
        let mut map: Map = keys.iter().map(|key| (key.to_vec(), vec![1; 40])).collect();
        let (hash, store) = fixture(&map);
        let mut trie = PatchTrie::new(&store, hash);
        for key in keys {
            assert_eq!(trie.remove(&key), Ok(true));
            map.remove(key.as_slice());
            assert_eq!(trie.root_hash(), Ok(root(&map)));
        }
    }
}

#[test]
fn proof_of_absence_does_not_resolve_hidden_children() {
    let map = Map::from([
        (nearby(0).to_vec(), vec![1; 40]),
        (nearby(1).to_vec(), vec![2; 40]),
    ]);
    let (hash, nodes) = hashed_nodes(&map);
    let store = NodeStore::new(nodes.into_iter().filter(|node| keccak256(node) == hash));
    let mut trie = PatchTrie::new(&store, hash);
    assert_eq!(trie.remove(&[0; 32]), Ok(false));
    assert_eq!(trie.root_hash(), Ok(hash));
    assert_eq!(trie.hashes, 0);
    trie.insert(&[0; 32], &[3]).unwrap();
    let mut updated = map;
    updated.insert(vec![0; 32], vec![3]);
    assert_eq!(trie.root_hash(), Ok(root(&updated)));
}

#[test]
fn empty_values_and_missing_roots_poison_until_reset() {
    let store = NodeStore::default();
    let mut trie = PatchTrie::new(&store, EMPTY_ROOT_HASH);
    assert_eq!(trie.insert(&key(0), &[]), Err(PatchError::EmptyValue));
    assert_eq!(trie.root_hash(), Err(PatchError::EmptyValue));
    trie.reset([1; 32]);
    let error = PatchError::Node(LookupError::BlindedNode([1; 32]));
    assert_eq!(trie.remove(&key(0)), Err(error));
    assert_eq!(trie.root_hash(), Err(error));
    trie.reset(EMPTY_ROOT_HASH);
    assert_eq!(trie.root_hash(), Ok(EMPTY_ROOT_HASH));
}

fn reject(nodes: Vec<Vec<u8>>, root: [u8; 32], key: [u8; 32], bad: [u8; 32]) {
    let store = NodeStore::new(nodes);
    for insert in [false, true] {
        let mut trie = PatchTrie::new(&store, root);
        let error = PatchError::Node(LookupError::MalformedNode(bad));
        let result = if insert {
            trie.insert(&key, &[7])
        } else {
            trie.remove(&key)
        };
        assert_eq!(result, Err(error));
        assert_eq!(trie.root_hash(), Err(error));
    }
}

#[test]
fn malformed_paths_and_nonsecure_nodes_are_rejected_without_panics() {
    for raw in [
        vec![],
        vec![0xff; 9],
        vec![0xc3, 0x20, 1, 0xb8],
        vec![0xc2, 0x20, 1], // A valid generic leaf, but not a 32-byte-key root.
        vec![0xc2, 0x20, 0x80], // Empty leaf value.
    ] {
        let hash = keccak256(&raw);
        reject(vec![raw], hash, [0; 32], hash);
    }
    let mut stream = rlp::RlpStream::new_list(2);
    stream.append(&vec![0x20; 100]).append(&1u8);
    let raw = stream.out().to_vec();
    let hash = keccak256(&raw);
    reject(vec![raw], hash, [0; 32], hash);
}

#[test]
fn hashed_extension_target_must_be_a_branch() {
    let mut leaf = rlp::RlpStream::new_list(2);
    leaf.append(&vec![0x30; 32]).append(&vec![1; 40]);
    let leaf = leaf.out().to_vec();
    let leaf_hash = keccak256(&leaf);
    let mut extension = rlp::RlpStream::new_list(2);
    extension.append(&vec![0x10]).append(&leaf_hash.as_slice());
    let extension = extension.out().to_vec();
    let root = keccak256(&extension);
    reject(vec![extension, leaf], root, [0; 32], leaf_hash);
}

fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn differential_sequences_check_every_intermediate_root() {
    for seed in 1..=8 {
        let mut rng = seed;
        let mut map: Map = (0..48)
            .map(|i| (key(i).to_vec(), vec![i.to_le_bytes()[0]; 40]))
            .collect();
        let (hash, store) = fixture(&map);
        let mut trie = PatchTrie::new(&store, hash);
        for step in 0..300 {
            let key = key(random(&mut rng) % 96);
            if random(&mut rng).is_multiple_of(3) {
                let changed = map.remove(key.as_slice()).is_some();
                assert_eq!(trie.remove(&key), Ok(changed));
            } else {
                let len = usize::try_from(random(&mut rng) % 100 + 1).unwrap();
                let value = vec![random(&mut rng).to_le_bytes()[0]; len];
                let changed = map.get(key.as_slice()) != Some(&value);
                assert_eq!(trie.insert(&key, &value), Ok(changed));
                map.insert(key.to_vec(), value);
            }
            assert_eq!(trie.root_hash(), Ok(root(&map)), "seed {seed}, step {step}");
        }
    }
}

#[test]
fn arbitrary_witness_bytes_fail_closed() {
    let mut rng = 7;
    for len in 0..160 {
        for _ in 0..8 {
            let raw: Vec<_> = (0..len)
                .map(|_| random(&mut rng).to_le_bytes()[0])
                .collect();
            let hash = keccak256(&raw);
            let store = NodeStore::new([raw]);
            let mut trie = PatchTrie::new(&store, hash);
            if let Err(error) = trie.insert(&key(random(&mut rng)), &[1]) {
                assert_eq!(trie.root_hash(), Err(error));
            }
        }
    }
}

#[test]
fn noops_under_an_extension_do_not_dirty_or_accumulate_nodes() {
    let map: Map = (0..32u8)
        .map(|i| (nearby(i).to_vec(), vec![i; 40]))
        .collect();
    let (hash, store) = fixture(&map);
    let mut trie = PatchTrie::new(&store, hash);
    for i in 0..32u8 {
        assert_eq!(trie.insert(&nearby(i), &[i; 40]), Ok(false));
        assert_eq!(trie.root_hash(), Ok(hash));
        assert!(trie.nodes.is_empty() && trie.branches.is_empty());
    }
    assert_eq!(trie.hashes, 0);
    assert!(trie.values.is_empty());
    assert_eq!(
        trie.nodes.capacity() + trie.branches.capacity() + trie.values.capacity(),
        0
    );
}

#[test]
fn batch_updates_and_deep_branches_match_the_reference() {
    let mut map = Map::new();
    let store = NodeStore::default();
    let mut trie = PatchTrie::new(&store, EMPTY_ROOT_HASH);
    // A branch at every nibble depth exercises the full 64-nibble recursion bound.
    let keys: Vec<_> = (0..64)
        .map(|depth| {
            let mut key = [0; 32];
            key[depth / 2] = if depth % 2 == 0 { 0x10 } else { 1 };
            key
        })
        .collect();
    for (i, key) in keys.iter().enumerate() {
        let value = vec![i.to_le_bytes()[0]; 40];
        trie.insert(key, &value).unwrap();
        map.insert(key.to_vec(), value);
    }
    assert_eq!(trie.root_hash(), Ok(root(&map)));
    for key in keys.iter().rev() {
        trie.remove(key).unwrap();
        map.remove(key.as_slice());
        assert_eq!(trie.root_hash(), Ok(root(&map)));
    }
}

#[test]
fn reset_switches_between_roots_in_one_store() {
    let a = Map::from([(key(1).to_vec(), vec![1])]);
    let b = Map::from([(key(2).to_vec(), vec![2])]);
    let (a_root, mut nodes) = hashed_nodes(&a);
    let (b_root, other) = hashed_nodes(&b);
    nodes.extend(other);
    let store = NodeStore::new(nodes);
    let mut trie = PatchTrie::new(&store, a_root);
    trie.insert(&key(3), &[3]).unwrap();
    trie.root_hash().unwrap();
    trie.reset(b_root);
    trie.remove(&key(2)).unwrap();
    assert_eq!(trie.root_hash(), Ok(EMPTY_ROOT_HASH));
    trie.reset(a_root);
    assert_eq!(trie.root_hash(), Ok(a_root));
}

#[test]
fn hashed_short_child_and_branch_terminal_values_are_rejected() {
    let short = vec![0xc2, 0x20, 1];
    let short_hash = keccak256(&short);
    let mut branch = rlp::RlpStream::new_list(17);
    branch.append(&short_hash.as_slice());
    branch.append(&[7u8; 32].as_slice());
    for _ in 2..17 {
        branch.append_empty_data();
    }
    let raw = branch.out().to_vec();
    let hash = keccak256(&raw);
    reject(vec![raw, short], hash, [0; 32], short_hash);

    let mut branch = rlp::RlpStream::new_list(17);
    branch.append(&[7u8; 32].as_slice());
    for _ in 1..16 {
        branch.append_empty_data();
    }
    branch.append(&1u8);
    let raw = branch.out().to_vec();
    let hash = keccak256(&raw);
    reject(vec![raw], hash, [0; 32], hash);
}

/// Four-field Ethereum account encoding, kept in the test rather than the generic trie library.
fn account(nonce: u64, balance: &str, storage: [u8; 32], code: &[u8]) -> Vec<u8> {
    let mut stream = rlp::RlpStream::new_list(4);
    stream.append(&nonce);
    stream.append(&hex::decode(balance).unwrap());
    stream.append(&storage.as_slice());
    stream.append(&keccak256(code).as_slice());
    stream.out().to_vec()
}

/// EEST v5.4.0, `blockchain_tests/berlin/eip2930_access_list/test_repeated_address_acl.json`,
/// `fork_Berlin-blockchain_test_from_state_test`; fixture hash `a6f98637..30e6addd`.
/// Uses official pre/post roots, testing MPT transitions only, not Berlin EVM execution.
#[test]
fn eest_access_list_storage_and_account_roots() {
    let sender = keccak256(&hex::decode("f7e89272be947560f09d73c2cd1e8a388d017593").unwrap());
    let contract = keccak256(&hex::decode("8cdf9cd5727230f7cf60842520379509cfa50825").unwrap());
    let beneficiary = keccak256(&hex::decode("2adc25665018aa1fe0e6bc666dac8fc2697ff9ba").unwrap());
    let code =
        hex::decode("5a6000545a90509003600590036000555a6001545a905090036005900360015500").unwrap();
    let pre = Map::from([
        (
            sender.to_vec(),
            account(0, "3635c9adc5dea00000", EMPTY_ROOT_HASH, &[]),
        ),
        (contract.to_vec(), account(1, "", EMPTY_ROOT_HASH, &code)),
    ]);
    let (pre_root, store) = fixture(&pre);
    assert_eq!(
        hex::encode(pre_root),
        "8941020a3e31617a8d1811dc70a5b37771c973f5026473baeb3e5ea342dc2c7c"
    );

    let empty = NodeStore::default();
    let mut storage = PatchTrie::new(&empty, EMPTY_ROOT_HASH);
    let mut slot = [0; 32];
    storage.insert(&keccak256(&slot), &[0x64]).unwrap();
    slot[31] = 1;
    storage.insert(&keccak256(&slot), &[0x64]).unwrap();
    let storage_root = storage.root_hash().unwrap();
    let mut state = PatchTrie::new(&store, pre_root);
    state
        .insert(&contract, &account(1, "", storage_root, &code))
        .unwrap();
    state
        .insert(
            &sender,
            &account(1, "3635c9adc5de955718", EMPTY_ROOT_HASH, &[]),
        )
        .unwrap();
    state
        .insert(
            &beneficiary,
            &account(0, "1bc16d674ed2a8e8", EMPTY_ROOT_HASH, &[]),
        )
        .unwrap();
    assert_eq!(
        hex::encode(state.root_hash().unwrap()),
        "ea0013a3ab0946647c0aa40e90a65367c4bc8dd9fef50df1a7e0d30a510d79f4"
    );
}
