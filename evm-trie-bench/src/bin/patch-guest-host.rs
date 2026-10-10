//! Small RV32 acceptance benchmark for the isolated sparse overlay.

use aurora_evm_trie::sparse::reference::hashed_nodes;
use aurora_evm_trie_bench::{
    KeccakHasher,
    patch_guest::{Input, Output, Update},
};
use hash_db::Hasher;
use risc0_zkvm::{ExecutorEnv, default_executor};
use std::{collections::BTreeMap, error::Error};

fn key(index: usize) -> [u8; 32] {
    KeccakHasher::hash(&u64::try_from(index).unwrap().to_be_bytes())
}

fn input(size: usize, count: usize, noop: bool) -> Input {
    let mut map: BTreeMap<Vec<u8>, Vec<u8>> =
        (0..size).map(|i| (key(i).to_vec(), vec![1; 40])).collect();
    let (root, nodes) = hashed_nodes(&map);
    let mut updates = Vec::new();
    for index in 0..count {
        let value = if noop { vec![1; 40] } else { vec![2; 80] };
        updates.push(Update {
            key: key(index),
            value: Some(value.clone()),
        });
        map.insert(key(index).to_vec(), value);
    }
    if !noop {
        for index in size..size + count {
            updates.push(Update {
                key: key(index),
                value: Some(vec![3; 40]),
            });
            map.insert(key(index).to_vec(), vec![3; 40]);
        }
        for index in count..count * 2 {
            updates.push(Update {
                key: key(index),
                value: None,
            });
            map.remove(key(index).as_slice());
        }
    }
    let expected = triehash::trie_root::<KeccakHasher, _, _, _>(&map);
    let mut alloy = alloy_trie::HashBuilder::default();
    for (key, value) in &map {
        alloy.add_leaf(alloy_trie::Nibbles::unpack(key), value);
    }
    assert_eq!(alloy.root().0, expected);
    Input {
        root,
        nodes,
        updates,
        expected,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let elf = std::fs::read(
        std::env::args()
            .nth(1)
            .ok_or("usage: patch-guest-host ELF")?,
    )?;
    let elf = risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    for (size, count, noop) in [
        (128, 16, false),
        (1000, 64, false),
        (1000, 64, true),
        (0, 65, false),
    ] {
        let input = if size == 0 {
            deep_input()
        } else {
            input(size, count, noop)
        };
        let expected = input.expected;
        let env = ExecutorEnv::builder().write(&input)?.build()?;
        let session = default_executor().execute(env, &elf)?;
        let output: Output = session.journal.decode()?;
        assert_eq!(output.root, expected);
        println!(
            "size={size} updates={} noop={noop} session={} segments={} build={:?} initialize={:?}",
            input.updates.len(),
            session.cycles(),
            session.segments.len(),
            output.build,
            output.initialize
        );
        for (index, round) in output.rounds.iter().enumerate() {
            println!(
                "  round={index} update={:?} finalize={:?} cached={:?}",
                round.update, round.finalize, round.cached
            );
            assert_eq!(round.cached.heap, 0);
            if noop {
                assert_eq!(round.update.heap, 0);
            }
            if index > 0 {
                assert_eq!(round.update.heap + round.finalize.heap, 0);
            }
        }
    }
    Ok(())
}

/// Synthetic prehashed keys put a branch at every nibble depth, checking the RV32 stack bound.
fn deep_input() -> Input {
    let mut map = BTreeMap::new();
    map.insert(vec![0; 32], vec![1; 40]);
    for depth in 0..64 {
        let mut key = vec![0; 32];
        key[depth / 2] = if depth % 2 == 0 { 0x10 } else { 1 };
        map.insert(key, vec![1; 40]);
    }
    let expected = triehash::trie_root::<KeccakHasher, _, _, _>(&map);
    let mut alloy = alloy_trie::HashBuilder::default();
    for (key, value) in &map {
        alloy.add_leaf(alloy_trie::Nibbles::unpack(key), value);
    }
    assert_eq!(alloy.root().0, expected);
    let updates = map
        .into_iter()
        .map(|(key, value)| Update {
            key: key.try_into().unwrap(),
            value: Some(value),
        })
        .collect();
    Input {
        root: alloy_trie::EMPTY_ROOT_HASH.0,
        nodes: vec![],
        updates,
        expected,
    }
}
