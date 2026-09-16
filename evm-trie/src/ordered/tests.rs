use super::{
    NodeBuffer, SliceValues, TrieHasher, capacity_for, finish_node, leaf_prefix, root, root_of,
    root_with_encoder,
};
use sha3::{Digest, Keccak256};

#[derive(Default, Debug)]
struct ReferenceHasher;

impl hash_db::Hasher for ReferenceHasher {
    type Out = [u8; 32];
    type StdHasher = plain_hasher::PlainHasher;
    const LENGTH: usize = 32;
    fn hash(bytes: &[u8]) -> Self::Out {
        Keccak256::digest(bytes).into()
    }
}

fn expected(values: &[Vec<u8>]) -> [u8; 32] {
    triehash::ordered_trie_root::<ReferenceHasher, _>(values)
}

fn values(count: usize, length: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let mut value = vec![i.to_le_bytes()[0]; length];
            // Distinguish keys across the 256 boundary rather than repeating the same 256 values.
            for (byte, source) in value.iter_mut().zip(i.to_be_bytes()) {
                *byte = source;
            }
            value
        })
        .collect()
}

#[test]
fn index_boundaries_and_scratch_bound_match_the_reference() {
    for count in (0..=260).chain([
        511, 512, 513, 4095, 4096, 4097, 65535, 65536, 65537, 100_000,
    ]) {
        let values = values(count, 37);
        let reference = expected(&values);
        assert_eq!(root_of(&values), reference, "count={count}");
        if count >= 2 {
            // The exact computed bound, not the larger production tier, must be sufficient.
            let mut scratch = vec![0; capacity_for(count)];
            assert_eq!(root(&mut scratch, &mut SliceValues(&values)), reference);
        }
    }
}

#[test]
fn inline_threshold_uses_the_entire_encoded_node() {
    for (value_len, node_len) in [(28, 31), (29, 32), (30, 33)] {
        let mut head = [0; 32];
        let value = vec![0x81; value_len];
        let (prefix, tail) = leaf_prefix(&mut head, 0, 0, &value);
        assert_eq!(prefix + tail, node_len);
    }
    for payload_len in [30, 31, 32] {
        let mut data = [0u8; 100];
        let mut buffer = NodeBuffer {
            data: &mut data,
            len: 0,
            hasher: TrieHasher::new(),
        };
        buffer.extend(&vec![0x80; payload_len]);
        finish_node(&mut buffer, 0);
        if payload_len == 30 {
            assert_eq!(buffer.len, 31);
            assert_eq!(buffer.data[0], 0xde);
        } else {
            assert_eq!(buffer.len, 33);
            assert_eq!(buffer.data[0], 0xa0);
            let mut stream = rlp::RlpStream::new_list(payload_len);
            for _ in 0..payload_len {
                stream.append_empty_data();
            }
            assert_eq!(&buffer.data[1..33], &Keccak256::digest(stream.out())[..]);
        }
    }
}

#[test]
fn values_cross_rlp_and_keccak_boundaries() {
    for length in [
        0, 1, 2, 27, 28, 29, 30, 31, 32, 33, 55, 56, 57, 135, 136, 137, 255, 256, 65535, 65536,
    ] {
        for count in [1, 2, 17, 129] {
            let values = values(count, length);
            assert_eq!(
                root_of(&values),
                expected(&values),
                "count={count}, length={length}"
            );
        }
    }
    for byte in [0, 1, 0x7f, 0x80, 0xff] {
        let values = vec![vec![byte]; 17];
        assert_eq!(root_of(&values), expected(&values));
    }
}

#[test]
fn leaf_prefix_covers_every_native_key_width() {
    for remaining in 0..=size_of::<usize>() * 2 {
        for path in [0usize, 0x1234, usize::MAX] {
            let nibbles: Vec<_> = (0..remaining)
                .rev()
                .map(|offset| (path >> (offset * 4)).to_le_bytes()[0] & 15)
                .collect();
            let odd = remaining % 2 == 1;
            let mut compact = vec![if odd { 0x30 | nibbles[0] } else { 0x20 }];
            for pair in nibbles[usize::from(odd)..].chunks_exact(2) {
                compact.push(pair[0] * 16 + pair[1]);
            }
            for value in [
                vec![],
                vec![0x7f],
                vec![0x80],
                vec![0x81; 56],
                vec![0x81; 65536],
            ] {
                let mut reference = rlp::RlpStream::new_list(2);
                reference.append(&compact).append(&value);
                let mut prefix = [0; 32];
                let (written, tail) = leaf_prefix(&mut prefix, path, remaining, &value);
                let mut encoded = prefix[..written].to_vec();
                if tail != 0 {
                    encoded.extend_from_slice(&value);
                }
                assert_eq!(encoded, reference.out());
            }
        }
    }
}

#[test]
fn empty_streaming_root_does_not_invoke_the_encoder() {
    assert_eq!(
        root_with_encoder::<u64, _>(&[], |_, _| panic!("empty trie invoked encoder")),
        expected(&[])
    );
}

#[test]
fn streaming_visits_each_index_once_and_reuses_a_shrinking_value_buffer() {
    let values: Vec<_> = (0usize..260)
        .map(|i| vec![i.to_le_bytes()[0]; if i % 2 == 0 { 4096 } else { 1 }])
        .collect();
    let encoded: Vec<_> = values
        .iter()
        .map(|value| rlp::encode(value).to_vec())
        .collect();
    let indices: Vec<_> = (0..values.len()).collect();
    let mut visited = Vec::new();
    let actual = root_with_encoder(&indices, |&index, stream| {
        visited.push(index);
        stream.clear();
        stream.append(&values[index]);
        stream.as_raw()
    });
    assert_eq!(actual, expected(&encoded));
    let mut sorted = indices;
    sorted.sort_by_key(|i| rlp::encode(i).to_vec());
    assert_eq!(visited, sorted);
}
