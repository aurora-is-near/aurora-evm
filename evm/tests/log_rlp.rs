//! Ethereum log wire encoding, including a pinned EEST v20.0.2 logs hash.

use aurora_evm::backend::Log;
use primitive_types::{H160, H256};
use rlp::{DecoderError, RlpStream};
use sha3::{Digest, Keccak256};

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn data_is_a_string_at_rlp_length_boundaries() {
    // Independent wire bytes: address = 0x11 * 20, no topics, then the data string.
    for (data, encoded_data, outer) in [
        (vec![], vec![0x80], vec![0xd7]),
        (vec![0], vec![0], vec![0xd7]),
        (vec![0x7f], vec![0x7f], vec![0xd7]),
        (vec![0x80], vec![0x81, 0x80], vec![0xd8]),
        (vec![1, 2], vec![0x82, 1, 2], vec![0xd9]),
        (
            vec![0xab; 55],
            [vec![0xb7], vec![0xab; 55]].concat(),
            vec![0xf8, 78],
        ),
        (
            vec![0xab; 56],
            [vec![0xb8, 56], vec![0xab; 56]].concat(),
            vec![0xf8, 80],
        ),
        (
            vec![0xab; 256],
            [vec![0xb9, 1, 0], vec![0xab; 256]].concat(),
            vec![0xf9, 1, 25],
        ),
    ] {
        let log = Log {
            address: H160([0x11; 20]),
            topics: vec![],
            data,
        };
        let expected = [outer, vec![0x94], vec![0x11; 20], vec![0xc0], encoded_data].concat();

        assert_eq!(rlp::encode(&log).as_ref(), expected);
        assert_eq!(rlp::decode::<Log>(&expected).unwrap(), log);
    }
}

#[test]
fn log_list_matches_eest_commitment() {
    // EEST v20.0.2, stLogTests/log2_non_empty_mem_log_mem_size1_log_mem_start31:
    // LOG2 emits the last byte of a word and two zero topics.
    let log = Log {
        address: H160::from_slice(&bytes("931d278637a9ddbe64fd613bc2ab1a65bda4ebcc")),
        topics: vec![H256::zero(), H256::zero()],
        data: vec![0xdd],
    };
    let encoded = rlp::encode_list(core::slice::from_ref(&log));

    assert_eq!(
        &Keccak256::digest(&encoded)[..],
        bytes("f98bbca50c0a2dc0c0608fe8f507183714ebbc02bf4972d90ad015e01ee11fa1")
    );
    assert_eq!(rlp::decode_list::<Log>(&encoded), vec![log]);
}

fn raw_log(address: &[u8], topics: &[u8], data: &[u8]) -> Vec<u8> {
    let mut stream = RlpStream::new_list(3);
    stream.append(&address);
    stream.append_raw(topics, 1);
    stream.append_raw(data, 1);
    stream.out().to_vec()
}

#[test]
fn log_fields_must_be_wrapped_in_a_list() {
    let log = Log::default();
    let list = rlp::encode(&log);
    let fields = rlp::Rlp::new(&list).data().unwrap();
    let string = rlp::encode(&fields);

    assert_eq!(rlp::decode::<Log>(&list), Ok(log));
    assert_eq!(
        rlp::decode::<Log>(&string),
        Err(DecoderError::RlpExpectedToBeList)
    );
}

#[test]
fn decoder_rejects_wrong_field_types_and_lengths() {
    for data in [&[0xc0][..], &[0xc2, 1, 2]] {
        assert_eq!(
            rlp::decode::<Log>(&raw_log(&[0; 20], &[0xc0], data)),
            Err(DecoderError::RlpExpectedToBeData)
        );
    }

    for len in [0, 19, 21] {
        assert!(rlp::decode::<Log>(&raw_log(&vec![0; len], &[0xc0], &[0x80])).is_err());
    }

    for len in [0, 31, 33] {
        let mut topics = RlpStream::new_list(1);
        topics.append(&vec![0; len]);

        assert!(rlp::decode::<Log>(&raw_log(&[0; 20], &topics.out(), &[0x80])).is_err());
    }

    assert!(rlp::decode::<Log>(&raw_log(&[0; 20], &[0x80], &[0x80])).is_err());

    // A single byte below 0x80 must not carry a string prefix.
    assert_eq!(
        rlp::decode::<Log>(&raw_log(&[0; 20], &[0xc0], &[0x81, 1])),
        Err(DecoderError::RlpInvalidIndirection)
    );

    for count in [0, 2, 4] {
        let mut stream = RlpStream::new_list(count);

        for _ in 0..count {
            stream.append_empty_data();
        }

        assert_eq!(
            rlp::decode::<Log>(&stream.out()),
            Err(DecoderError::RlpIncorrectListLen)
        );
    }
}

#[test]
fn decoder_requires_exact_input_and_complete_list_payloads() {
    let encoded = rlp::encode(&Log::default());
    let mut with_suffix = encoded.to_vec();
    with_suffix.push(0x80);

    assert_eq!(
        rlp::decode::<Log>(&with_suffix),
        Err(DecoderError::RlpIsTooBig)
    );

    // Include a partial fourth field inside the list, not after it.
    let mut fields = RlpStream::new_list(4);
    fields.append(&H160::zero());
    fields.begin_list(0);
    fields.append_empty_data();
    fields.append_raw(&[0x82], 1);

    assert!(rlp::decode::<Log>(&fields.out()).is_err());

    // A valid topic must not hide a truncated second topic in the same list.
    let mut topics = RlpStream::new_list(2);
    topics.append(&H256::zero());
    topics.append_raw(&[0xa0], 1);
    let encoded = raw_log(&[0; 20], &topics.out(), &[0x80]);

    assert!(rlp::decode::<Log>(&encoded).is_err());
}

#[test]
fn nested_logs_keep_item_boundaries() {
    let logs = vec![
        Log::default(),
        Log {
            address: H160([2; 20]),
            topics: vec![H256([3; 32]); 4],
            data: vec![4; 56],
        },
        Log {
            data: vec![0x7f],
            ..Log::default()
        },
    ];
    let encoded = rlp::encode_list(&logs);
    let list = rlp::Rlp::new(&encoded);

    assert_eq!(list.item_count().unwrap(), 3);

    for (index, log) in logs.iter().enumerate() {
        let item = list.at(index).unwrap();

        assert_eq!(item.item_count().unwrap(), 3);
        assert_eq!(item.at(1).unwrap().item_count().unwrap(), log.topics.len());
        assert_eq!(item.at(2).unwrap().data().unwrap(), log.data);
    }

    assert_eq!(rlp::decode_list::<Log>(&encoded), logs);
}
