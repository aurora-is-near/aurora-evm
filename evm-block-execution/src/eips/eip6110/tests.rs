use super::{
    DEPOSIT_EVENT_SIGNATURE_HASH, DEPOSIT_LOG_DATA_LENGTH, DEPOSIT_REQUEST_LENGTH, DepositField,
    DepositLogError, MAINNET_DEPOSIT_CONTRACT_ADDRESS, parse_deposits_from_receipts,
};
use crate::crypto::keccak256;
use crate::receipt::Receipt;
use crate::transaction::TxType;
use aurora_evm::backend::Log;
use hex_literal::hex;
use primitive_types::{H160, H256};

/// Mainnet deposit logs of transactions `0xa5239d4c…` and `0xd9734d4e…` (block 19 860 877).
const LOG_A: [u8; DEPOSIT_LOG_DATA_LENGTH] = hex!(
        "00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000"
        "000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000140"
        "000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000"
        "000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000030"
        "998c8086669bf65e24581cda47d8537966e9f5066fc6ffdcba910a1bfb91eae7a4873fcce166a1c4ea217e6b1afd3962"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020"
        "01000000000000000000000001c340fb72ed14d4eaa71f7633ee9e33b88d4f3900000000000000000000000000000000"
        "000000000000000000000000000000080040597307000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000006098ddbffd700c1aac324cfdf0492ff289"
        "223661eb26718ce3651ba2469b22f480d56efab432ed91af05a006bde0c1ea68134e0acd8cacca0c13ad1f716db874b4"
        "4abfcc966368019753174753bca3af2ea84bc569c46f76592a91e97f311eddec00000000000000000000000000000000"
        "00000000000000000000000000000008e474160000000000000000000000000000000000000000000000000000000000"
);
const LOG_B: [u8; DEPOSIT_LOG_DATA_LENGTH] = hex!(
        "00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000"
        "000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000140"
        "000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000"
        "000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000030"
        "a1a2ba870a90e889aa594a0cc1c6feffb94c2d8f65646c937f1f456a315ef649533e25a4614d8f4f66ebdb06481b90af"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020"
        "0100000000000000000000000a0f04a231efbc29e1db7d086300ff550211c2f600000000000000000000000000000000"
        "000000000000000000000000000000080040597307000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000060ad416d590e1a7f52baff770a12835b68"
        "904efad22cc9f8ba531e50cbbd26f32b9c7373cf6538a0577f501e4d3e3e63e208767bcccaae94e1e3720bfb734a286f"
        "9c017d17af46536545ccb7ca94d71f295e71f6d25bf978c09ada6f8d3f7ba03900000000000000000000000000000000"
        "00000000000000000000000000000008e374160000000000000000000000000000000000000000000000000000000000"
);
/// Their request bytes as published by alloy's deposit parser tests.
const EXPECTED: [u8; 2 * DEPOSIT_REQUEST_LENGTH] = hex!(
        "998c8086669bf65e24581cda47d8537966e9f5066fc6ffdcba910a1bfb91eae7a4873fcce166a1c4ea217e6b1afd3962"
        "01000000000000000000000001c340fb72ed14d4eaa71f7633ee9e33b88d4f39004059730700000098ddbffd700c1aac"
        "324cfdf0492ff289223661eb26718ce3651ba2469b22f480d56efab432ed91af05a006bde0c1ea68134e0acd8cacca0c"
        "13ad1f716db874b44abfcc966368019753174753bca3af2ea84bc569c46f76592a91e97f311eddece474160000000000"
        "a1a2ba870a90e889aa594a0cc1c6feffb94c2d8f65646c937f1f456a315ef649533e25a4614d8f4f66ebdb06481b90af"
        "0100000000000000000000000a0f04a231efbc29e1db7d086300ff550211c2f60040597307000000ad416d590e1a7f52"
        "baff770a12835b68904efad22cc9f8ba531e50cbbd26f32b9c7373cf6538a0577f501e4d3e3e63e208767bcccaae94e1"
        "e3720bfb734a286f9c017d17af46536545ccb7ca94d71f295e71f6d25bf978c09ada6f8d3f7ba039e374160000000000"
);

fn deposit_log(data: Vec<u8>) -> Log {
    Log {
        address: MAINNET_DEPOSIT_CONTRACT_ADDRESS,
        topics: vec![DEPOSIT_EVENT_SIGNATURE_HASH],
        data,
    }
}

fn receipt(logs: Vec<Log>) -> Receipt {
    Receipt::new(TxType::Legacy, true, 0, logs)
}

#[test]
fn topic_is_the_event_signature_hash() {
    assert_eq!(
        keccak256(b"DepositEvent(bytes,bytes,bytes,bytes,bytes)"),
        DEPOSIT_EVENT_SIGNATURE_HASH
    );
}

#[test]
fn mainnet_deposits_produce_the_published_request_bytes() {
    let receipts = [
        receipt(vec![deposit_log(LOG_A.to_vec())]),
        receipt(vec![deposit_log(LOG_B.to_vec())]),
    ];
    assert_eq!(
        parse_deposits_from_receipts(&receipts, MAINNET_DEPOSIT_CONTRACT_ADDRESS).unwrap(),
        EXPECTED
    );
}

#[test]
fn abi_padding_does_not_change_the_deposit_request() {
    let mut data = LOG_A;
    for padding in [240..256, 360..384, 552..576] {
        data[padding].fill(0xff);
    }
    let receipts = [receipt(vec![deposit_log(data.to_vec())])];
    assert_eq!(
        parse_deposits_from_receipts(&receipts, MAINNET_DEPOSIT_CONTRACT_ADDRESS).unwrap(),
        EXPECTED[..DEPOSIT_REQUEST_LENGTH]
    );
}

#[test]
fn foreign_logs_and_other_topics_are_ignored() {
    let mut other_address = deposit_log(LOG_A.to_vec());
    other_address.address = H160::repeat_byte(0x11);
    let mut other_topic = deposit_log(LOG_A.to_vec());
    other_topic.topics = vec![H256::repeat_byte(0x22)];
    let no_topic = Log {
        address: MAINNET_DEPOSIT_CONTRACT_ADDRESS,
        topics: Vec::new(),
        data: vec![0xff; 10],
    };
    let receipts = [receipt(vec![other_address, other_topic, no_topic])];
    assert!(
        parse_deposits_from_receipts(&receipts, MAINNET_DEPOSIT_CONTRACT_ADDRESS)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_configured_contract_address_replaces_the_mainnet_one() {
    let custom = H160::repeat_byte(0x33);
    let mut log = deposit_log(LOG_A.to_vec());
    log.address = custom;
    let receipts = [receipt(vec![log])];
    assert_eq!(
        parse_deposits_from_receipts(&receipts, custom).unwrap(),
        EXPECTED[..DEPOSIT_REQUEST_LENGTH]
    );
    assert!(
        parse_deposits_from_receipts(&receipts, MAINNET_DEPOSIT_CONTRACT_ADDRESS)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn truncated_or_padded_data_is_rejected() {
    for len in [0, DEPOSIT_LOG_DATA_LENGTH - 1, DEPOSIT_LOG_DATA_LENGTH + 1] {
        let mut data = LOG_A.to_vec();
        data.resize(len, 0);
        let receipts = [receipt(vec![deposit_log(data)])];
        assert_eq!(
            parse_deposits_from_receipts(&receipts, MAINNET_DEPOSIT_CONTRACT_ADDRESS),
            Err(DepositLogError::Length { got: len })
        );
    }
}

/// Every offset and size word is checked against the canonical layout, as the EEST
/// `test_invalid_layout` cases (`value_zero`, `value_max_uint256`) require.
#[test]
fn every_offset_and_size_word_is_checked() {
    let fields = [
        (DepositField::Pubkey, 0, 160),
        (DepositField::WithdrawalCredentials, 32, 256),
        (DepositField::Amount, 64, 320),
        (DepositField::Signature, 96, 384),
        (DepositField::Index, 128, 512),
    ];
    for (field, offset_word, size_word) in fields {
        for corrupt in [[0u8; 32], [0xff; 32]] {
            let mut data = LOG_A.to_vec();
            data[offset_word..offset_word + 32].copy_from_slice(&corrupt);
            let receipts = [receipt(vec![deposit_log(data)])];
            assert_eq!(
                parse_deposits_from_receipts(&receipts, MAINNET_DEPOSIT_CONTRACT_ADDRESS),
                Err(DepositLogError::Offset { field })
            );

            let mut data = LOG_A.to_vec();
            data[size_word..size_word + 32].copy_from_slice(&corrupt);
            let receipts = [receipt(vec![deposit_log(data)])];
            assert_eq!(
                parse_deposits_from_receipts(&receipts, MAINNET_DEPOSIT_CONTRACT_ADDRESS),
                Err(DepositLogError::Size { field })
            );
        }
    }
}

#[test]
fn a_failing_log_fails_the_whole_parse() {
    let receipts = [
        receipt(vec![deposit_log(LOG_A.to_vec())]),
        receipt(vec![deposit_log(vec![0; 10])]),
    ];
    assert!(parse_deposits_from_receipts(&receipts, MAINNET_DEPOSIT_CONTRACT_ADDRESS).is_err());
}
