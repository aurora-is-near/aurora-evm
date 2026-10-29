//! Post-execution checks anchored to reth/EEST vectors and an independent receipt-trie oracle.

use super::{CANCUN_TIMESTAMP, OSAKA_TIMESTAMP, PRAGUE_TIMESTAMP, chain_spec};
use crate::block::{Block, Header, validate_block_post_execution};
use crate::bloom::Bloom;
use crate::chain_spec::ActiveSpec;
use crate::constants::{EMPTY_REQUESTS_HASH, EMPTY_ROOT_HASH};
use crate::crypto::sha256;
use crate::eips::eip4844::DATA_GAS_PER_BLOB;
use crate::errors::BlockExecutionError;
use crate::execution_types::execution::BlockExecutionResult;
use crate::receipt::Receipt;
use crate::requests::Requests;
use crate::spec::Spec;
use crate::transaction::TxType;
use crate::trie::KeccakHasher;
use aurora_evm::backend::Log;
use hex_literal::hex;
use primitive_types::{H160, H256};

fn empty(spec: Spec) -> (Header, ActiveSpec, BlockExecutionResult) {
    let timestamp = match spec {
        Spec::Cancun => CANCUN_TIMESTAMP,
        Spec::Prague => PRAGUE_TIMESTAMP,
        Spec::Osaka => OSAKA_TIMESTAMP,
        _ => panic!("post-execution fixtures require Cancun or later"),
    };
    let active = chain_spec(spec)
        .active_spec_at_timestamp(timestamp)
        .unwrap();
    (
        Header {
            timestamp,
            gas_used: 0,
            blob_gas_used: Some(0),
            receipts_root: EMPTY_ROOT_HASH,
            logs_bloom: Bloom::zero(),
            requests_hash: (spec >= Spec::Prague).then_some(EMPTY_REQUESTS_HASH),
            ..Header::default()
        },
        active,
        BlockExecutionResult {
            receipts: Vec::new(),
            requests: Requests::new(),
            gas_used: 0,
            blob_gas_used: 0,
        },
    )
}

/// Independent encoding and trie builder, not `Receipt::encoded` or the production ordered trie.
fn reference_root(receipts: &[Receipt]) -> H256 {
    let encoded: Vec<_> = receipts
        .iter()
        .map(|receipt| {
            let mut stream = rlp::RlpStream::new_list(4);
            stream.append(&u8::from(receipt.success));
            stream.append(&receipt.cumulative_gas_used);
            stream.append(&receipt.bloom.0.as_slice());
            stream.begin_list(receipt.logs.len());
            for log in &receipt.logs {
                stream.begin_list(3);
                stream.append(&log.address);
                stream.append_list(&log.topics);
                stream.append(&log.data.as_slice());
            }
            let prefix = match receipt.tx_type {
                TxType::Legacy => None,
                TxType::Eip2930 => Some(1),
                TxType::Eip1559 => Some(2),
                TxType::Eip4844 => Some(3),
                TxType::Eip7702 => Some(4),
            };
            let mut bytes: Vec<u8> = prefix.into_iter().collect();
            bytes.extend_from_slice(&stream.out());
            bytes
        })
        .collect();
    triehash::ordered_trie_root::<KeccakHasher, _>(encoded)
}

#[test]
fn empty_blocks_pass_on_every_supported_fork() {
    for spec in [Spec::Cancun, Spec::Prague, Spec::Osaka] {
        let (header, active, result) = empty(spec);
        assert_eq!(
            validate_block_post_execution(&header, &active, &result),
            Ok(())
        );
    }
}

#[test]
fn gas_mismatch_precedes_other_commitments_and_preserves_values() {
    let (mut header, active, mut result) = empty(Spec::Cancun);
    header.gas_used = 21_000;
    result.gas_used = 20_999;
    header.blob_gas_used = None;
    header.receipts_root = H256::zero();
    assert_eq!(
        validate_block_post_execution(&header, &active, &result),
        Err(BlockExecutionError::GasUsedMismatch {
            got: 20_999,
            expected: 21_000
        })
    );
}

#[test]
fn blob_gas_requires_presence_and_exact_equality_even_for_zero() {
    for spec in [Spec::Cancun, Spec::Prague, Spec::Osaka] {
        let (mut header, active, mut result) = empty(spec);
        for (got, expected) in [
            (0, None),
            (DATA_GAS_PER_BLOB, Some(0)),
            (0, Some(DATA_GAS_PER_BLOB)),
        ] {
            result.blob_gas_used = got;
            header.blob_gas_used = expected;
            assert_eq!(
                validate_block_post_execution(&header, &active, &result),
                Err(BlockExecutionError::BlobGasUsedMismatch { got, expected })
            );
        }
        result.blob_gas_used = DATA_GAS_PER_BLOB;
        header.blob_gas_used = Some(DATA_GAS_PER_BLOB);
        assert_eq!(
            validate_block_post_execution(&header, &active, &result),
            Ok(())
        );
    }
}

/// reth's `test_verify_receipts_success`: five default (failed legacy) receipts.
#[test]
fn reth_receipt_root_vector_passes_and_detects_status_mutation() {
    let (mut header, active, mut result) = empty(Spec::Cancun);
    header.receipts_root = H256(hex!(
        "61353b4fb714dc1fccacbf7eafc4273e62f3d1eed716fe41b2a0cd2e12c63ebc"
    ));
    result.receipts = vec![Receipt::new(TxType::Legacy, false, 0, vec![]); 5];
    assert_eq!(
        validate_block_post_execution(&header, &active, &result),
        Ok(())
    );
    result.receipts[2].success = true;
    assert_eq!(
        validate_block_post_execution(&header, &active, &result),
        Err(BlockExecutionError::ReceiptsRootMismatch {
            got: reference_root(&result.receipts),
            expected: header.receipts_root,
        })
    );
}

/// Existing EEST v5.4.0 Prague block: one successful EIP-2930 transaction, no logs or requests.
#[test]
fn eest_header_commits_to_typed_receipt_and_cumulative_gas() {
    let vector = crate::block::codec::tests::vectors().remove(1);
    let block = Block::decode_exact(vector.rlp).unwrap();
    let (_, active, mut result) = empty(Spec::Prague);
    result.gas_used = block.header.gas_used;
    result
        .receipts
        .push(Receipt::new(TxType::Eip2930, true, result.gas_used, vec![]));
    assert_eq!(
        validate_block_post_execution(&block.header, &active, &result),
        Ok(())
    );

    for change_type in [false, true] {
        let mut changed = result.clone();
        if change_type {
            changed.receipts[0].tx_type = TxType::Legacy;
        } else {
            changed.receipts[0].cumulative_gas_used += 1;
        }
        assert_eq!(
            validate_block_post_execution(&block.header, &active, &changed),
            Err(BlockExecutionError::ReceiptsRootMismatch {
                got: reference_root(&changed.receipts),
                expected: block.header.receipts_root,
            })
        );
    }
}

#[test]
fn mixed_receipts_preserve_order_logs_and_union_all_blooms() {
    let (mut header, active, mut result) = empty(Spec::Osaka);
    for (index, tx_type) in [
        TxType::Legacy,
        TxType::Eip2930,
        TxType::Eip1559,
        TxType::Eip4844,
        TxType::Eip7702,
    ]
    .into_iter()
    .enumerate()
    {
        let byte = u8::try_from(index + 1).unwrap();
        let logs = if index == 1 {
            vec![]
        } else {
            vec![Log {
                // Shared address bits must survive OR even with an even number of logs.
                address: H160::repeat_byte(0x11),
                topics: vec![H256::repeat_byte(byte)],
                data: vec![byte; 64 - index * 13],
            }]
        };
        result.receipts.push(Receipt::new(
            tx_type,
            index != 1,
            u64::from(byte) * 30_000,
            logs,
        ));
    }
    result.gas_used = 150_000;
    result.blob_gas_used = DATA_GAS_PER_BLOB;
    header.gas_used = result.gas_used;
    header.blob_gas_used = Some(result.blob_gas_used);
    header.receipts_root = reference_root(&result.receipts);
    // An independent bytewise union catches overwriting, XOR and omission of a receipt bloom.
    for (index, byte) in header.logs_bloom.0.iter_mut().enumerate() {
        *byte = result
            .receipts
            .iter()
            .fold(0, |union, receipt| union | receipt.bloom.0[index]);
    }
    assert_eq!(
        validate_block_post_execution(&header, &active, &result),
        Ok(())
    );

    let correct_bloom = header.logs_bloom.clone();
    header.logs_bloom.0[0] ^= 1;
    assert_eq!(
        validate_block_post_execution(&header, &active, &result),
        Err(BlockExecutionError::LogsBloomMismatch {
            got: Box::new(correct_bloom.clone()),
            expected: Box::new(header.logs_bloom.clone()),
        })
    );
    header.logs_bloom = correct_bloom;

    result.receipts.swap(0, 4);
    assert_eq!(
        validate_block_post_execution(&header, &active, &result),
        Err(BlockExecutionError::ReceiptsRootMismatch {
            got: reference_root(&result.receipts),
            expected: header.receipts_root,
        })
    );
    result.receipts.swap(0, 4);
    result.receipts[0].logs[0].data[0] ^= 1;
    assert!(matches!(
        validate_block_post_execution(&header, &active, &result),
        Err(BlockExecutionError::ReceiptsRootMismatch { .. })
    ));
}

#[test]
fn empty_receipts_still_require_the_empty_root_and_zero_bloom() {
    let (mut header, active, result) = empty(Spec::Cancun);
    header.receipts_root = H256::zero();
    header.logs_bloom.0[255] = 1;
    assert_eq!(
        validate_block_post_execution(&header, &active, &result),
        Err(BlockExecutionError::ReceiptsRootMismatch {
            got: EMPTY_ROOT_HASH,
            expected: H256::zero()
        })
    );
    header.receipts_root = EMPTY_ROOT_HASH;
    assert_eq!(
        validate_block_post_execution(&header, &active, &result),
        Err(BlockExecutionError::LogsBloomMismatch {
            got: Box::new(Bloom::zero()),
            expected: Box::new(header.logs_bloom.clone()),
        })
    );
}

#[test]
fn prague_and_osaka_require_requests_hash_even_without_requests() {
    for spec in [Spec::Prague, Spec::Osaka] {
        let (mut header, active, result) = empty(spec);
        for expected in [None, Some(H256::zero())] {
            header.requests_hash = expected;
            assert_eq!(
                validate_block_post_execution(&header, &active, &result),
                Err(BlockExecutionError::RequestsHashMismatch {
                    got: Some(EMPTY_REQUESTS_HASH),
                    expected
                })
            );
        }
    }
}

#[test]
fn request_hash_uses_payload_and_ignores_type_only_entries() {
    let (mut header, active, mut result) = empty(Spec::Prague);
    result.requests.push_request_with_type(2, []);
    result.requests.push_request_with_type(1, [0xaa, 0xbb]);
    // EIP-7685: SHA256(SHA256(type || data)), excluding the empty type-2 request.
    let expected = sha256(sha256(&[1, 0xaa, 0xbb]).as_bytes());
    header.requests_hash = Some(expected);
    assert_eq!(
        validate_block_post_execution(&header, &active, &result),
        Ok(())
    );
    header.requests_hash = Some(EMPTY_REQUESTS_HASH);
    assert_eq!(
        validate_block_post_execution(&header, &active, &result),
        Err(BlockExecutionError::RequestsHashMismatch {
            got: Some(expected),
            expected: Some(EMPTY_REQUESTS_HASH)
        })
    );
}

#[test]
fn requests_follow_resolved_fork_not_configured_ceiling() {
    let chain = chain_spec(Spec::Osaka);
    let (mut header, _, result) = empty(Spec::Cancun);
    header.requests_hash = None;
    for (timestamp, required) in [(PRAGUE_TIMESTAMP - 1, false), (PRAGUE_TIMESTAMP, true)] {
        header.timestamp = timestamp;
        let active = chain.active_spec_at_timestamp(timestamp).unwrap();
        let expected = if required {
            Err(BlockExecutionError::RequestsHashMismatch {
                got: Some(EMPTY_REQUESTS_HASH),
                expected: None,
            })
        } else {
            Ok(())
        };
        assert_eq!(
            validate_block_post_execution(&header, &active, &result),
            expected
        );
    }
}
