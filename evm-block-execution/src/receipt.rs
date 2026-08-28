//! Transaction receipts and their [EIP-2718] encoding.
//!
//! A receipt records status, cumulative block gas, logs and their bloom. Its consensus body is
//! `rlp([status, cumulative_gas_used, bloom, logs])`; typed receipts prepend the transaction type
//! byte. Encoded receipts form `receipts_root`, while their blooms combine into the block bloom.
//!
//! [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718

use crate::bloom::{Bloom, logs_bloom};
use crate::transaction::TxType;
use crate::transaction::types::{eip1559, eip2930, eip4844, eip7702};
use aurora_evm::backend::Log;

/// Appends logs as `[address, topics, data]` receipt entries.
fn append_logs(stream: &mut rlp::RlpStream, logs: &[Log]) {
    stream.begin_list(logs.len());
    for log in logs {
        stream.begin_list(3);
        stream.append(&log.address);
        stream.append_list(&log.topics);
        // The derived `Encodable for Log` treats `data` as a list of bytes; receipts require one
        // RLP byte string.
        stream.append(&log.data.as_slice());
    }
}

/// Execution receipt for a single transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Transaction type (EIP-2718).
    pub tx_type: TxType,
    /// Post-Byzantium status: `true` for success, `false` for revert/halt.
    pub success: bool,
    /// Cumulative gas used in the block up to and including this transaction.
    pub cumulative_gas_used: u64,
    /// Logs emitted by the transaction.
    pub logs: Vec<Log>,
    /// Bloom filter derived from `logs`.
    pub bloom: Bloom,
}

impl Receipt {
    /// Builds a receipt, computing the bloom filter from `logs`.
    #[must_use]
    pub fn new(tx_type: TxType, success: bool, cumulative_gas_used: u64, logs: Vec<Log>) -> Self {
        let bloom = logs_bloom(&logs);
        Self {
            tx_type,
            success,
            cumulative_gas_used,
            logs,
            bloom,
        }
    }

    /// Appends the consensus RLP body `[status, cumulative_gas_used, bloom, logs]`.
    ///
    /// The status is encoded as a scalar (`0` → empty string, `1` → `0x01`).
    fn append_body(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(4);
        stream.append(&u8::from(self.success));
        stream.append(&self.cumulative_gas_used);
        stream.append(&self.bloom);
        append_logs(stream, &self.logs);
    }

    /// EIP-2718 encoding: `rlp(body)` for legacy receipts, `type_byte || rlp(body)` otherwise.
    #[must_use]
    pub fn encoded(&self) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        self.encode_2718_in(&mut stream).to_vec()
    }

    /// Writes the EIP-2718 encoding into reusable `stream` and returns the receipt slice.
    ///
    /// The stream is cleared but retains its allocation. Any existing backing-buffer prefix is
    /// excluded from the returned slice.
    ///
    /// # Panics
    /// Panics if encoding leaves an RLP list unfinished. Debug builds also reject an unfinished
    /// input stream.
    pub(crate) fn encode_2718_in<'stream>(
        &self,
        stream: &'stream mut rlp::RlpStream,
    ) -> &'stream [u8] {
        // Catch an enclosing list before `clear()` silently discards it in debug builds.
        debug_assert!(
            stream.is_finished(),
            "the receipt scratch stream must not contain an unfinished list"
        );
        stream.clear();
        let base = stream.as_raw().len();
        let type_byte = match self.tx_type {
            TxType::Legacy => None,
            TxType::Eip2930 => Some(eip2930::TYPE_BYTE),
            TxType::Eip1559 => Some(eip1559::TYPE_BYTE),
            TxType::Eip4844 => Some(eip4844::TYPE_BYTE),
            TxType::Eip7702 => Some(eip7702::TYPE_BYTE),
        };
        if let Some(type_byte) = type_byte {
            stream.append_raw(&[type_byte], 0);
        }
        self.append_body(stream);
        // `as_raw()` skips `out()`'s completion check; fail closed before hashing the receipt.
        assert!(stream.is_finished(), "receipt encoding left an open list");
        &stream.as_raw()[base..]
    }
}

#[cfg(test)]
mod tests {
    use super::Receipt;
    use crate::bloom::Bloom;
    use crate::transaction::TxType;
    use crate::trie::ordered_trie_root;
    use aurora_evm::backend::Log;
    use hex_literal::hex;
    use primitive_types::{H160, H256};

    /// Separate expression of the EIP-2718 receipt encoding used by scratch-buffer tests.
    fn reference_encoding(receipt: &Receipt) -> Vec<u8> {
        let mut body = rlp::RlpStream::new_list(4);
        body.append(&u8::from(receipt.success));
        body.append(&receipt.cumulative_gas_used);
        body.append(&receipt.bloom);
        body.begin_list(receipt.logs.len());
        for log in &receipt.logs {
            body.begin_list(3);
            body.append(&log.address);
            body.append_list(&log.topics);
            body.append(&log.data.as_slice());
        }
        let body = body.out();

        let type_byte = match receipt.tx_type {
            TxType::Legacy => return body.to_vec(),
            TxType::Eip2930 => crate::transaction::types::eip2930::TYPE_BYTE,
            TxType::Eip1559 => crate::transaction::types::eip1559::TYPE_BYTE,
            TxType::Eip4844 => crate::transaction::types::eip4844::TYPE_BYTE,
            TxType::Eip7702 => crate::transaction::types::eip7702::TYPE_BYTE,
        };
        let mut encoded = Vec::with_capacity(body.len() + 1);
        encoded.push(type_byte);
        encoded.extend_from_slice(&body);
        encoded
    }

    fn log(data_len: usize, topic_count: usize) -> Log {
        Log {
            address: H160::repeat_byte(0x11),
            topics: vec![H256::repeat_byte(0x22); topic_count],
            data: vec![0x33; data_len],
        }
    }

    #[test]
    fn legacy_receipt_has_no_type_prefix() {
        let receipt = Receipt::new(TxType::Legacy, true, 21_000, vec![]);
        let encoded = receipt.encoded();
        // A legacy receipt is a bare RLP list.
        assert!(encoded[0] >= 0xc0);
    }

    #[test]
    fn every_typed_receipt_has_its_transaction_type_prefix() {
        for (tx_type, expected) in [
            (TxType::Eip2930, 0x01),
            (TxType::Eip1559, 0x02),
            (TxType::Eip4844, 0x03),
            (TxType::Eip7702, 0x04),
        ] {
            let receipt = Receipt::new(tx_type, true, 21_000, vec![]);
            assert_eq!(receipt.encoded()[0], expected, "{tx_type:?}");
        }
    }

    /// Published EIP-2481 vector, also used by Reth's Ethereum receipt tests.
    #[test]
    fn legacy_receipt_matches_eip2481_vector() {
        let mut expected = vec![0xf9, 0x01, 0x66, 0x80, 0x01, 0xb9, 0x01, 0x00];
        expected.extend_from_slice(&[0; 256]);
        expected.extend_from_slice(&hex!(
            "f85ff85d940000000000000000000000000000000000000011f842"
            "a0000000000000000000000000000000000000000000000000000000000000dead"
            "a0000000000000000000000000000000000000000000000000000000000000beef830100ff"
        ));
        let receipt = Receipt {
            tx_type: TxType::Legacy,
            success: false,
            cumulative_gas_used: 1,
            logs: vec![Log {
                address: H160(hex!("0000000000000000000000000000000000000011")),
                topics: vec![
                    H256(hex!(
                        "000000000000000000000000000000000000000000000000000000000000dead"
                    )),
                    H256(hex!(
                        "000000000000000000000000000000000000000000000000000000000000beef"
                    )),
                ],
                data: hex!("0100ff").to_vec(),
            }],
            // The published encoding vector deliberately carries an explicit zero bloom.
            bloom: Bloom::zero(),
        };

        assert_eq!(receipt.encoded(), expected);
    }

    /// Single-receipt Cancun block from EEST v5.4.0 (`blobhash_opcode_contexts`, legacy case).
    #[test]
    fn eest_receipt_matches_its_encoding_and_root() {
        let receipt = Receipt::new(TxType::Legacy, true, 0x5aa9, vec![]);

        // rlp([status = 1, cumulative gas = 0x5aa9, zero bloom, empty logs]).
        let mut expected = vec![0xf9, 0x01, 0x08, 0x01, 0x82, 0x5a, 0xa9, 0xb9, 0x01, 0x00];
        expected.extend_from_slice(&[0; 256]);
        expected.push(0xc0);

        assert_eq!(receipt.encoded(), expected);
        assert_eq!(
            ordered_trie_root([expected]),
            H256(hex!(
                "a5ca6f0ba985abff77f091ae13b5077613972f2f4aff28b45229f5726a3e59e6"
            ))
        );
    }

    #[test]
    fn one_scratch_stream_encodes_a_receipt_sequence() {
        let receipts = [
            Receipt::new(TxType::Legacy, true, u64::MAX, vec![log(96, 3)]),
            Receipt::new(TxType::Eip2930, false, 0, vec![]),
            Receipt::new(TxType::Eip1559, true, 21_000, vec![log(1, 1)]),
            Receipt::new(TxType::Eip4844, false, 1, vec![]),
            Receipt::new(TxType::Eip7702, true, u32::MAX.into(), vec![log(48, 2)]),
        ];
        let expected: Vec<_> = receipts.iter().map(reference_encoding).collect();
        let lengths: Vec<_> = expected.iter().map(Vec::len).collect();
        assert!(lengths.windows(2).any(|pair| pair[0] > pair[1]));
        assert!(lengths.windows(2).any(|pair| pair[0] < pair[1]));
        let mut scratch = rlp::RlpStream::new();

        for (receipt, expected) in receipts.iter().zip(&expected) {
            assert_eq!(receipt.encode_2718_in(&mut scratch), expected);
        }
        for (receipt, expected) in receipts.iter().zip(&expected).rev() {
            assert_eq!(receipt.encode_2718_in(&mut scratch), expected);
        }
    }

    #[test]
    fn receipt_scratch_excludes_an_existing_prefix() {
        let receipt = Receipt::new(TxType::Eip1559, true, 21_000, vec![]);
        let expected = receipt.encoded();
        let prefix = rlp::encode(&"prefix");
        let prefix_len = prefix.len();
        let mut scratch = rlp::RlpStream::new_with_buffer(prefix);

        assert_eq!(receipt.encode_2718_in(&mut scratch), expected);
        assert_eq!(&scratch.as_raw()[..prefix_len], rlp::encode(&"prefix"));
    }

    #[test]
    fn empty_logs_produce_zero_bloom() {
        let receipt = Receipt::new(TxType::Legacy, false, 0, vec![]);
        assert_eq!(receipt.bloom, Bloom::zero());
    }

    #[test]
    fn legacy_receipt_rlp_structure() {
        let receipt = Receipt::new(TxType::Legacy, true, 21_000, vec![]);
        let encoded = receipt.encoded();
        let rlp = rlp::Rlp::new(&encoded);
        assert_eq!(rlp.item_count().unwrap(), 4);
        assert_eq!(rlp.val_at::<u8>(0).unwrap(), 1);
        assert_eq!(rlp.val_at::<u64>(1).unwrap(), 21_000);
        assert_eq!(rlp.val_at::<Vec<u8>>(2).unwrap().len(), 256);
        assert!(rlp.at(3).unwrap().is_list());
    }

    #[test]
    fn typed_receipt_body_decodes_and_status_zero_is_empty() {
        let receipt = Receipt::new(TxType::Eip1559, false, 50_000, vec![]);
        let encoded = receipt.encoded();
        assert_eq!(encoded[0], 0x02);
        // `false` is the empty RLP string and decodes to zero.
        let body = rlp::Rlp::new(&encoded[1..]);
        assert_eq!(body.item_count().unwrap(), 4);
        assert_eq!(body.val_at::<u8>(0).unwrap(), 0);
        assert_eq!(body.val_at::<u64>(1).unwrap(), 50_000);
    }
}
