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
        stream.append_list(&self.logs);
    }

    /// EIP-2718 encoding: `rlp(body)` for legacy receipts, `type_byte || rlp(body)` otherwise.
    #[must_use]
    pub fn encoded(&self) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        self.encode_2718_in(&mut stream).to_vec()
    }

    /// Writes the EIP-2718 receipt encoding into a dedicated scratch stream and returns its slice.
    ///
    /// The stream is cleared before use, so one backing allocation can serve every receipt in a
    /// block. If the stream was created over an existing buffer, the returned slice excludes that
    /// prefix and covers only this receipt.
    ///
    /// # Panics
    /// Panics if the fixed four-field receipt body is left unfinished. In debug builds, also panics
    /// if `stream` already contains an unfinished list instead of a reusable scratch value.
    pub(crate) fn encode_2718_in<'stream>(
        &self,
        stream: &'stream mut rlp::RlpStream,
    ) -> &'stream [u8] {
        // `clear()` would silently discard an enclosing list; catch misuse of the scratch contract
        // while developing, without charging the zkVM release path.
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
        // `as_raw()` bypasses `RlpStream::out()` and its completion check, so an unfinished body
        // must fail closed before it can change the receipts root.
        assert!(stream.is_finished(), "receipt encoding left an open list");
        &stream.as_raw()[base..]
    }
}

#[cfg(test)]
mod tests {
    use super::Receipt;
    use crate::bloom::Bloom;
    use crate::transaction::TxType;
    use aurora_evm::backend::Log;
    use primitive_types::{H160, H256};

    /// Independent, allocation-insensitive expression of the EIP-2718 receipt encoding.
    fn reference_encoding(receipt: &Receipt) -> Vec<u8> {
        let mut body = rlp::RlpStream::new_list(4);
        body.append(&u8::from(receipt.success));
        body.append(&receipt.cumulative_gas_used);
        body.append(&receipt.bloom);
        body.append_list(&receipt.logs);
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
        // A legacy receipt is a bare RLP list (first byte >= 0xc0), no type envelope byte.
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
        assert_eq!(rlp.val_at::<u8>(0).unwrap(), 1); // status: success → 1
        assert_eq!(rlp.val_at::<u64>(1).unwrap(), 21_000); // cumulative gas
        assert_eq!(rlp.val_at::<Vec<u8>>(2).unwrap().len(), 256); // bloom
        assert!(rlp.at(3).unwrap().is_list()); // logs
    }

    #[test]
    fn typed_receipt_body_decodes_and_status_zero_is_empty() {
        let receipt = Receipt::new(TxType::Eip1559, false, 50_000, vec![]);
        let encoded = receipt.encoded();
        assert_eq!(encoded[0], 0x02); // EIP-2718 type envelope
        // status `false` is encoded as the empty string (0x80), decoding back to 0.
        let body = rlp::Rlp::new(&encoded[1..]);
        assert_eq!(body.item_count().unwrap(), 4);
        assert_eq!(body.val_at::<u8>(0).unwrap(), 0);
        assert_eq!(body.val_at::<u64>(1).unwrap(), 50_000);
    }
}
