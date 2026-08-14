//! Transaction receipts and their [EIP-2718] typed encoding.
//!
//! A receipt is the protocol-visible summary of one executed transaction: the post-Byzantium
//! success status (EIP-658), the **cumulative** gas used in the block up to and including this
//! transaction (receipts carry no per-transaction gas), the emitted logs and their bloom filter
//! ([`logs_bloom`]). This crate targets post-merge forks, so the status form is always used.
//!
//! The consensus encoding is `rlp([status, cumulative_gas_used, bloom, logs])`, wrapped in the
//! EIP-2718 envelope by [`Receipt::encoded`]: a legacy receipt is the bare RLP list, a typed
//! receipt is prefixed with its [`TxType`] byte.
//!
//! # Place in the execution pipeline
//!
//! The transaction loop builds one [`Receipt`] per transaction — status from the exit reason,
//! gas accumulated across the loop, logs from the executor — and collects them in
//! [`BlockExecutionResult`](crate::execution_types::execution::BlockExecutionResult). Two header
//! commitments derive
//! from receipts: `receipts_root`, an [`ordered_trie_root`](crate::trie::ordered_trie_root) over
//! the encoded receipts, and the block `logs_bloom`, the union (OR) of all receipt blooms.
//!
//! [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718

use crate::bloom::{Bloom, logs_bloom};
use crate::transaction::TxType;
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
        self.append_body(&mut stream);
        let body = stream.out();
        if self.tx_type == TxType::Legacy {
            body.to_vec()
        } else {
            let mut out = Vec::with_capacity(body.len() + 1);
            out.push(u8::from(self.tx_type));
            out.extend_from_slice(body.as_ref());
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Receipt;
    use crate::bloom::Bloom;
    use crate::transaction::TxType;

    #[test]
    fn legacy_receipt_has_no_type_prefix() {
        let receipt = Receipt::new(TxType::Legacy, true, 21_000, vec![]);
        let encoded = receipt.encoded();
        // A legacy receipt is a bare RLP list (first byte >= 0xc0), no type envelope byte.
        assert!(encoded[0] >= 0xc0);
    }

    #[test]
    fn typed_receipt_has_type_prefix() {
        let receipt = Receipt::new(TxType::Eip1559, true, 21_000, vec![]);
        assert_eq!(receipt.encoded()[0], 0x02);
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
