//! Ethereum logs bloom filter (2048-bit / 256-byte), the "bloom-9" construction.

use crate::crypto::keccak256;
use aurora_evm::backend::Log;

/// A 2048-bit (256-byte) bloom filter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bloom(pub [u8; 256]);

impl Default for Bloom {
    fn default() -> Self {
        Self::zero()
    }
}

impl Bloom {
    /// Returns an all-zero bloom.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 256])
    }

    /// Mixes `input` into the filter by setting three bits derived from `keccak256(input)`.
    pub fn accrue(&mut self, input: &[u8]) {
        let hash = keccak256(input);
        let bytes = hash.as_bytes();
        for i in [0usize, 2, 4] {
            // 11-bit position into the 2048-bit field.
            let bit = (usize::from(bytes[i] & 0x07) << 8) | usize::from(bytes[i + 1]);
            let byte = 255 - (bit / 8);
            self.0[byte] |= 1u8 << (bit % 8);
        }
    }

    /// Bitwise-ORs another bloom into this one (block bloom = OR of receipt blooms).
    pub fn accrue_bloom(&mut self, other: &Self) {
        for (slot, value) in self.0.iter_mut().zip(other.0.iter()) {
            *slot |= *value;
        }
    }
}

impl rlp::Encodable for Bloom {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.encoder().encode_value(&self.0);
    }
}

/// Computes the bloom filter for a set of logs (each log contributes its address and topics).
#[must_use]
pub fn logs_bloom(logs: &[Log]) -> Bloom {
    let mut bloom = Bloom::zero();
    for log in logs {
        bloom.accrue(log.address.as_bytes());
        for topic in &log.topics {
            bloom.accrue(topic.as_bytes());
        }
    }
    bloom
}

#[cfg(test)]
mod tests {
    use super::{Bloom, logs_bloom};
    use aurora_evm::backend::Log;
    use primitive_types::{H160, H256};

    #[test]
    fn empty_logs_zero_bloom() {
        assert_eq!(logs_bloom(&[]), Bloom::zero());
    }

    #[test]
    fn single_input_sets_exactly_three_bits() {
        // Per the bloom-9 construction each input sets three bits (no collision for this input).
        let mut bloom = Bloom::zero();
        bloom.accrue(b"hello");
        let set_bits: u32 = bloom.0.iter().map(|byte| byte.count_ones()).sum();
        assert_eq!(set_bits, 3);
    }

    #[test]
    fn nonempty_log_sets_bits() {
        let log = Log {
            address: H160::repeat_byte(0x01),
            topics: vec![H256::repeat_byte(0x02)],
            data: vec![],
        };
        let bloom = logs_bloom(std::slice::from_ref(&log));
        assert_ne!(bloom, Bloom::zero());
        // exactly six bits max (address + one topic, three bits each), and idempotent.
        let mut twice = bloom.clone();
        twice.accrue_bloom(&bloom);
        assert_eq!(twice, bloom);
    }

    #[test]
    fn accrue_or_is_superset() {
        let mut a = Bloom::zero();
        a.accrue(b"hello");
        let mut b = Bloom::zero();
        b.accrue(b"world");
        let mut both = a.clone();
        both.accrue_bloom(&b);
        // every set bit of `a` and `b` is present in `both`.
        for i in 0..256 {
            assert_eq!(both.0[i] & a.0[i], a.0[i]);
            assert_eq!(both.0[i] & b.0[i], b.0[i]);
        }
    }
}
