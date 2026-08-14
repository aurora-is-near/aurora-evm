//! Ethereum logs bloom filter (2048-bit / 256-byte), the "bloom-9" construction.
//!
//! A probabilistic membership index over log *addresses* and *topics*: a match may be a false
//! positive, but a non-match guarantees the logs are absent — letting clients skip blocks and
//! receipts without replaying them.
//!
//! The construction (the Yellow Paper `M` function): each input sets **three** bits of the
//! 2048-bit field. The input is hashed with `keccak256`, and byte pairs `(0,1)`, `(2,3)`,
//! `(4,5)` of the hash each yield an 11-bit position; bit indices count from the **high end**
//! of the byte array (`byte = 255 - bit / 8`). Per log, the emitting address and every topic
//! are accrued ([`logs_bloom`]). Filters compose by bitwise OR ([`Bloom::accrue_bloom`]), so a
//! union never loses set bits.
//!
//! # Place in the execution pipeline
//!
//! Each receipt carries the bloom of its own logs as part of the consensus receipt encoding
//! (see [`Receipt`](crate::receipt::Receipt)). The block-level `logs_bloom` is the OR of all
//! receipt blooms and is compared against the header field during post-execution validation.

use crate::crypto::keccak256;
use aurora_evm::backend::Log;

/// Ethereum 256 byte bloom filter.
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

impl rlp::Decodable for Bloom {
    /// A bloom is a fixed-width byte string: exactly 256 bytes, never trimmed of leading zeros.
    fn decode(rlp: &rlp::Rlp<'_>) -> Result<Self, rlp::DecoderError> {
        rlp.decoder().decode_value(|bytes| {
            <[u8; 256]>::try_from(bytes)
                .map(Self)
                .map_err(|_| rlp::DecoderError::Custom("bloom filter is not 256 bytes"))
        })
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
    use rlp::{Decodable, Encodable};

    #[test]
    fn rlp_is_a_fixed_256_byte_string() {
        // Long-string header (0xb9) plus a two-byte length, then the untrimmed 256 bytes: a bloom
        // keeps its leading zeros, unlike an integer.
        let encoded = rlp::encode(&Bloom::zero());
        assert_eq!(&encoded[..3], &[0xb9, 0x01, 0x00]);
        assert_eq!(encoded.len(), 259);
        assert!(encoded[3..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn rlp_roundtrip() {
        let mut bloom = Bloom::zero();
        bloom.accrue(H160::repeat_byte(0xaa).as_bytes());
        bloom.accrue(H256::repeat_byte(0xbb).as_bytes());
        let encoded = rlp::encode(&bloom);
        assert_eq!(rlp::decode::<Bloom>(&encoded).unwrap(), bloom);
    }

    #[test]
    fn rlp_rejects_wrong_width() {
        for width in [0usize, 32, 255, 257] {
            let encoded = rlp::encode(&vec![0u8; width]);
            assert!(
                rlp::decode::<Bloom>(&encoded).is_err(),
                "a {width}-byte string must not decode as a bloom"
            );
        }
    }

    #[test]
    fn rlp_rejects_a_list() {
        let mut stream = rlp::RlpStream::new_list(1);
        stream.append(&vec![0u8; 256]);
        assert!(Bloom::decode(&rlp::Rlp::new(&stream.out())).is_err());
    }

    #[test]
    fn rlp_append_matches_encodable() {
        let bloom = Bloom::zero();
        let mut stream = rlp::RlpStream::new();
        bloom.rlp_append(&mut stream);
        assert_eq!(stream.out().to_vec(), rlp::encode(&bloom).to_vec());
    }

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
