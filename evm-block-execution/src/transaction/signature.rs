//! The normalized ECDSA signature carried by a transaction.
//!
//! [`TxSignature`] stores `(y_parity, r, s)` for every transaction type. Legacy `v` conversion
//! belongs to the legacy transaction codec. [EIP-2] additionally requires `s` to lie in the lower
//! half of the curve order to prevent signature malleability.
//!
//! [EIP-2]: https://eips.ethereum.org/EIPS/eip-2

use primitive_types::U256;

/// `secp256k1n / 2`: the inclusive upper bound [EIP-2] places on a signature's `s`.
///
/// [EIP-2]: https://eips.ethereum.org/EIPS/eip-2
pub const SECP256K1N_HALF: U256 = U256([
    0xDFE9_2F46_681B_20A0,
    0x5D57_6E73_57A4_501D,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
]);

/// A transaction's ECDSA signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxSignature {
    /// Parity of the recovered public key's y coordinate.
    pub y_parity: bool,
    /// Signature `r` component.
    pub r: U256,
    /// Signature `s` component.
    pub s: U256,
}

impl TxSignature {
    /// Builds a signature from its components.
    #[must_use]
    pub const fn new(y_parity: bool, r: U256, s: U256) -> Self {
        Self { y_parity, r, s }
    }

    /// Whether `s` lies in the lower half of the curve order, as EIP-2 requires.
    #[must_use]
    pub fn is_s_normalized(&self) -> bool {
        self.s <= SECP256K1N_HALF
    }

    /// The signature as the 64 raw bytes `r || s` that verification consumes.
    #[must_use]
    pub fn rs_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r.to_big_endian());
        bytes[32..].copy_from_slice(&self.s.to_big_endian());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::{SECP256K1N_HALF, TxSignature};
    use primitive_types::U256;

    #[test]
    fn s_normalization_boundary_is_inclusive() {
        let at_limit = TxSignature::new(false, U256::one(), SECP256K1N_HALF);
        assert!(at_limit.is_s_normalized());
        let above_limit = TxSignature::new(false, U256::one(), SECP256K1N_HALF + U256::one());
        assert!(!above_limit.is_s_normalized());
    }

    #[test]
    fn rs_bytes_are_big_endian_and_zero_padded() {
        let signature = TxSignature::new(false, U256::one(), U256::from(0x0102u64));
        let bytes = signature.rs_bytes();
        assert_eq!(bytes[31], 1);
        assert_eq!(bytes[..31], [0u8; 31]);
        assert_eq!(bytes[62..], [0x01, 0x02]);
    }
}
