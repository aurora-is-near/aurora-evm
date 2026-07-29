//! The ECDSA signature carried by a transaction, and the `v` encoding rules around it.
//!
//! A signature is the triple `(y_parity, r, s)`. Legacy transactions do not store `y_parity`
//! directly: they store `v`, which folds the parity together with the chain id
//! ([EIP-155]) — see [`TxSignature::legacy_v`] and [`TxSignature::from_legacy_v`]. Typed
//! transactions (EIP-2930 and later) store the parity as its own field.
//!
//! [EIP-2] additionally requires `s` to be in the lower half of the curve order: for any valid
//! signature `(r, s)`, the pair `(r, n - s)` is an equally valid signature over the same message,
//! so accepting both would let a transaction be re-signed into a different hash. Verification must
//! therefore reject a non-normalized `s` explicitly — see [`TxSignature::is_s_normalized`].
//!
//! [EIP-155]: https://eips.ethereum.org/EIPS/eip-155
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

/// `v` of a pre-EIP-155 signature with even parity; the odd-parity value is one greater.
const LEGACY_V_BASE: u64 = 27;

/// `v` offset introduced by EIP-155, where `v = EIP155_V_BASE + 2 * chain_id + y_parity`.
const EIP155_V_BASE: u64 = 35;

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

    /// The legacy `v` for this parity: `27 + y_parity`, or `35 + 2 * chain_id + y_parity` when the
    /// signature covers a chain id (EIP-155).
    ///
    /// Returns `None` only if `chain_id` is so large that `v` overflows `u64`.
    #[must_use]
    pub fn legacy_v(&self, chain_id: Option<u64>) -> Option<u64> {
        let parity = u64::from(self.y_parity);
        match chain_id {
            None => Some(LEGACY_V_BASE + parity),
            Some(chain_id) => chain_id
                .checked_mul(2)?
                .checked_add(EIP155_V_BASE)?
                .checked_add(parity),
        }
    }

    /// Splits a legacy `v` into its parity and, from EIP-155 on, the chain id it commits to.
    ///
    /// Returns `None` for a `v` that encodes neither form (`27`/`28`, or `>= 35`).
    #[must_use]
    pub const fn from_legacy_v(v: u64) -> Option<(bool, Option<u64>)> {
        match v {
            LEGACY_V_BASE => Some((false, None)),
            28 => Some((true, None)),
            v if v >= EIP155_V_BASE => {
                let offset = v - EIP155_V_BASE;
                Some((offset % 2 == 1, Some(offset / 2)))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SECP256K1N_HALF, TxSignature};
    use primitive_types::U256;

    fn signature(y_parity: bool) -> TxSignature {
        TxSignature::new(y_parity, U256::one(), U256::from(2u64))
    }

    #[test]
    fn pre_eip155_v_is_27_or_28() {
        assert_eq!(signature(false).legacy_v(None), Some(27));
        assert_eq!(signature(true).legacy_v(None), Some(28));
        assert_eq!(TxSignature::from_legacy_v(27), Some((false, None)));
        assert_eq!(TxSignature::from_legacy_v(28), Some((true, None)));
    }

    #[test]
    fn eip155_v_roundtrips_for_several_chain_ids() {
        for chain_id in [1u64, 137, 0xFFFF, 1_000_000] {
            for y_parity in [false, true] {
                let v = signature(y_parity).legacy_v(Some(chain_id)).unwrap();
                assert_eq!(v, 35 + 2 * chain_id + u64::from(y_parity));
                assert_eq!(
                    TxSignature::from_legacy_v(v),
                    Some((y_parity, Some(chain_id)))
                );
            }
        }
    }

    #[test]
    fn mainnet_v_values_are_37_and_38() {
        // The canonical chain-id-1 values, the form seen in EIP-155 mainnet transactions.
        assert_eq!(signature(false).legacy_v(Some(1)), Some(37));
        assert_eq!(signature(true).legacy_v(Some(1)), Some(38));
    }

    #[test]
    fn v_values_between_the_two_forms_are_rejected() {
        for v in [0u64, 1, 26, 29, 30, 31, 32, 33, 34] {
            assert_eq!(TxSignature::from_legacy_v(v), None, "v = {v}");
        }
    }

    #[test]
    fn absurd_chain_id_overflows_rather_than_wrapping() {
        assert_eq!(signature(false).legacy_v(Some(u64::MAX)), None);
        assert_eq!(signature(false).legacy_v(Some(u64::MAX / 2)), None);
    }

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
