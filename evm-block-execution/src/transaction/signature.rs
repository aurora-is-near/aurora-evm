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
    /// A `u128`, and therefore **total**: the widest chain id is a `u64`, and `2 * u64::MAX + 36`
    /// fits with room to spare. Computing it in a `u64` would make the operation partial for chain
    /// ids near the top of the range, which is a bound `v` itself does not have. RLP encodes integers
    /// minimally, so the width changes nothing on the wire.
    #[must_use]
    pub fn legacy_v(&self, chain_id: Option<u64>) -> u128 {
        let parity = u128::from(self.y_parity);
        chain_id.map_or_else(
            || u128::from(LEGACY_V_BASE) + parity,
            |chain_id| u128::from(EIP155_V_BASE) + u128::from(chain_id) * 2 + parity,
        )
    }

    /// Splits a legacy `v` into its parity and, from EIP-155 on, the chain id it commits to.
    ///
    /// Returns `None` for a `v` that encodes neither form (`27`/`28`, or `>= 35`), and for one whose
    /// chain id does not fit in a `u64` — the width every other type declares `chain_id` with.
    #[must_use]
    pub fn from_legacy_v(v: u128) -> Option<(bool, Option<u64>)> {
        let legacy = u128::from(LEGACY_V_BASE);
        let eip155 = u128::from(EIP155_V_BASE);
        match v {
            _ if v == legacy => Some((false, None)),
            _ if v == legacy + 1 => Some((true, None)),
            _ if v >= eip155 => {
                let offset = v - eip155;
                // Every other type declares `chain_id` as a `u64`; a `v` demanding more is not a
                // chain this crate can describe, so it is rejected here rather than truncated.
                let chain_id = u64::try_from(offset / 2).ok()?;
                Some((offset % 2 == 1, Some(chain_id)))
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
        assert_eq!(signature(false).legacy_v(None), 27);
        assert_eq!(signature(true).legacy_v(None), 28);
        assert_eq!(TxSignature::from_legacy_v(27), Some((false, None)));
        assert_eq!(TxSignature::from_legacy_v(28), Some((true, None)));
    }

    #[test]
    fn eip155_v_roundtrips_for_several_chain_ids() {
        for chain_id in [1u64, 137, 0xFFFF, 1_000_000] {
            for y_parity in [false, true] {
                let v = signature(y_parity).legacy_v(Some(chain_id));
                assert_eq!(v, 35 + 2 * u128::from(chain_id) + u128::from(y_parity));
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
        assert_eq!(signature(false).legacy_v(Some(1)), 37);
        assert_eq!(signature(true).legacy_v(Some(1)), 38);
    }

    /// `v` is a `u128`, so the operation is total for every `u64` chain id — including the ones a
    /// `u64`-computed `v` could not hold. That was a real transaction being refused, not a synthetic
    /// edge: `v = u64::MAX` decodes to a chain id one above what such a bound would admit.
    #[test]
    fn every_u64_chain_id_has_a_v_and_it_round_trips() {
        for chain_id in [u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            for y_parity in [false, true] {
                let v = signature(y_parity).legacy_v(Some(chain_id));
                assert_eq!(v, 35 + 2 * u128::from(chain_id) + u128::from(y_parity));
                assert_eq!(
                    TxSignature::from_legacy_v(v),
                    Some((y_parity, Some(chain_id)))
                );
            }
        }
        // The widest `v` a `u64` could express is legal and its chain id is in range.
        assert_eq!(
            TxSignature::from_legacy_v(u128::from(u64::MAX)),
            Some((false, Some((u64::MAX - 35) / 2)))
        );
    }

    /// Beyond a `u64` chain id there is no chain this crate can describe, so `v` is refused rather
    /// than truncated.
    #[test]
    fn a_chain_id_wider_than_a_u64_is_refused() {
        let too_wide = 35 + (u128::from(u64::MAX) + 1) * 2;
        assert_eq!(TxSignature::from_legacy_v(too_wide), None);
        assert_eq!(TxSignature::from_legacy_v(u128::MAX), None);
    }

    #[test]
    fn v_values_between_the_two_forms_are_rejected() {
        for v in [0u128, 1, 26, 29, 30, 31, 32, 33, 34] {
            assert_eq!(TxSignature::from_legacy_v(v), None, "v = {v}");
        }
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
