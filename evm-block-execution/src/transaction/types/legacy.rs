//! The legacy (pre-EIP-2718) transaction: a bare RLP list with no type byte.

use super::codec::{TxDecodeError, append_destination, decode_destination, expect_items};

use crate::transaction::env::TxEnv;
use crate::transaction::signature::TxSignature;
use crate::transaction::{AccessList, TxKind, TxType};
use primitive_types::{H160, U256};

const COMMON_FIELDS: usize = 6;
const TRAILING_FIELDS: usize = 3;
const SIGNED_TRANSACTION_FIELDS: usize = COMMON_FIELDS + TRAILING_FIELDS;
const PRE_EIP155_SIGNING_FIELDS: usize = COMMON_FIELDS;
const EIP155_SIGNING_FIELDS: usize = SIGNED_TRANSACTION_FIELDS;
const V_INDEX: usize = COMMON_FIELDS;
const R_INDEX: usize = V_INDEX + 1;
const S_INDEX: usize = R_INDEX + 1;
const PRE_EIP155_V_EVEN: u128 = 27;
const PRE_EIP155_V_ODD: u128 = 28;
const EIP155_V_BASE: u128 = 35;

/// A normalized legacy transaction.
///
/// The first six fields are the legacy wire fields. `chain_id` is recovered from the encoded `v` and
/// selects the pre-EIP-155 or EIP-155 encoding for signing; encoding folds it back into `v` with the
/// signature parity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxLegacy {
    /// Chain this transaction is bound to, or `None` for a pre-EIP-155 signature valid anywhere.
    pub chain_id: Option<u64>,
    /// Sender's transaction counter.
    pub nonce: U256,
    /// Price per gas unit.
    pub gas_price: U256,
    /// Maximum gas the transaction may consume.
    pub gas_limit: u64,
    /// Destination, or a contract creation.
    pub to: TxKind,
    /// Value transferred.
    pub value: U256,
    /// Call data, or init code for a creation.
    pub data: Vec<u8>,
}

impl TxLegacy {
    /// The six fields every legacy encoding opens with.
    fn append_base_fields(&self, stream: &mut rlp::RlpStream) {
        stream.append(&self.nonce);
        stream.append(&self.gas_price);
        stream.append(&self.gas_limit);
        append_destination(stream, self.to);
        stream.append(&self.value);
        stream.append(&self.data);
    }

    /// Encodes the six-field pre-EIP-155 signing form, or the nine-field EIP-155 form ending in
    /// `[chain_id, 0, 0]`, into `stream`, clearing it first. The bounded list independently checks
    /// the protocol arity.
    ///
    /// # Panics
    /// Panics if the internal encoder writes more fields than the selected protocol form permits.
    pub(crate) fn encode_for_signing_in(&self, stream: &mut rlp::RlpStream) {
        stream.clear();
        let field_count = if self.chain_id.is_some() {
            EIP155_SIGNING_FIELDS
        } else {
            PRE_EIP155_SIGNING_FIELDS
        };
        stream.begin_list(field_count);
        self.append_base_fields(stream);
        if let Some(chain_id) = self.chain_id {
            stream.append(&chain_id);
            stream.append(&0u8);
            stream.append(&0u8);
        }
    }

    /// Converts into the execution environment for the recovered `caller`, moving owned data.
    /// Named destructuring makes new consensus fields compile-time update points.
    #[must_use]
    pub fn into_tx_env(self, caller: H160) -> TxEnv {
        let Self {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to: tx_kind,
            value,
            data,
        } = self;

        TxEnv {
            tx_type: TxType::Legacy,
            caller,
            tx_kind,
            gas_limit,
            value,
            data,
            nonce,
            chain_id,
            gas_price: Some(gas_price),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: AccessList(Vec::new()),
            blob_versioned_hashes: Vec::new(),
            max_fee_per_blob_gas: 0,
            authorization_list: Vec::new(),
        }
    }
}

/// A legacy transaction with its signature parity and `r, s` components.
///
/// The encoded `v` is reconstructed from the parity and optional chain id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTxLegacy {
    /// The signed fields.
    pub tx: TxLegacy,
    /// The sender's signature; its parity and `chain_id` determine `v`.
    pub signature: TxSignature,
}

impl SignedTxLegacy {
    /// Returns `27 + parity`, or `35 + 2 * chain_id + parity` for EIP-155.
    /// The `u128` result covers every `u64` chain id without overflow.
    #[inline]
    #[must_use]
    pub fn v(&self) -> u128 {
        let parity = u128::from(self.signature.y_parity);
        self.tx.chain_id.map_or_else(
            || PRE_EIP155_V_EVEN + parity,
            |chain_id| EIP155_V_BASE + u128::from(chain_id) * 2 + parity,
        )
    }

    /// Splits a legacy wire `v` into signature parity and its optional EIP-155 chain id.
    ///
    /// # Errors
    /// [`TxDecodeError::InvalidLegacyV`] if `v` encodes neither form or its chain id exceeds `u64`.
    #[inline]
    fn decode_v(v: u128) -> Result<(bool, Option<u64>), TxDecodeError> {
        match v {
            PRE_EIP155_V_EVEN => Ok((false, None)),
            PRE_EIP155_V_ODD => Ok((true, None)),
            EIP155_V_BASE.. => {
                let offset = v - EIP155_V_BASE;
                let chain_id =
                    u64::try_from(offset / 2).map_err(|_| TxDecodeError::InvalidLegacyV(v))?;
                Ok((offset % 2 == 1, Some(chain_id)))
            }
            _ => Err(TxDecodeError::InvalidLegacyV(v)),
        }
    }

    /// Decodes the nine-item list.
    ///
    /// # Errors
    /// [`TxDecodeError`] if the list is not nine strictly-tiling items, `to` is malformed, or `v`
    /// encodes neither a pre-EIP-155 parity nor a chain id.
    pub fn decode_strict(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, SIGNED_TRANSACTION_FIELDS)?;
        let v: u128 = rlp.val_at(V_INDEX)?;
        let (y_parity, chain_id) = Self::decode_v(v)?;
        Ok(Self {
            tx: TxLegacy {
                chain_id,
                nonce: rlp.val_at(0)?,
                gas_price: rlp.val_at(1)?,
                gas_limit: rlp.val_at(2)?,
                to: decode_destination(rlp, 3)?,
                value: rlp.val_at(4)?,
                data: rlp.val_at(5)?,
            },
            signature: TxSignature::new(y_parity, rlp.val_at(R_INDEX)?, rlp.val_at(S_INDEX)?),
        })
    }
}

impl rlp::Encodable for SignedTxLegacy {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(SIGNED_TRANSACTION_FIELDS);
        self.tx.append_base_fields(stream);
        stream.append(&self.v());
        stream.append(&self.signature.r);
        stream.append(&self.signature.s);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EIP155_SIGNING_FIELDS, EIP155_V_BASE, PRE_EIP155_SIGNING_FIELDS, SIGNED_TRANSACTION_FIELDS,
        SignedTxLegacy, TxLegacy, V_INDEX,
    };
    use crate::transaction::TxEnv;
    use crate::transaction::types::TxDecodeError;
    use crate::transaction::{TxKind, TxSignature, TxType};
    use hex_literal::hex;
    use primitive_types::H160;
    use primitive_types::U256;

    fn encoded_for_signing(tx: &TxLegacy) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        tx.encode_for_signing_in(&mut stream);
        stream.out().to_vec()
    }

    /// A real pre-EIP-155 transaction (`v = 28`).
    const PRE_155: &[u8] = &hex!(
        "f85f800182520894000000000000000000000000000b9331677e6ebf0a801ca098ff921201554726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4aa01887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a3"
    );

    /// A real EIP-155 transaction on chain 1 (`v = 37`).
    const EIP_155: &[u8] = &hex!(
        "f9015482078b8505d21dba0083022ef1947a250d5630b4cf539739df2c5dacb4c659f2488d880c46549a521b13d8b8e47ff36ab50000000000000000000000000000000000000000000066ab5a608bd00a23f2fe000000000000000000000000000000000000000000000000000000000000008000000000000000000000000048c04ed5691981c42154c6167398f95e8f38a7ff00000000000000000000000000000000000000000000000000000000632ceac70000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000006c6ee5e31d828de241282b9606c8e98ea48526e225a0c9077369501641a92ef7399ff81c21639ed4fd8fc69cb793cfa1dbfab342e10aa0615facb2f1bcf3274a354cfe384a38d0cc008a11c2dd23a69111bc6930ba27a8"
    );

    fn decoded(raw: &[u8]) -> SignedTxLegacy {
        SignedTxLegacy::decode_strict(&rlp::Rlp::new(raw)).unwrap()
    }

    fn with_v(v: u128) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new_list(SIGNED_TRANSACTION_FIELDS);
        let rlp = rlp::Rlp::new(PRE_155);
        for index in 0..SIGNED_TRANSACTION_FIELDS {
            if index == V_INDEX {
                stream.append(&v);
            } else {
                stream.append_raw(rlp.at(index).unwrap().as_raw(), 1);
            }
        }
        stream.out().to_vec()
    }

    #[test]
    fn pre_eip155_v_values_encode_and_decode() {
        let mut typed = decoded(PRE_155);
        typed.tx.chain_id = None;
        for (v, y_parity) in [(27, false), (28, true)] {
            typed.signature.y_parity = y_parity;
            assert_eq!(typed.v(), v);
            assert_eq!(SignedTxLegacy::decode_v(v), Ok((y_parity, None)));
        }
    }

    #[test]
    fn invalid_pre_eip155_v_ranges_are_rejected() {
        for v in (0u128..=26).chain(29..=34) {
            assert_eq!(
                SignedTxLegacy::decode_v(v),
                Err(TxDecodeError::InvalidLegacyV(v)),
                "v = {v}"
            );
        }
    }

    #[test]
    fn pre_eip155_roundtrips_and_carries_no_chain_id() {
        let typed = decoded(PRE_155);
        assert_eq!(typed.tx.chain_id, None);
        assert!(typed.signature.y_parity);
        assert_eq!(typed.v(), 28);
        assert_eq!(rlp::encode(&typed).to_vec(), PRE_155);
    }

    #[test]
    fn eip155_roundtrips_and_recovers_the_chain_id() {
        let typed = decoded(EIP_155);
        assert_eq!(typed.tx.chain_id, Some(1));
        assert_eq!(typed.v(), 37);
        assert_eq!(rlp::encode(&typed).to_vec(), EIP_155);
        assert_eq!(typed.tx.into_tx_env(H160::zero()).tx_type, TxType::Legacy);
    }

    /// Reconstructed `v` must round-trip exactly to preserve the transaction identity.
    #[test]
    fn v_survives_the_split_into_parity_and_chain_id() {
        for raw in [PRE_155, EIP_155] {
            let typed = decoded(raw);
            let v = typed.v();
            assert_eq!(
                rlp::Rlp::new(raw).val_at::<u128>(V_INDEX).unwrap(),
                v,
                "{v} must match the encoded `v`"
            );
            let again =
                SignedTxLegacy::decode_strict(&rlp::Rlp::new(&rlp::encode(&typed))).unwrap();
            assert_eq!(again, typed);
        }
    }

    /// `chain_id` selects the six- or nine-field encoding for signing.
    #[test]
    fn the_encoding_for_signing_depends_on_the_chain_id() {
        let mut tx = decoded(PRE_155).tx;
        let unprotected = encoded_for_signing(&tx);
        tx.chain_id = Some(1);
        let protected = encoded_for_signing(&tx);
        assert_eq!(
            rlp::Rlp::new(&unprotected).item_count().unwrap(),
            PRE_EIP155_SIGNING_FIELDS
        );
        assert_eq!(
            rlp::Rlp::new(&protected).item_count().unwrap(),
            EIP155_SIGNING_FIELDS
        );
        assert_ne!(unprotected, protected);
    }

    /// Every `u64` chain id has a representable `u128` `v` and round-trips.
    #[test]
    fn eip155_v_encodes_and_decodes_across_the_u64_range() {
        for chain_id in [
            0u64,
            1,
            137,
            0xFFFF,
            1_000_000,
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ] {
            for y_parity in [false, true] {
                let mut typed = decoded(PRE_155);
                typed.tx.chain_id = Some(chain_id);
                typed.signature = TxSignature::new(y_parity, typed.signature.r, typed.signature.s);

                let expected = EIP155_V_BASE + u128::from(chain_id) * 2 + u128::from(y_parity);
                assert_eq!(typed.v(), expected, "chain {chain_id}, parity {y_parity}");
                assert_eq!(
                    SignedTxLegacy::decode_v(expected),
                    Ok((y_parity, Some(chain_id))),
                    "chain {chain_id}, parity {y_parity}"
                );

                let encoded = rlp::encode(&typed).to_vec();
                assert_eq!(
                    SignedTxLegacy::decode_strict(&rlp::Rlp::new(&encoded)).unwrap(),
                    typed,
                    "chain {chain_id}, parity {y_parity}"
                );
            }
        }
    }

    /// `v = u64::MAX` remains valid and round-trips exactly.
    #[test]
    fn the_widest_u64_v_decodes_and_reencodes() {
        let bytes = with_v(u128::from(u64::MAX));
        let typed = SignedTxLegacy::decode_strict(&rlp::Rlp::new(&bytes)).unwrap();
        assert_eq!(typed.tx.chain_id, Some((u64::MAX - 35) / 2));
        assert!(!typed.signature.y_parity);
        assert_eq!(typed.v(), u128::from(u64::MAX));
        assert_eq!(rlp::encode(&typed).to_vec(), bytes);
    }

    /// A `v` encoding a chain id wider than `u64` is rejected rather than truncated.
    #[test]
    fn a_chain_id_wider_than_a_u64_is_refused() {
        let first_too_wide = EIP155_V_BASE + (u128::from(u64::MAX) + 1) * 2;
        for v in [first_too_wide, first_too_wide + 1, u128::MAX] {
            assert_eq!(
                SignedTxLegacy::decode_v(v),
                Err(TxDecodeError::InvalidLegacyV(v))
            );
        }
        assert_eq!(
            SignedTxLegacy::decode_strict(&rlp::Rlp::new(&with_v(first_too_wide))),
            Err(TxDecodeError::InvalidLegacyV(first_too_wide))
        );
    }

    #[test]
    fn a_creation_is_representable_and_survives_the_round_trip() {
        let typed = SignedTxLegacy {
            tx: TxLegacy {
                chain_id: Some(1),
                nonce: U256::one(),
                gas_price: U256::from(10u64),
                gas_limit: 21_000,
                to: TxKind::Create,
                value: U256::zero(),
                data: vec![0x60, 0x00],
            },
            signature: TxSignature::new(false, U256::one(), U256::one()),
        };
        let encoded = rlp::encode(&typed).to_vec();
        let back = SignedTxLegacy::decode_strict(&rlp::Rlp::new(&encoded)).unwrap();
        assert_eq!(back, typed);
        assert_eq!(back.tx.into_tx_env(H160::zero()).tx_kind, TxKind::Create);
    }

    #[test]
    fn decoding_rejects_a_v_that_encodes_no_parity() {
        assert_eq!(
            SignedTxLegacy::decode_strict(&rlp::Rlp::new(&with_v(26))),
            Err(TxDecodeError::InvalidLegacyV(26))
        );
    }

    #[test]
    fn decoding_requires_the_signed_field_count_and_strict_tiling() {
        for count in [SIGNED_TRANSACTION_FIELDS - 1, SIGNED_TRANSACTION_FIELDS + 1] {
            let mut stream = rlp::RlpStream::new_list(count);
            for _ in 0..count {
                stream.append(&0u8);
            }
            assert_eq!(
                SignedTxLegacy::decode_strict(&rlp::Rlp::new(&stream.out())),
                Err(TxDecodeError::Rlp(rlp::DecoderError::RlpIncorrectListLen))
            );
        }

        // The correct item count plus three bytes no item accounts for, with the list header grown
        // to match.
        let mut spliced = PRE_155.to_vec();
        let payload = rlp::PayloadInfo::from(PRE_155).unwrap();
        spliced.extend_from_slice(&[0xb9, 0xff, 0xff]);
        spliced[1] = u8::try_from(payload.value_len + 3).unwrap();
        assert_eq!(
            crate::rlp_strict::declared_item_len(&spliced).unwrap(),
            spliced.len(),
            "the buffer must stay self-consistent, or the test proves nothing"
        );
        assert!(SignedTxLegacy::decode_strict(&rlp::Rlp::new(&spliced)).is_err());
    }

    /// Projection preserves legacy fields and supplies canonical absences for unsupported fields.
    #[test]
    fn the_projection_carries_its_own_fields_and_nothing_else() {
        let typed = decoded(EIP_155);
        let TxEnv {
            tx_type,
            caller,
            tx_kind,
            gas_limit,
            value,
            data,
            nonce,
            chain_id,
            gas_price,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            access_list,
            blob_versioned_hashes,
            max_fee_per_blob_gas,
            authorization_list,
        } = typed.tx.clone().into_tx_env(H160::zero());

        assert_eq!(tx_type, TxType::Legacy);
        assert_eq!(tx_kind, typed.tx.to);
        assert_eq!(gas_limit, typed.tx.gas_limit);
        assert_eq!(value, typed.tx.value);
        assert_eq!(data, typed.tx.data);
        assert_eq!(nonce, typed.tx.nonce);
        assert_eq!(chain_id, typed.tx.chain_id);
        assert_eq!(gas_price, Some(typed.tx.gas_price));
        // Fields a legacy transaction does not have, each as its own absent value.
        assert_eq!(max_fee_per_gas, None);
        assert_eq!(max_priority_fee_per_gas, None);
        assert!(access_list.is_empty());
        assert!(blob_versioned_hashes.is_empty());
        assert_eq!(max_fee_per_blob_gas, 0);
        // The caller is supplied to the projection; a legacy transaction has no authorizations.
        assert_eq!(caller, H160::zero());
        assert!(authorization_list.is_empty());
    }
}
