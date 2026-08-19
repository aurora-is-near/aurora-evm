//! The legacy (pre-EIP-2718) transaction: a bare RLP list with no type byte.

use super::codec::{TxDecodeError, append_destination, decode_destination, expect_items};

use crate::transaction::env::TxEnv;
use crate::transaction::signature::TxSignature;
use crate::transaction::{AccessList, TxKind, TxType};
use primitive_types::{H160, U256};

/// A legacy transaction's own fields.
///
/// `chain_id` is an `Option` because EIP-155 is opt-in: a transaction signed without it is valid on
/// every chain, and the two forms have *different signing preimages*. It is a field here rather than
/// a derivation of `v`, so that both the preimage and the signed encoding are total — `v` is computed
/// from it and the parity when the transaction is encoded, never stored.
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
    fn append_fields(&self, stream: &mut rlp::RlpStream) {
        stream.append(&self.nonce);
        stream.append(&self.gas_price);
        stream.append(&self.gas_limit);
        append_destination(stream, self.to);
        stream.append(&self.value);
        stream.append(&self.data);
    }

    /// Writes the signing preimage into `stream`: six fields before EIP-155, or nine with the
    /// `chain_id, 0, 0` tail.
    ///
    /// Which form is signed is what `chain_id` selects — the same fields sign differently on a chain
    /// that replays the transaction and one that does not. Takes the stream so a caller hashing a whole
    /// block's transactions can reuse one buffer for all of them.
    /// The list is unbounded and finalised, so the stream counts the fields itself — which matters most
    /// here, where the count depends on whether the chain id is present.
    pub(crate) fn append_signing_preimage(&self, stream: &mut rlp::RlpStream) {
        stream.clear();
        stream.begin_unbounded_list();
        self.append_fields(stream);
        if let Some(chain_id) = self.chain_id {
            stream.append(&chain_id);
            stream.append(&0u8);
            stream.append(&0u8);
        }
        stream.finalize_unbounded_list();
    }

    /// The signing preimage as its own buffer, for a one-off caller.
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        self.append_signing_preimage(&mut stream);
        stream.out().to_vec()
    }
}

/// A signed legacy transaction.
///
/// The signature is held in the same shape as every other type's — a parity and `r, s` — and the `v`
/// that folds the parity together with the chain id is reconstructed at encoding time. Storing `v`
/// raw instead would make the *signing preimage* the partial operation, which is the worse trade: a
/// signature that cannot be re-encoded must not stop the hash it signed from being computed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTxLegacy {
    /// The signed fields.
    pub tx: TxLegacy,
    /// The sender's signature. Its `y_parity` and the transaction's `chain_id` are what `v` encodes.
    pub signature: TxSignature,
}

impl SignedTxLegacy {
    /// The `v` this transaction encodes: `27 + parity` before EIP-155, `35 + 2 * chain_id + parity`
    /// after it.
    ///
    /// A `u128`, which is what makes it total for every `u64` chain id. RLP encodes integers
    /// minimally, so the width is invisible on the wire.
    #[must_use]
    pub fn v(&self) -> u128 {
        self.signature.legacy_v(self.tx.chain_id)
    }
}

impl rlp::Encodable for SignedTxLegacy {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(9);
        self.tx.append_fields(stream);
        stream.append(&self.v());
        stream.append(&self.signature.r);
        stream.append(&self.signature.s);
    }
}

impl SignedTxLegacy {
    /// Decodes the nine-item list.
    ///
    /// # Errors
    /// [`TxDecodeError`] if the list is not nine strictly-tiling items, `to` is malformed, or `v`
    /// encodes neither a pre-EIP-155 parity nor a chain id.
    pub fn decode_strict(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, 9)?;
        let v: u128 = rlp.val_at(6)?;
        let (y_parity, chain_id) =
            TxSignature::from_legacy_v(v).ok_or(TxDecodeError::InvalidLegacyV(v))?;
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
            signature: TxSignature::new(y_parity, rlp.val_at(7)?, rlp.val_at(8)?),
        })
    }
}

impl TxLegacy {
    /// This transaction's contribution to the execution environment, **consuming** it.
    ///
    /// Consuming rather than borrowing so that the owned fields — the call data, the access list and
    /// its storage keys — *move* instead of being copied. The executor takes them by value in the end,
    /// so a borrowing conversion would copy them once here and then hand the copy on; nothing reads the
    /// transaction after this point.
    ///
    /// `caller` is an argument because it is not a transaction field: it is what verifying the
    /// signature established.
    ///
    /// Every field is destructured by name. That is deliberate — adding a field to this type breaks
    /// this function, so a new consensus field cannot silently fail to reach execution.
    #[must_use]
    pub fn into_tx_env(self, caller: H160) -> TxEnv {
        let Self {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
        } = self;

        TxEnv {
            tx_type: TxType::Legacy,
            caller,
            tx_kind: to,
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

#[cfg(test)]
mod tests {
    use super::{SignedTxLegacy, TxLegacy};
    use crate::transaction::TxEnv;
    use crate::transaction::{TxKind, TxSignature, TxType};
    use hex_literal::hex;
    use primitive_types::H160;
    use primitive_types::U256;

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

    /// `v` is reconstructed, not stored, so the round trip has to reproduce it exactly — that is what
    /// keeps the transaction hash and the sender unchanged.
    #[test]
    fn v_survives_the_split_into_parity_and_chain_id() {
        for raw in [PRE_155, EIP_155] {
            let typed = decoded(raw);
            let v = typed.v();
            assert_eq!(
                rlp::Rlp::new(raw).val_at::<u128>(6).unwrap(),
                v,
                "{v} must match the encoded `v`"
            );
            let again =
                SignedTxLegacy::decode_strict(&rlp::Rlp::new(&rlp::encode(&typed))).unwrap();
            assert_eq!(again, typed);
        }
    }

    /// The signing preimage is six fields or nine, and `chain_id` is what chooses — the same
    /// transaction signs differently on a chain that replays it and one that does not.
    #[test]
    fn the_signing_preimage_depends_on_the_chain_id() {
        let mut tx = decoded(PRE_155).tx;
        let unprotected = tx.signing_preimage();
        tx.chain_id = Some(1);
        let protected = tx.signing_preimage();
        assert_eq!(rlp::Rlp::new(&unprotected).item_count().unwrap(), 6);
        assert_eq!(rlp::Rlp::new(&protected).item_count().unwrap(), 9);
        assert_ne!(unprotected, protected);
    }

    /// `v` is a `u128`, so every `u64` chain id encodes — including the one that makes `v` the widest
    /// a `u64` `v` could ever have been. Computing `v` in a `u64` would reject this transaction, and
    /// it is a perfectly ordinary one.
    #[test]
    fn the_widest_chain_id_still_encodes_and_round_trips() {
        for chain_id in [1u64, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            for y_parity in [false, true] {
                let mut typed = decoded(PRE_155);
                typed.tx.chain_id = Some(chain_id);
                typed.signature = TxSignature::new(y_parity, typed.signature.r, typed.signature.s);

                let expected = 35 + u128::from(chain_id) * 2 + u128::from(y_parity);
                assert_eq!(typed.v(), expected, "chain {chain_id}, parity {y_parity}");

                let encoded = rlp::encode(&typed).to_vec();
                assert_eq!(
                    SignedTxLegacy::decode_strict(&rlp::Rlp::new(&encoded)).unwrap(),
                    typed,
                    "chain {chain_id}, parity {y_parity}"
                );
            }
        }
    }

    /// `v = u64::MAX` is a legal legacy `v`, and its chain id is one above what a `u64`-computed
    /// bound would admit. Decoding it must succeed and re-encoding must reproduce it exactly.
    #[test]
    fn the_widest_u64_v_decodes_and_reencodes() {
        let mut stream = rlp::RlpStream::new_list(9);
        let rlp = rlp::Rlp::new(PRE_155);
        for index in 0..9usize {
            if index == 6 {
                stream.append(&u128::from(u64::MAX));
            } else {
                stream.append_raw(rlp.at(index).unwrap().as_raw(), 1);
            }
        }
        let bytes = stream.out().to_vec();
        let typed = SignedTxLegacy::decode_strict(&rlp::Rlp::new(&bytes)).unwrap();
        assert_eq!(typed.tx.chain_id, Some((u64::MAX - 35) / 2));
        assert!(!typed.signature.y_parity);
        assert_eq!(typed.v(), u128::from(u64::MAX));
        assert_eq!(rlp::encode(&typed).to_vec(), bytes);
    }

    /// A `v` whose chain id needs more than a `u64` is refused rather than truncated: every other
    /// transaction type declares `chain_id` as a `u64`, so there is no chain here to describe.
    #[test]
    fn a_chain_id_wider_than_a_u64_is_refused() {
        let mut stream = rlp::RlpStream::new_list(9);
        let rlp = rlp::Rlp::new(PRE_155);
        for index in 0..9usize {
            if index == 6 {
                stream.append(&(35u128 + (u128::from(u64::MAX) + 1) * 2));
            } else {
                stream.append_raw(rlp.at(index).unwrap().as_raw(), 1);
            }
        }
        assert!(SignedTxLegacy::decode_strict(&rlp::Rlp::new(&stream.out())).is_err());
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
        let mut stream = rlp::RlpStream::new_list(9);
        let rlp = rlp::Rlp::new(PRE_155);
        for index in 0..9usize {
            if index == 6 {
                stream.append(&26u64); // below 27 and below 35: neither form
            } else {
                stream.append_raw(rlp.at(index).unwrap().as_raw(), 1);
            }
        }
        assert!(SignedTxLegacy::decode_strict(&rlp::Rlp::new(&stream.out())).is_err());
    }

    #[test]
    fn decoding_requires_exactly_nine_strictly_tiling_items() {
        // Eight items.
        let mut short = rlp::RlpStream::new_list(8);
        for _ in 0..8 {
            short.append(&0u8);
        }
        assert!(SignedTxLegacy::decode_strict(&rlp::Rlp::new(&short.out())).is_err());

        // Nine items plus three bytes no item accounts for, with the list header grown to match.
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

    /// The projection into the execution environment: this type's own fields carried across, every
    /// field it does not have written as its absent value, and the caller supplied to the consuming
    /// projection. Destructured, so a field added to `TxEnv` breaks this test rather than slipping
    /// through unasserted — the name promises the whole projection.
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
