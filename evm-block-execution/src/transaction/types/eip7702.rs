//! [EIP-7702] set-code transaction, type byte `0x04`.
//!
//! [EIP-7702]: https://eips.ethereum.org/EIPS/eip-7702

use super::{
    TxDecodeError, append_access_list, append_signature, decode_access_list,
    decode_required_destination, decode_signature, expect_items,
};
use crate::rlp_strict;
use crate::transaction::env::TxEnv;
use crate::transaction::signature::TxSignature;
use crate::transaction::{AccessList, SignedAuthorization, TxKind, TxType};
use aurora_evm::executor::stack::Authorization;
use primitive_types::{H160, U256};

/// The EIP-7702 type byte.
pub const TYPE_BYTE: u8 = 0x04;

/// A set-code transaction's own fields.
///
/// `to` is an `H160` for the same reason as in [`TxEip4844`](super::TxEip4844): the type has no
/// creation form, so a creation is better made unrepresentable than rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxEip7702 {
    /// Chain this transaction is valid on.
    pub chain_id: u64,
    /// Sender's transaction counter.
    pub nonce: U256,
    /// Tip paid to the block's beneficiary, on top of the base fee.
    pub max_priority_fee_per_gas: U256,
    /// Total the sender will pay per gas unit, base fee included.
    pub max_fee_per_gas: U256,
    /// Maximum gas the transaction may consume.
    pub gas_limit: u64,
    /// Destination. A set-code transaction cannot be a creation.
    pub to: H160,
    /// Value transferred.
    pub value: U256,
    /// Call data.
    pub data: Vec<u8>,
    /// Addresses and storage slots pre-warmed for this transaction.
    pub access_list: AccessList,
    /// Delegations this transaction authorizes. Each is signed by its own authority, independently
    /// of the transaction's sender, and an unrecoverable one is skipped rather than fatal.
    pub authorization_list: Vec<SignedAuthorization>,
}

impl TxEip7702 {
    /// The ten fields, shared by the signed encoding and the signing preimage.
    fn append_fields(&self, stream: &mut rlp::RlpStream) {
        stream.append(&self.chain_id);
        stream.append(&self.nonce);
        stream.append(&self.max_priority_fee_per_gas);
        stream.append(&self.max_fee_per_gas);
        stream.append(&self.gas_limit);
        stream.append(&self.to);
        stream.append(&self.value);
        stream.append(&self.data);
        append_access_list(stream, &self.access_list);
        stream.append_list(&self.authorization_list);
    }

    /// Writes the signing preimage — the type byte, then this type's fields — into `stream`.
    ///
    /// The type byte goes in as raw bytes ahead of the list, so the preimage is one contiguous buffer
    /// rather than a list that then has to be copied to make room for a prefix. Takes the stream so a
    /// caller hashing a whole block's transactions can reuse one buffer for all of them.
    ///
    /// The list is unbounded and finalized, so the stream counts the fields itself. A handwritten count
    /// would be the field list repeated in a second place, and the two can disagree — a preimage read
    /// back with `as_raw` does not check that its list was completed, so a wrong count would silently
    /// produce a wrong signature hash and therefore a wrong sender.
    pub(crate) fn append_signing_preimage(&self, stream: &mut rlp::RlpStream) {
        stream.clear();
        stream.append_raw(&[TYPE_BYTE], 0);
        stream.begin_unbounded_list();
        self.append_fields(stream);
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

/// A signed set-code transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTxEip7702 {
    /// The signed fields.
    pub tx: TxEip7702,
    /// The sender's signature. Distinct from the signatures inside `authorization_list`.
    pub signature: TxSignature,
}

impl rlp::Encodable for SignedTxEip7702 {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(13);
        self.tx.append_fields(stream);
        append_signature(stream, &self.signature);
    }
}

impl SignedTxEip7702 {
    /// Decodes the thirteen-item list that follows the type byte.
    ///
    /// # Errors
    /// [`TxDecodeError`] if the list is not thirteen strictly-tiling items, the transaction is a
    /// creation, an authorization tuple is malformed, or the transaction sender's `y_parity` is not
    /// 0 or 1. A tuple's own `y_parity` may be any `u8`; values above 1 make that tuple ineffective.
    pub fn decode_strict(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, 13)?;
        Ok(Self {
            tx: TxEip7702 {
                chain_id: rlp.val_at(0)?,
                nonce: rlp.val_at(1)?,
                max_priority_fee_per_gas: rlp.val_at(2)?,
                max_fee_per_gas: rlp.val_at(3)?,
                gas_limit: rlp.val_at(4)?,
                to: decode_required_destination(rlp, 5, TxType::Eip7702)?,
                value: rlp.val_at(6)?,
                data: rlp.val_at(7)?,
                access_list: decode_access_list(rlp, 8)?,
                authorization_list: rlp_strict::checked_list_at(rlp, 9)?,
            },
            signature: decode_signature(rlp, 10)?,
        })
    }
}

impl TxEip7702 {
    /// The authorities this transaction's tuples authorize, one entry per tuple.
    ///
    /// One RLP buffer is built here and reused for every tuple: each preimage is three small fields,
    /// so a fresh buffer per tuple would cost more than hashing it does. `recover_authority` clears the
    /// buffer before writing, so the tuples cannot bleed into one another's preimage.
    ///
    /// The list is never shortened. A tuple that fails a check is present with `is_valid: false`,
    /// because intrinsic gas is charged per tuple whether it authorizes anyone or not.
    #[must_use]
    pub fn recovered_authorizations(&self) -> Vec<Authorization> {
        let mut stream = rlp::RlpStream::new();
        self.authorization_list
            .iter()
            .map(|tuple| tuple.recover_authority(self.chain_id, &mut stream))
            .collect()
    }

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
        // Recovered *before* the fields move, because recovery borrows the tuples and a borrow cannot
        // outlive the move. Doing it the other way round is what forces a clone of `data` and the
        // access list.
        let authorization_list = self.recovered_authorizations();

        let Self {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list,
            authorization_list: _tuples,
        } = self;

        TxEnv {
            tx_type: TxType::Eip7702,
            caller,
            tx_kind: TxKind::Call(to),
            gas_limit,
            value,
            data,
            nonce,
            chain_id: Some(chain_id),
            gas_price: None,
            max_fee_per_gas: Some(max_fee_per_gas),
            max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
            access_list,
            blob_versioned_hashes: Vec::new(),
            max_fee_per_blob_gas: 0,
            authorization_list,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SignedTxEip7702, TYPE_BYTE};
    use crate::transaction::TxEnv;
    use crate::transaction::{SignedAuthorization, TxKind, TxType};
    use hex_literal::hex;
    use primitive_types::H160;
    use primitive_types::U256;

    /// A real set-code transaction, carrying one authorization.
    const RAW: &[u8] = &hex!(
        "04f8e101808007830f424094000f3df6d732807ef1319fb7b8bb8522d0beac0280a00000"
        "00000000000000000000000000000000000000000000000000000000000cc0f85cf85a80"
        "9400000000000000000000000000000000000000008080a085044e88414585239b3b7b4f"
        "91c0bc6275ed817b925d973869370ca9b842925aa02e021ec5210eb0cc051524a05e9049"
        "d6a57acdf0386e3feeae658df6d2a242a980a0f2e0c327202f18c44b074c628433f8d7ed"
        "09f7fbe180684f1ab6da84b8d94c4aa00c755520f565a678bac8959549dba76a7c212002"
        "5b53e1565b09845880a66dbf"
    );

    fn decoded() -> SignedTxEip7702 {
        SignedTxEip7702::decode_strict(&rlp::Rlp::new(&RAW[1..])).unwrap()
    }

    #[test]
    fn the_signing_preimage_omits_the_senders_signature_but_keeps_the_authorizations() {
        let typed = decoded();
        let preimage = typed.tx.signing_preimage();
        assert_eq!(preimage[0], TYPE_BYTE);
        let rlp = rlp::Rlp::new(&preimage[1..]);
        assert_eq!(rlp.item_count().unwrap(), 10);
        assert_eq!(rlp.at(9).unwrap().item_count().unwrap(), 1);
    }

    /// The projection into the execution payload: this type's own fields carried across, and every
    /// field it does not have written as its absent value. There is no impl back, so this is the only
    /// direction there is to check.
    #[test]
    fn the_projection_carries_its_own_fields_and_nothing_else() {
        let typed = decoded();
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

        assert_eq!(tx_type, TxType::Eip7702);
        assert_eq!(tx_kind, TxKind::Call(typed.tx.to));
        assert_eq!(gas_limit, typed.tx.gas_limit);
        assert_eq!(value, typed.tx.value);
        assert_eq!(data, typed.tx.data);
        assert_eq!(nonce, typed.tx.nonce);
        assert_eq!(chain_id, Some(typed.tx.chain_id));
        assert_eq!(max_fee_per_gas, Some(typed.tx.max_fee_per_gas));
        assert_eq!(
            max_priority_fee_per_gas,
            Some(typed.tx.max_priority_fee_per_gas)
        );
        assert_eq!(access_list, typed.tx.access_list);
        assert_eq!(gas_price, None);
        assert!(blob_versioned_hashes.is_empty());
        assert_eq!(max_fee_per_blob_gas, 0);
        assert_eq!(caller, H160::zero());
        // The *signed* tuples stay on the consensus form; the environment carries the **recovered**
        // authorities, derived here, one per tuple.
        assert_eq!(
            authorization_list.len(),
            typed.tx.authorization_list.len(),
            "one recovered authority per signed tuple"
        );
        for (recovered, tuple) in authorization_list.iter().zip(&typed.tx.authorization_list) {
            assert_eq!(recovered.address, tuple.address);
            assert_eq!(recovered.nonce, tuple.nonce);
        }
    }

    /// The list is never shortened, whatever a tuple turns out to be.
    ///
    /// Intrinsic gas is charged per tuple, so a tuple that authorizes nobody must still occupy its
    /// place — dropping it would undercharge the transaction and change the state root. A failure is
    /// `is_valid: false`, not an absence.
    #[test]
    fn recovery_keeps_one_entry_per_tuple_however_it_fails() {
        let tx = decoded().tx;
        let good = tx.recovered_authorizations();
        assert_eq!(good.len(), tx.authorization_list.len());
        assert!(good[0].is_valid, "the published tuple must recover");
        assert_eq!(
            good[0].authority,
            H160(hex!("dde0a8f1c754bca49c7ad9017cbb242d3116d9a3")),
            "authority independently recovered from the published tuple"
        );

        // Four independent ways for a tuple to authorize nobody, plus one that works — every one of
        // them still yields exactly one entry.
        let mut tx = tx;
        let sound = tx.authorization_list[0];
        let broken = vec![
            sound, // as decoded
            SignedAuthorization {
                y_parity: 27, // not a parity: no signature at all
                ..sound
            },
            SignedAuthorization {
                chain_id: U256::from(u64::MAX), // a chain this transaction is not on
                ..sound
            },
            SignedAuthorization {
                s: crate::transaction::SECP256K1N_HALF + U256::one(), // EIP-2 unnormalized
                ..sound
            },
            SignedAuthorization {
                r: U256::zero(), // no key recovers from this
                s: U256::zero(),
                ..sound
            },
        ];
        let expected = broken.len();
        tx.authorization_list = broken;

        let recovered = tx.recovered_authorizations();
        assert_eq!(recovered.len(), expected, "no tuple may be dropped");
        for (index, entry) in recovered.iter().enumerate() {
            assert_eq!(
                entry.address, sound.address,
                "entry {index} keeps its target"
            );
            assert_eq!(entry.nonce, sound.nonce, "entry {index} keeps its nonce");
            if !entry.is_valid {
                assert_eq!(
                    entry.authority,
                    H160::zero(),
                    "entry {index} authorises nobody, so it names nobody"
                );
            }
        }
        // The last four are broken in four different ways; none of them may be valid.
        assert_eq!(recovered[0], good[0], "the sound tuple must still recover");
        assert!(recovered[1..].iter().all(|entry| !entry.is_valid));
    }

    /// One buffer serves the whole list, so the preimages must not bleed into one another: two
    /// identical tuples must recover to the same authority, and a list of them must agree with
    /// recovering each on its own.
    #[test]
    fn a_shared_rlp_buffer_does_not_leak_between_tuples() {
        let mut tx = decoded().tx;
        let one = tx.authorization_list[0];
        let other = SignedAuthorization { nonce: 9, ..one };
        tx.authorization_list = vec![one, other, one, other];

        let together = tx.recovered_authorizations();

        let mut alone = Vec::new();
        for tuple in [one, other, one, other] {
            let mut single = tx.clone();
            single.authorization_list = vec![tuple];
            alone.extend(single.recovered_authorizations());
        }
        assert_eq!(
            together, alone,
            "a shared buffer must give per-tuple results"
        );
        assert_eq!(together[0], together[2]);
        assert_eq!(together[1], together[3]);
    }
}
