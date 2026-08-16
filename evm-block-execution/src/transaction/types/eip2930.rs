//! [EIP-2930] access-list transaction, type byte `0x01`.
//!
//! [EIP-2930]: https://eips.ethereum.org/EIPS/eip-2930

use super::{
    TxDecodeError, append_access_list, append_destination, append_signature, decode_access_list,
    decode_destination, decode_signature, expect_items,
};
use crate::transaction::env::TxEnv;
use crate::transaction::signature::TxSignature;
use crate::transaction::{AccessList, TxKind, TxType};
use primitive_types::{H160, U256};

/// The EIP-2930 type byte.
pub const TYPE_BYTE: u8 = 0x01;

/// An EIP-2930 transaction's own fields: the legacy set, with a chain id in front and an access list
/// at the end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxEip2930 {
    /// Chain this transaction is valid on. Mandatory from this type onward.
    pub chain_id: u64,
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
    /// Addresses and storage slots pre-warmed for this transaction.
    pub access_list: AccessList,
}

impl TxEip2930 {
    /// The eight fields, shared by the signed encoding and the signing preimage.
    fn append_fields(&self, stream: &mut rlp::RlpStream) {
        stream.append(&self.chain_id);
        stream.append(&self.nonce);
        stream.append(&self.gas_price);
        stream.append(&self.gas_limit);
        append_destination(stream, self.to);
        stream.append(&self.value);
        stream.append(&self.data);
        append_access_list(stream, &self.access_list);
    }

    /// Writes the signing preimage — the type byte, then this type's fields — into `stream`.
    ///
    /// The type byte goes in as raw bytes ahead of the list, so the preimage is one contiguous buffer
    /// rather than a list that then has to be copied to make room for a prefix. Takes the stream so a
    /// caller hashing a whole block's transactions can reuse one buffer for all of them.
    ///
    /// The list is unbounded and finalised, so the stream counts the fields itself. A hand-written count
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

/// A signed EIP-2930 transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTxEip2930 {
    /// The signed fields.
    pub tx: TxEip2930,
    /// The sender's signature.
    pub signature: TxSignature,
}

impl rlp::Encodable for SignedTxEip2930 {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(11);
        self.tx.append_fields(stream);
        append_signature(stream, &self.signature);
    }
}

impl SignedTxEip2930 {
    /// Decodes the eleven-item list that follows the type byte.
    ///
    /// # Errors
    /// [`TxDecodeError`] if the list is not eleven strictly-tiling items, `to` is malformed, or
    /// `y_parity` is not 0 or 1.
    pub fn decode_strict(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        expect_items(rlp, 11)?;
        Ok(Self {
            tx: TxEip2930 {
                chain_id: rlp.val_at(0)?,
                nonce: rlp.val_at(1)?,
                gas_price: rlp.val_at(2)?,
                gas_limit: rlp.val_at(3)?,
                to: decode_destination(rlp, 4)?,
                value: rlp.val_at(5)?,
                data: rlp.val_at(6)?,
                access_list: decode_access_list(rlp, 7)?,
            },
            signature: decode_signature(rlp, 8)?,
        })
    }
}

impl TxEip2930 {
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
            access_list,
        } = self;

        TxEnv {
            tx_type: TxType::Eip2930,
            caller,
            tx_kind: to,
            gas_limit,
            value,
            data,
            nonce,
            chain_id: Some(chain_id),
            gas_price: Some(gas_price),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list,
            blob_versioned_hashes: Vec::new(),
            max_fee_per_blob_gas: 0,
            authorization_list: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SignedTxEip2930, TYPE_BYTE};
    use crate::transaction::TxEnv;
    use crate::transaction::TxType;
    use hex_literal::hex;
    use primitive_types::H160;

    /// A real EIP-2930 transaction with a non-empty access list.
    const RAW: &[u8] = &hex!(
        "01f89b01800a8301e974943068947c19dbbc5a170610a69c65e341f0a0b7458080f838f7940000000000000000000000000000000000000000e1a0000000000000000000000000000000000000000000000000000000000000000001a0712d63f4983ce033255f9adfe3b159f465766eac906591091e3ad03ffc06ad16a0078e21a3501b9fc9b9b9e223cc19768be044d5c7c6faf1fbc0f5aa4deb325fe9"
    );

    fn decoded() -> SignedTxEip2930 {
        SignedTxEip2930::decode_strict(&rlp::Rlp::new(&RAW[1..])).unwrap()
    }

    #[test]
    fn the_signing_preimage_omits_the_signature() {
        let typed = SignedTxEip2930::decode_strict(&rlp::Rlp::new(&RAW[1..])).unwrap();
        let preimage = typed.tx.signing_preimage();
        assert_eq!(preimage[0], TYPE_BYTE);
        assert_eq!(rlp::Rlp::new(&preimage[1..]).item_count().unwrap(), 8);
    }

    #[test]
    fn a_byte_string_where_the_access_list_belongs_is_rejected() {
        let rlp = rlp::Rlp::new(&RAW[1..]);
        let mut stream = rlp::RlpStream::new_list(11);
        for i in 0..11usize {
            if i == 7 {
                stream.append(&vec![0xaau8; 3]);
            } else {
                stream.append_raw(rlp.at(i).unwrap().as_raw(), 1);
            }
        }
        assert!(SignedTxEip2930::decode_strict(&rlp::Rlp::new(&stream.out())).is_err());
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

        assert_eq!(tx_type, TxType::Eip2930);
        assert_eq!(tx_kind, typed.tx.to);
        assert_eq!(gas_limit, typed.tx.gas_limit);
        assert_eq!(value, typed.tx.value);
        assert_eq!(data, typed.tx.data);
        assert_eq!(nonce, typed.tx.nonce);
        assert_eq!(chain_id, Some(typed.tx.chain_id));
        assert_eq!(gas_price, Some(typed.tx.gas_price));
        assert_eq!(access_list, typed.tx.access_list);
        // A 2930 transaction has no dynamic fees, and the projection says so rather than inventing
        // a value no signature covered.
        assert_eq!(max_fee_per_gas, None);
        assert_eq!(max_priority_fee_per_gas, None);
        assert!(blob_versioned_hashes.is_empty());
        assert_eq!(max_fee_per_blob_gas, 0);
        assert_eq!(caller, H160::zero());
        assert!(authorization_list.is_empty());
    }
}
